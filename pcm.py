"""Postmod Comment Markdown (PCM v0.1) — the reference (Python) implementation.

A safety-first CommonMark subset for comments/messages, with three Postmod
extensions: DID-anchored mentions (`@[handle](did:…)`), masked links
(`[label](url)` → `label (domain)`), and permalinks (`pm:<32 hex>` → an in-app
reference to a post/comment by its message id, §5b). The canonical artifact is the
UTF-8 source string itself — no sidecar facets — so it commits cleanly under message
franking and renders offline on the E2EE plane. Full spec:
../postmodern-flutter/POSTMOD_COMMENT_MARKDOWN.md (this mirrors lib/comment_markdown.dart).

Permalinks are recognized at parse/render time only — NOT in `normalize_pcm` — so
they never affect franking (the literal `pm:<id>` bytes commit identically; only
rendering interprets them).

The one HARD cross-client invariant is `normalize_pcm`: it MUST produce
byte-identical output to the Flutter client, because that's what you frank/encrypt
("two comments are equal iff their normalized bytes are equal"). Parsing/rendering
need not be byte-identical, but the safety rules (strip HTML/images/reference
links, mask links, never execute code) must hold.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import urlsplit


class PcmError(ValueError):
    """Normalization/limit failure (oversize, invalid UTF-8). Reject, don't truncate."""


# ---------------------------------------------------------------------------
# Policy (§7 limits / §9 per-context toggles)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PcmPolicy:
    max_bytes: int = 4096
    max_depth: int = 4
    max_links: int = 25
    max_mentions: int = 25
    max_list_items: int = 100
    allow_headings: bool = False
    allow_tables: bool = False


COMMENT = PcmPolicy()
POST = PcmPolicy(max_bytes=65536, max_depth=6, max_links=100, max_mentions=100,
                 max_list_items=500, allow_headings=True, allow_tables=True)


# ---------------------------------------------------------------------------
# Normalization (§7) — the wire-relevant, byte-identical-with-Flutter step
# ---------------------------------------------------------------------------

# Bidi/RTL overrides (Trojan-source), zero-width spoofers, BOM.
_SPOOFERS = re.compile("[\u202A-\u202E\u2066-\u2069\u200B-\u200D\u2060\uFEFF]")
_TRIPLE_NL = re.compile(r"\n{3,}")


def normalize_pcm(source, policy: PcmPolicy = COMMENT, *, enforce_size: bool = True) -> str:
    """Canonicalize PCM source. Order (must match Flutter's normalizePcm exactly):
    decode UTF-8 → Unicode NFC → strip spoofers → CRLF/CR to LF → collapse 3+
    newlines to 2 → enforce the byte cap (reject, don't truncate).

    `enforce_size=False` skips the cap (the send path lets the wire layer enforce
    its own length limit, raising its own error) — the transform is unchanged, so
    franking equality is preserved either way."""
    if isinstance(source, (bytes, bytearray)):
        try:
            source = bytes(source).decode("utf-8")
        except UnicodeDecodeError as e:
            raise PcmError("invalid UTF-8") from e
    s = unicodedata.normalize("NFC", source)          # NFC first (canonical equivalence)
    s = _SPOOFERS.sub("", s)                           # strip Trojan-source / zero-width
    s = s.replace("\r\n", "\n").replace("\r", "\n")    # CRLF/CR → LF
    s = _TRIPLE_NL.sub("\n\n", s)                      # collapse blank-line runs
    if enforce_size and len(s.encode("utf-8")) > policy.max_bytes:
        raise PcmError("PCM exceeds max size")
    return s


def pcm_has_markup(source: str) -> bool:
    """Does `source` use any PCM markup? A plain message can skip the parser and
    render as one fast text run (keeps the common case cheap)."""
    return bool(_MARKUP_CHARS.search(source))


_MARKUP_CHARS = re.compile(r"[*_~`\[\]()>#]|^\s*[-+]\s|^\s*\d+\.\s", re.MULTILINE)


# ---------------------------------------------------------------------------
# Mentions (§5) — DID-anchored token + compose helpers
# ---------------------------------------------------------------------------

MENTION_TOKEN_RE = re.compile(
    r"@\[([^\]]{1,64})\]\((did:[a-z0-9]+:[A-Za-z0-9._%:-]{1,256})\)")


def mention_token(handle: str, did: str) -> str:
    """The canonical mention token, `@[handle](did:method:id)`."""
    return f"@[{handle}]({did})"


def extract_mentions(source: str) -> list[tuple[str, str]]:
    """The (handle, did) pairs mentioned in `source` (normalized first). The DID is
    the source of truth — anchor inbox pings / profile links to it, not the handle."""
    return [(m.group(1), m.group(2))
            for m in MENTION_TOKEN_RE.finditer(normalize_pcm(source, enforce_size=False))]


def mention_query(text: str, cursor: int):
    """The active `@query` being typed at `cursor` (for autocomplete), or None.
    Fires on `@` at start or after whitespace, never inside a completed token.
    Returns (start, end, query)."""
    if cursor < 0 or cursor > len(text):
        return None
    before = text[:cursor]
    m = re.search(r"(?:^|\s)@([A-Za-z0-9._-]{0,64})$", before)
    if not m:
        return None
    start = before.rfind("@")
    if start < 0:
        return None
    return (start, cursor, m.group(1))


# Permalink token (§ permalinks): `pm:<32 hex>` inline — the canonical reference to
# a post/comment is just its globally-unique message id; the client resolves it
# (the `permalink` op) and renders/navigates however it likes. Recognized at
# parse/render time only — NOT in normalize_pcm — so it never affects franking
# (both clients frank the literal text identically; only rendering interprets it).
PERMALINK_RE = re.compile(r"(?<![0-9A-Za-z])pm:([0-9a-f]{32})(?![0-9a-f])")


def permalink_token(msg_id: str) -> str:
    """The canonical permalink token for a message id — `pm:<32 hex>`."""
    return f"pm:{msg_id}"


def extract_permalinks(source: str) -> list[str]:
    """The message ids permalinked in `source` (normalized first)."""
    return [m.group(1)
            for m in PERMALINK_RE.finditer(normalize_pcm(source, enforce_size=False))]


# ---------------------------------------------------------------------------
# Masked links (§4) — preserve the destination, render eTLD+1, run safety gates
# ---------------------------------------------------------------------------

# Fallback multi-label suffixes for the registrable-domain heuristic when no
# Public Suffix List is available (mirror of the Flutter fallback set).
_MULTI_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "or.jp", "ne.jp",
    "com.au", "net.au", "org.au", "co.nz", "com.br", "co.in", "co.za",
}

try:                                  # use the full PSL if one happens to be installed
    import publicsuffix2 as _psl      # type: ignore
    _PSL = _psl.PublicSuffixList()
except Exception:                     # pragma: no cover - optional dependency
    _PSL = None


def registrable_domain(host: str) -> str:
    """The registrable domain (eTLD+1) of `host`: `a.b.example.co.uk` →
    `example.co.uk`. Uses the Public Suffix List when available, else a small
    built-in heuristic for common multi-label suffixes (naive last-two-labels is
    wrong for `*.co.uk`)."""
    host = host.lower()
    if _PSL is not None:
        try:
            dom = _PSL.get_sld(host)
            if dom:
                return dom
        except Exception:
            pass
    if host.startswith("www."):
        host = host[4:]
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    last_two = ".".join(parts[-2:])
    if last_two in _MULTI_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


@dataclass(frozen=True)
class MaskedLink:
    raw_url: str
    label: str
    display_domain: str          # eTLD+1 of the destination
    is_http_only: bool           # http, not https → demote/warn
    is_idn: bool                 # contains an xn-- label
    label_target_mismatch: bool  # label names a different domain than the target
    rejected: bool               # failed the scheme allowlist / had creds → inert text

    @property
    def has_warning(self) -> bool:
        return self.is_http_only or self.is_idn or self.label_target_mismatch or self.rejected


def _host_from_label(label: str):
    s = label.strip()
    return s if re.match(r"^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)+$", s) else None


def analyze_link(raw_url: str, label: str) -> MaskedLink:
    """Run the §4 safety gates on a link. Any failure → render inert + badge."""
    try:
        u = urlsplit(raw_url)
    except Exception:
        return MaskedLink(raw_url, label, raw_url, False, False, False, True)
    scheme = (u.scheme or "").lower()
    rejected = scheme not in ("https", "http")
    host = u.hostname or ""
    is_idn = any(lbl.startswith("xn--") for lbl in host.split("."))
    dest = registrable_domain(host)
    mismatch = False
    label_host = _host_from_label(label)
    if label_host is not None:
        mismatch = registrable_domain(label_host) != dest
    has_creds = bool(u.username)
    return MaskedLink(
        raw_url=raw_url, label=label, display_domain=dest or host,
        is_http_only=(scheme == "http"), is_idn=is_idn,
        label_target_mismatch=mismatch, rejected=rejected or has_creds)


# ---------------------------------------------------------------------------
# AST (§2/§3) — a small node, mirroring the Flutter tags so behaviour is testable
# ---------------------------------------------------------------------------

class Node:
    """A parsed element. Inline tags: text/em/strong/del/code/a/mention. Block
    tags: p/blockquote/ul/ol/li/pre/code/h1..h6. `a` carries attrs['href'];
    `mention` carries attrs['did'] + attrs['handle']."""
    __slots__ = ("tag", "children", "text", "attrs")

    def __init__(self, tag, children=None, text=None, attrs=None):
        self.tag = tag
        self.children = children
        self.text = text
        self.attrs = attrs or {}

    @property
    def text_content(self) -> str:
        if self.text is not None:
            return self.text
        return "".join(c.text_content for c in (self.children or ()))

    def __repr__(self):
        return f"Node({self.tag!r})"


_ALLOWED_INLINE = {"text", "em", "strong", "del", "code", "a", "mention", "permalink"}
_ALLOWED_BLOCK = {"p", "blockquote", "ul", "ol", "li", "pre", "code"}

_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")
_BULLET_RE = re.compile(r"^\s*[-*+]\s+(.*)$")
_ORDERED_RE = re.compile(r"^\s*\d+\.\s+(.*)$")
_THEMATIC_RE = re.compile(r"^\s*([-*_])(?:\s*\1){2,}\s*$")
_FENCE_RE = re.compile(r"^\s*```")


def parse_pcm(source, policy: PcmPolicy = COMMENT) -> list[Node]:
    """Normalize, then parse to a sanitized block AST: allowlist the grammar and
    drop anything disallowed (raw HTML, images, reference links, and — on the
    comment surface — headings). Enforces the §F limits (reject on overflow)."""
    s = normalize_pcm(source, policy)
    blocks = _parse_blocks(s.split("\n"), policy, depth=1)
    _enforce_limits(blocks, policy)
    return blocks


def _parse_blocks(lines, policy, depth) -> list[Node]:
    if depth > policy.max_depth:
        raise PcmError("PCM exceeds max nesting depth")
    out: list[Node] = []
    i, n = 0, len(lines)
    while i < n:
        line = lines[i]
        if not line.strip():
            i += 1
            continue
        if _FENCE_RE.match(line):                      # fenced code (never executed)
            body, i = [], i + 1
            while i < n and not _FENCE_RE.match(lines[i]):
                body.append(lines[i])
                i += 1
            i += 1                                       # consume closing fence
            out.append(Node("pre", children=[Node("code", text="\n".join(body))]))
            continue
        if _THEMATIC_RE.match(line):                    # thematic break: off → drop
            i += 1
            continue
        if line.lstrip().startswith(">"):               # blockquote (nestable)
            quote, i = [], i
            while i < n and lines[i].lstrip().startswith(">"):
                stripped = lines[i].lstrip()[1:]
                quote.append(stripped[1:] if stripped.startswith(" ") else stripped)
                i += 1
            out.append(Node("blockquote", children=_parse_blocks(quote, policy, depth + 1)))
            continue
        mb, mo = _BULLET_RE.match(line), _ORDERED_RE.match(line)
        if mb or mo:                                    # list (flat; comment-grade)
            ordered = mo is not None
            items, i = [], i
            while i < n:
                m = _ORDERED_RE.match(lines[i]) if ordered else _BULLET_RE.match(lines[i])
                if not m:
                    break
                items.append(Node("li", children=_parse_inline(m.group(1))))
                i += 1
            out.append(Node("ol" if ordered else "ul", children=items))
            continue
        mh = _HEADING_RE.match(line)
        if mh:
            inline = _parse_inline(mh.group(2))
            if policy.allow_headings:
                out.append(Node("h" + str(len(mh.group(1))), children=inline))
            else:                                        # headings off → keep the text as a paragraph
                out.append(Node("p", children=inline))
            i += 1
            continue
        para, i = [], i                                  # paragraph: gather until blank/special
        while i < n and lines[i].strip() and not _is_block_start(lines[i]):
            para.append(lines[i])
            i += 1
        out.append(Node("p", children=_parse_inline("\n".join(para))))
    return out


def _is_block_start(line: str) -> bool:
    return bool(_FENCE_RE.match(line) or _THEMATIC_RE.match(line)
                or line.lstrip().startswith(">") or _BULLET_RE.match(line)
                or _ORDERED_RE.match(line) or _HEADING_RE.match(line))


# Inline scanner: ordered so mentions beat links, images/HTML/ref-links are
# dropped, and a bare URL autolinks (rendered masked, like `[…](url)`).
_INLINE = [
    ("image",   re.compile(r"!\[[^\]]*\]\([^)]*\)")),                    # tracking pixels → drop
    ("mention", MENTION_TOKEN_RE),
    ("permalink", PERMALINK_RE),                                         # pm:<id> → in-app link
    ("link",    re.compile(r"\[([^\]]*)\]\((https?://[^)\s]+|[^):\s]+)\)")),
    ("code",    re.compile(r"`([^`]+)`")),
    ("strong",  re.compile(r"\*\*(.+?)\*\*|__(.+?)__", re.DOTALL)),
    ("em",      re.compile(r"\*(.+?)\*|_(.+?)_", re.DOTALL)),
    ("del",     re.compile(r"~~(.+?)~~", re.DOTALL)),
    ("autolink", re.compile(r"https?://[^\s<>()]+")),
    ("html",    re.compile(r"<[^>]+>")),                                 # raw HTML → strip tag
]


def _parse_inline(text: str) -> list[Node]:
    out: list[Node] = []
    buf = []
    i, n = 0, len(text)

    def flush():
        if buf:
            out.append(Node("text", text="".join(buf)))
            buf.clear()

    while i < n:
        matched = False
        for kind, rx in _INLINE:
            m = rx.match(text, i)
            if not m:
                continue
            if kind == "image" or kind == "html":      # strip entirely (inert)
                flush()
                i = m.end()
                matched = True
                break
            flush()
            if kind == "mention":
                out.append(Node("mention", text=m.group(1),
                                attrs={"did": m.group(2), "handle": m.group(1)}))
            elif kind == "permalink":
                out.append(Node("permalink", text=m.group(1), attrs={"id": m.group(1)}))
            elif kind == "link":
                out.append(Node("a", children=_parse_inline(m.group(1)),
                                attrs={"href": m.group(2)}))
            elif kind == "code":
                out.append(Node("code", text=m.group(1)))
            elif kind == "autolink":
                url = m.group(0)
                out.append(Node("a", children=[Node("text", text=url)],
                                attrs={"href": url}))
            else:                                        # strong / em / del
                inner = next(g for g in m.groups() if g is not None)
                out.append(Node(kind, children=_parse_inline(inner)))
            i = m.end()
            matched = True
            break
        if not matched:
            buf.append(text[i])
            i += 1
    flush()
    return out


def _enforce_limits(blocks, policy):
    links = mentions = 0
    stack = list(blocks)
    while stack:
        node = stack.pop()
        if node.tag in ("a", "permalink"):       # a permalink counts as a link
            links += 1
        elif node.tag == "mention":
            mentions += 1
        elif node.tag in ("ul", "ol"):
            items = sum(1 for c in (node.children or ()) if c.tag == "li")
            if items > policy.max_list_items:
                raise PcmError("PCM exceeds max list items")
        if node.children:
            stack.extend(node.children)
    if links > policy.max_links:
        raise PcmError("PCM exceeds max links")
    if mentions > policy.max_mentions:
        raise PcmError("PCM exceeds max mentions")


# ---------------------------------------------------------------------------
# Plain-text renderer — terminal-safe, applies masking + mention resolution
# ---------------------------------------------------------------------------

def render_plain(source, resolver=None, policy: PcmPolicy = COMMENT) -> str:
    """Render PCM `source` to safe plain text for a terminal/log: links masked to
    `label (domain)`, mentions resolved to `@handle` (or fallback + `•` on a miss),
    code/emphasis as their text, blockquotes/lists prefixed. `resolver` is an
    optional `did -> current_handle | None`. Degrades to the raw source on a
    parse/oversize failure (never raises)."""
    try:
        blocks = parse_pcm(source, policy)
    except PcmError:
        return source
    return "\n".join(_render_block(b, resolver) for b in blocks).strip("\n")


def _render_block(node: Node, resolver) -> str:
    if node.tag == "blockquote":
        inner = "\n".join(_render_block(c, resolver) for c in (node.children or ()))
        return "\n".join("> " + ln for ln in inner.split("\n"))
    if node.tag == "pre":
        return node.text_content
    if node.tag in ("ul", "ol"):
        lines, idx = [], 1
        for li in (node.children or ()):
            if li.tag != "li":
                continue
            marker = f"{idx}." if node.tag == "ol" else "•"
            lines.append(f"{marker} {_render_inline(li.children or [], resolver)}")
            idx += 1
        return "\n".join(lines)
    if node.tag.startswith("h") and len(node.tag) == 2 and node.tag[1].isdigit():
        return "#" * int(node.tag[1]) + " " + _render_inline(node.children or [], resolver)
    return _render_inline(node.children or [], resolver)


def _render_inline(nodes, resolver) -> str:
    parts = []
    for node in nodes:
        if node.tag == "text":
            parts.append(node.text or "")
        elif node.tag in ("em", "strong", "del"):
            parts.append(_render_inline(node.children or [], resolver))
        elif node.tag == "code":
            parts.append(node.text or "")
        elif node.tag == "a":
            parts.append(_render_link(node, resolver))
        elif node.tag == "mention":
            parts.append(_render_mention(node, resolver))
        elif node.tag == "permalink":
            parts.append("↗" + (node.attrs.get("id", "")[:8]))   # in-app link → short marker
        else:
            parts.append(_render_inline(node.children or [], resolver))
    return "".join(parts)


def _render_link(node: Node, resolver) -> str:
    href = node.attrs.get("href", "")
    label = node.text_content
    link = analyze_link(href, label)
    bare = label.strip() == href.strip()
    if link.rejected:
        return label                                     # inert text, destination not linkified
    shown = link.display_domain if bare else f"{label} ({link.display_domain})"
    return ("⚠ " + shown) if link.has_warning else shown


def _render_mention(node: Node, resolver) -> str:
    did = node.attrs.get("did", "")
    fallback = node.attrs.get("handle") or node.text_content
    current = resolver(did) if resolver else None
    handle = current or fallback
    return f"@{handle}" + ("" if current else " •")     # trailing dot = unverified
