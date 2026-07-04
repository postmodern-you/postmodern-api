"""Shared wire protocol: canonical signing payloads and signature checks.

Neutral ground imported by both `server` and `client` — it defines how an
event is serialized for signing and how a signature is verified, so the two
sides agree byte-for-byte. It holds no secrets and no client/server policy;
key derivation, encryption, and franking commitments live in client/crypto.

Each chat event is signed by the sender's ed25519 profile key over a
canonical, unit-separated payload, so a member (or a malicious server)
cannot forge another profile's name. The signature covers a content
`commit` that binds the separately-fetched body to the signed skeleton.
"""

import hashlib
import hmac as _hmac
import json
import math
import secrets
import time

import re

import nacl.hash
import nacl.signing
from nacl.encoding import RawEncoder

_US = "\x1f"  # unit separator: unambiguous, language-neutral field delimiter

# ---------------- Wire protocol version (graceful cross-version evolution) -------
#
# A monotonically increasing integer baked into every build (server AND each
# client). After launch, a deployed server and an installed app can be different
# versions; the `hello` handshake (API.md) exchanges both sides' (PROTOCOL_VERSION,
# MIN_PROTOCOL) so each can decide whether it can talk to the other.
#
# Bump rules:
#   - any wire change (new op/field/format)  -> bump PROTOCOL_VERSION
#   - when you drop support for an old peer   -> raise MIN_PROTOCOL to the oldest
#     version you still interoperate with (anything older is told to update)
# Additive changes keep MIN_PROTOCOL where it is (old peers still work, ignoring
# the new bits + feature-detecting via the `hello` reply's `features`).
PROTOCOL_VERSION = 1
MIN_PROTOCOL = 1


def protocol_compatible(peer_protocol: int, peer_min: int) -> bool:
    """Can this build interoperate with a peer at (peer_protocol, peer_min)? True
    iff each side's version is within the other's supported range — i.e. the peer
    isn't too old for us AND we aren't too old for the peer. Symmetric: client and
    server compute the same answer from the `hello` exchange."""
    try:
        return peer_protocol >= MIN_PROTOCOL and PROTOCOL_VERSION >= int(peer_min)
    except (TypeError, ValueError):
        return False


# ---------------- DIDs (self-minted profile identity, IDENTITY.md) ----------------
#
# A profile's DID is its ed25519 signing public key, encoded as a `did:key`
# (self-certifying — no issuer, no resolver). This is the canonical, permanent
# profile id; the human `@handle` is a separate, mutable pointer to it. Encoding
# is standard did:key for ed25519: multibase-base58btc('z') of the multicodec
# (ed25519-pub = 0xed 0x01) prefix + the 32-byte key — so every client (and the
# Flutter port) derives byte-identical DIDs. All ed25519 did:keys start
# "did:key:z6Mk". Pure encoding, no secrets — lives here in the shared module.
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_ED25519_MULTICODEC = b"\xed\x01"
DID_KEY_PREFIX = "did:key:z"


def _b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + out   # leading zeros → '1'


def _b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + _B58.index(ch)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return b"\x00" * (len(s) - len(s.lstrip("1"))) + body


def did_key(sign_pub_hex: str) -> str:
    """The did:key for a profile's ed25519 signing public key (hex)."""
    return DID_KEY_PREFIX + _b58encode(_ED25519_MULTICODEC + bytes.fromhex(sign_pub_hex))


def did_to_sign_pub(did: str) -> str:
    """Inverse of did_key: the ed25519 signing public key (hex) inside a did:key.
    Raises ValueError on a malformed or non-ed25519 did:key."""
    if not did.startswith(DID_KEY_PREFIX):
        raise ValueError("not a did:key")
    b58 = did[len(DID_KEY_PREFIX):]
    raw = _b58decode(b58)
    if raw[:2] != _ED25519_MULTICODEC:
        raise ValueError("did:key is not ed25519")
    # Reject non-canonical encodings: exactly 2 multicodec + 32 key bytes, and the
    # base58 must be its own canonical form (round-trips). Otherwise several distinct
    # DID strings could map to one key — a malleability landmine even if downstream
    # binds to the derived key.
    if len(raw) != 34 or _b58encode(raw) != b58:
        raise ValueError("non-canonical did:key")
    return raw[2:].hex()


# A profile's DID self-certifies its *signing* key (the DID IS the verify key), but
# its X25519 `enc_pub` is a separate key the server would otherwise merely assert —
# leaving a first-contact MITM window on the room-key seal (TOFU only catches a
# *later* swap). So a profile signs a binding of its enc_pub with its sign key at
# claim; resolving the DID returns (enc_pub, this signature), and anyone verifies it
# against `did_to_sign_pub(did)` — making enc_pub **trustless given the DID** (a
# minimal DID document). enc_pub is mint-once/permanent (like the DID); the version
# tag leaves room for a future rotatable binding (add a version/ts then).
def encpub_signing_bytes(did: str, enc_pub: str) -> bytes:
    return _join("pm-encpub-v1", did, enc_pub)

# A message's optional `post` discriminator: None/absent = a plain message; else
# the post *type*, an open-ended short token (text, image, video, event,
# for_sale, …) — a free-form string, not a fixed enum, so new kinds need no
# server change. Type-specific structured data lives in the body; this field just
# says how to read it. Carried in the signed skeleton (sealed `meta` in private
# rooms), so the type can't be forged, relabeled, or stripped.
POST_TYPE_RE = re.compile(r"^[a-z0-9_]{1,32}$")

# WebSocket frame ceiling, shared so client and server agree. It must exceed
# the largest legitimate message — a server-mediated content_put/get carries
# base64 of up to MAX_BLOB_BYTES (25 MiB ⇒ ~33 MiB), and an account blob_get
# carries up to MAX_ACCOUNT_BLOB. Set above the transport default (1 MiB) so
# the *application* size caps return clean errors instead of the transport
# dropping the connection (1009). Big uploads should prefer the presigned
# direct-to-store path, which never crosses the websocket. If MAX_BLOB_BYTES is
# raised past ~28 MiB, raise this too.
WS_MAX_FRAME = 40 * 1024 * 1024

# Body-storage tier threshold. With the `tiered` body store, content at or above
# this size goes to S3 (object storage handles big objects and keeps the NATS
# stream lean); smaller content stays on NATS (sub-millisecond, no extra hop).
# 64 KiB: every text body and small image stays on NATS; large images/video go
# to S3. The client uses it to decide whether to attempt a direct S3 upload; the
# server's threshold is authoritative (CHAT_BODY_S3_THRESHOLD), and the client
# records the tier it actually used, so a mismatch self-corrects.
BODY_S3_THRESHOLD = 64 * 1024

# Max plaintext size of a single message body (bytes). The client enforces this
# *before* encryption so it's consistent across public and private rooms; the
# server allows a looser wire bound (MAX_WIRE_TEXT) to absorb ciphertext
# expansion. Larger content belongs in a post/blob, not a message.
MAX_TEXT_LEN = 4096

# Owner-asserted profile metadata caps (public profile plane, DESIGN.md identity).
# A display name is the human-facing label shown alongside the @handle; the small
# avatar is the chat thumbnail, stored inline server-side but served off the hot
# key-lookup path (a few KB; 16 KiB comfortably holds a ~96px WebP/JPEG). The
# large avatar lives in the object store — the profile only keeps a URL.
MAX_DISPLAY_NAME_LEN = 64
MAX_BIO_LEN = 500            # owner-asserted "about" text shown on the profile page
MAX_AVATAR_BYTES = 16 * 1024
MAX_AVATAR_URL_LEN = 1024
# Large profile-page avatar uploaded to the public object store (see
# server/avatarstore.py). Bigger than the inline thumbnail but still bounded.
MAX_LARGE_AVATAR_BYTES = 4 * 1024 * 1024

# A quote-post body is `QUOTE1:` + JSON {"room","id","text"?}: a reference to
# another message (the quote-tweet analog, POSTS.md). Shared because the server
# parses it on public posts to enforce the privacy boundary (a public post may
# not quote a private room), and clients must agree on the format.
QUOTE_PREFIX = "QUOTE1:"

# A binary/media post body is `PMBLOB1:` + a JSON descriptor (mime, caption,
# blob ref). Shared so the server can recognize a media body — e.g. to keep
# anonymous sessions to plain text, enforced on the body, not the `post` label.
BLOB_PREFIX = "PMBLOB1:"

# Key-exchange CONTROL message bodies (knock pubkey, room-key invite/re-seal).
# These ride a NON-encrypted message frame even in a private room — by necessity:
# they bootstrap the room key (you can't room-encrypt the delivery of that key),
# and the payload is instead sealed to the recipient's individual pubkey. Shared so
# the server can permit exactly these as cleartext in a private room while still
# refusing cleartext CONTENT (the ciphertext-only invariant). Mirror in clients.
CONTROL_PREFIXES = ("pk1:", "inv1:", "inv2:")


def canonical_json(obj) -> str:
    """Deterministic JSON for any body that gets SIGNED + franked (commit), so
    its bytes are byte-identical across clients for the same logical content.
    Canonical form: keys sorted, no whitespace, raw UTF-8 (non-ASCII left
    unescaped) — exactly Dart's `jsonEncode` over a key-sorted map, so the
    Flutter port matches with `_canonicalJson`. Use ONLY str/int/bool/None
    values; floats are forbidden (they serialize differently across languages
    — e.g. 1.0 vs 1) and would silently break parity. This is the structured
    analog of `pcm.normalize_pcm` for free-text bodies."""
    if _has_float(obj):
        raise ValueError("canonical_json: float values break cross-client "
                         "byte-parity; use int/str instead")
    if _has_nonascii_key(obj):
        # Keys are sorted for canonicalization, but Python sorts by Unicode code
        # point while Dart's jsonEncode sorts by UTF-16 code unit — they DIVERGE for
        # astral-plane (surrogate-pair) chars in KEYS, which would produce different
        # canonical bytes and break the franking commitment. Values are fine (not
        # sorted). All descriptor keys are fixed ASCII schema, so enforce that.
        raise ValueError("canonical_json: object keys must be ASCII "
                         "(non-ASCII keys sort differently across clients)")
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def _has_nonascii_key(obj) -> bool:
    if isinstance(obj, dict):
        return any((not str(k).isascii()) or _has_nonascii_key(v)
                   for k, v in obj.items())
    if isinstance(obj, (list, tuple)):
        return any(_has_nonascii_key(v) for v in obj)
    return False


def _has_float(obj) -> bool:
    if isinstance(obj, float):
        return True
    if isinstance(obj, dict):
        return any(_has_float(v) for v in obj.values())
    if isinstance(obj, (list, tuple)):
        return any(_has_float(v) for v in obj)
    return False


def blob_descriptor_body(descriptor: dict) -> str:
    """Canonical wire form of a media/blob post body: `BLOB_PREFIX` + canonical
    JSON of the descriptor. The body is what the author signs + commits
    (franks), so two clients composing the same logical image post MUST emit
    identical bytes — otherwise the commitment doesn't reproduce and
    cross-client equality/dedup breaks (the descriptor analog of
    `normalize_pcm`). Always build the body through this, never raw
    `json.dumps(descriptor)`."""
    return BLOB_PREFIX + canonical_json(descriptor)

# BlurHash (https://blurhash.dev): a compact base83 string encoding a tiny blurred
# preview of an image. Every image upload must carry one (descriptor `blurhash`),
# so a viewer always has an instant placeholder. We don't decode it server-side —
# we validate that it's STRUCTURALLY a real BlurHash, a cheap, forge-resistant gate
# that rejects junk/absent values. The same check runs client-side (private rooms
# seal the descriptor, so the server can't see it there — the client is the gate).
BLURHASH_ALPHABET = ("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                     "#$%*+,-.:;=?@[]^_{|}~")
_BLURHASH_INDEX = {c: i for i, c in enumerate(BLURHASH_ALPHABET)}


def _b83_decode(s: str) -> int:
    v = 0
    for c in s:
        v = v * 83 + _BLURHASH_INDEX[c]   # KeyError on any non-base83 char
    return v


def blurhash_valid(s) -> bool:
    """True iff `s` is a structurally valid BlurHash. Three checks, no decode:
    (1) every character is in the base83 alphabet; (2) the length equals
    4 + 2*numX*numY where (numX, numY) are dictated by the first character's size
    flag (a built-in checksum tying the first char to the total length — only
    size flags 0..80, i.e. 1..9 components per axis, are legal); (3) the DC
    component (chars 2..5) is a real packed 24-bit RGB (< 2**24)."""
    if not isinstance(s, str) or len(s) < 6:
        return False
    if any(c not in _BLURHASH_INDEX for c in s):          # (1) charset
        return False
    size_flag = _BLURHASH_INDEX[s[0]]
    if size_flag > 80:                                    # only 1..9 per axis
        return False
    num_x, num_y = (size_flag % 9) + 1, (size_flag // 9) + 1
    if len(s) != 4 + 2 * num_x * num_y:                   # (2) length<->components
        return False
    return _b83_decode(s[2:6]) < (1 << 24)                # (3) DC is 24-bit RGB

# Polls are a special POST type ("poll") whose body is `PMPOLL1:` + JSON
# {"q": question, "options": [opt, …]} — the poll *definition*, a signed board
# post like any other. A BALLOT, by contrast, is NOT a message: it's a dedicated
# signed `pollvote` annotation (like a vote/reaction) carrying the chosen option
# index, so the SERVER can fold it into an authoritative per-poll tally (the
# source of truth for a public poll) — a message body can't be tallied
# server-side because the historian folds skeletons, not bodies. Ballots dedup
# ONE per profile, first wins (no revote). Polls live only in public boards.
POLL_PREFIX = "PMPOLL1:"
MAX_POLL_OPTIONS = 10
MAX_POLL_QUESTION = 280


def parse_poll(text: str):
    """Return a validated poll definition {"q", "options"} if `text` is a poll
    body, else None."""
    if not text.startswith(POLL_PREFIX):
        return None
    try:
        d = json.loads(text[len(POLL_PREFIX):])
    except (ValueError, TypeError):
        return None
    if not isinstance(d, dict):
        return None
    q, opts = d.get("q"), d.get("options")
    if not isinstance(q, str) or not q or len(q) > MAX_POLL_QUESTION:
        return None
    if not isinstance(opts, list) or not (2 <= len(opts) <= MAX_POLL_OPTIONS):
        return None
    if not all(isinstance(o, str) and o for o in opts):
        return None
    return {"q": q, "options": opts}


def pollvote_signing_bytes(room, poll_id, choice, ts_ms) -> bytes:
    return _join("pm-pollvote-v2", room, poll_id, str(choice), str(ts_ms))

# A board post gets its own comment room, named deterministically from the post
# id so any client that sees the post can find it: `post-<post id>`. Shared so
# client and server agree (the server auto-creates it on the publish path).
POST_ROOM_PREFIX = "post-"

# The single shared public board ("the big board"). All posts go here — board
# creation is otherwise disabled (one board until traffic warrants sub-boards).
# Shared so the server (which auto-creates it) and the client (which joins it to
# post) agree on the name. An operator override (CHAT_BIGBOARD) must be matched
# on the client, same as INBOX_SUFFIX.
BIGBOARD = "bigboard"


def post_room(post_id: str) -> str:
    return POST_ROOM_PREFIX + post_id


# A profile's notification inbox is a room named deterministically from its
# permanent DID — NOT its @handle — so the inbox (and its NATS subject) survives a
# handle change (IDENTITY.md 1c-B). Hashed to stay within the room-name charset
# (alphanumeric/-/_), since a did:key contains colons. Shared so client + server
# agree. Plain sha256 (NOT the double-hex commit quirk).
INBOX_PREFIX = "inbox-"


def inbox_room(did: str) -> str:
    return INBOX_PREFIX + hashlib.sha256(did.encode()).hexdigest()[:24]


# A system moderator's private mod-review room — server-authored, member = that mod
# only — where the server crossposts every scanned public image's verdict for human
# review. Named from the mod's permanent DID (like the inbox) so it's stable.
MODREVIEW_PREFIX = "modreview-"


def modreview_room(did: str) -> str:
    return MODREVIEW_PREFIX + hashlib.sha256(did.encode()).hexdigest()[:24]


# The single shared franked-report review room: every verified abuse report from a
# PRIVATE room (franking, API.md §7b) is server-authored here as cleartext for the
# system moderators to review. Distinct from the per-mod image MODREVIEW rooms. It
# carries content + reporter + reportee only — a private message has no permalink.
FRANKING_REPORTS_ROOM = "franking-reports"


def is_reserved_room_name(name: str) -> bool:
    """Room names the SERVER owns and creates itself: the shared board, a profile's
    inbox, the per-mod image-review rooms, a post's comment room, and the shared
    franked-report room. `room_create` must REFUSE these — otherwise a user can
    pre-create ("squat") a system room, become its sponsor, and receive the
    cleartext the server authors into it (abuse-report plaintext + reporter/reportee
    DIDs + surrendered images; per-mod NSFW verdicts). The system rooms are created
    with server-only kinds ('inbox'/'modreview'/'board'), which a client can't set
    via room_create — that kind check is the second line of defense (see
    `_ensure_franking_room`/`_crosspost_verdict`)."""
    return (name == BIGBOARD
            or name == FRANKING_REPORTS_ROOM
            or name.startswith((INBOX_PREFIX, MODREVIEW_PREFIX, POST_ROOM_PREFIX)))


def parse_quote(text: str):
    """Return the quote descriptor dict if `text` is a quote body, else None."""
    if not text.startswith(QUOTE_PREFIX):
        return None
    try:
        d = json.loads(text[len(QUOTE_PREFIX):])
    except (ValueError, TypeError):
        return None
    return d if isinstance(d, dict) and "room" in d and "id" in d else None


def parse_blob(text: str):
    """Return the media descriptor dict if `text` is a blob body, else None.
    Cleartext (public-room) bodies only — a private room's descriptor is sealed,
    so the server never sees it (the client enforces media rules there)."""
    if not text.startswith(BLOB_PREFIX):
        return None
    try:
        d = json.loads(text[len(BLOB_PREFIX):])
    except (ValueError, TypeError):
        return None
    return d if isinstance(d, dict) else None


def _join(*parts) -> bytes:
    return _US.join(parts).encode()


# v2 (IDENTITY.md 1c): authorship-by-signature. The author is NO LONGER in the
# signed bytes — the signing key IS the author (its `did:key` is stamped on the
# frame and self-verifies). So these cover CONTENT only; a verifier extracts the
# key from the frame's `did` and checks the sig. Tag bumped v1→v2 so an old
# author-bearing sig can never be confused with a new one (hard cutover; reseed).
def message_signing_bytes(id, room, parent, ts_ms, commit, post=None) -> bytes:
    # `post` is appended only when set, so plain messages produce identical bytes.
    # When set, it's bound by the signature, so it can't be added/changed/stripped.
    base = ("pm-msg-v2", id, room, parent or "", str(ts_ms), commit)
    return _join(*base, post) if post else _join(*base)


def vote_signing_bytes(id, room, vote, ts_ms) -> bytes:
    return _join("pm-vote-v2", id, room, vote, str(ts_ms))


def auth_signing_bytes(name, nonce) -> bytes:
    """Domain-separated payload a profile signs for `profile_auth` (login). Tagged
    + field-separated so the identity key never signs a bare, ambiguous string —
    defense-in-depth against cross-protocol signature reuse. (The server still
    accepts the legacy bare-nonce signature during the client migration.)"""
    return _join("pm-auth-v1", name, nonce)


# Emoji reactions: a reaction is a small signed annotation on a message id —
# like a vote, but the value is an emoji and a user may attach a SET of them
# (multiple distinct emoji per message), each toggled add/remove. The signature
# binds target+emoji+op so a reaction can't be forged, retargeted, or flipped
# add↔remove. `op` ∈ {add, remove}. Emoji is capped so a reaction can't smuggle
# a text payload (a few codepoints for ZWJ/skin-tone sequences is plenty).
MAX_EMOJI_BYTES = 32
REACTION_OPS = ("add", "remove")


def valid_emoji(emoji: str) -> bool:
    return (isinstance(emoji, str) and 0 < len(emoji.encode("utf-8")) <= MAX_EMOJI_BYTES
            and not any(c.isspace() or ord(c) < 0x20 for c in emoji))


def reaction_signing_bytes(room, target, emoji, op, ts_ms) -> bytes:
    return _join("pm-react-v2", room, target, emoji, op, str(ts_ms))


# --- anonymous (no-account) sessions: proof-of-work-gated ephemeral profiles --
# Zero-friction public commenting (no login) mints a THROWAWAY profile on the
# chat plane: a client-generated keypair claimed via PROOF OF WORK instead of an
# account voucher. PoW replaces the account/voucher sybil gate — it taxes
# identity *creation* with CPU, independent of IP, so it survives carrier-grade
# NAT (many users behind one address) and IP rotation (which a per-IP limit
# can't). It is a cost, not a wall.
#
# Puzzle (hashcash-style): find a `nonce` such that
#   sha256("pm-anon-pow-v1" ⋮ challenge ⋮ sign_pub ⋮ nonce)
# has >= `bits` leading zero bits. Verification is ONE sha256 (O(1)) — chosen so
# the verifier is never itself a DoS target; the difficulty *unit* can be swapped
# for an asymmetric memory-hard one later if GPU grinding shows up. The
# server-issued, single-use `challenge` blocks precomputation/replay; binding
# `sign_pub` means a solved proof can't be reused for a different identity.
#
# SHA-256 (not BLAKE2b): we briefly used libsodium's BLAKE2b to keep the client on
# one hash, but the Dart libsodium binding doesn't expose crypto_generichash, so the
# Flutter client needs a separate hash dependency either way — and SHA-256 lives in
# Dart's canonical `crypto` package. So this stays SHA-256 (stdlib hashlib here).
#
# Anonymous guests get a pronounceable three-word handle (e.g. `brave_otter_charlie`)
# assigned server-side from operator-editable word lists — see server/anon_names.py.
# There is NO reserved name prefix: guests share the real-user handle namespace,
# and clients tell a guest apart by the `anon` profile flag (in profile_info /
# profile_infos), not by the name. The client just uses the name the server returns.


def leading_zero_bits(digest: bytes) -> int:
    """Number of leading zero BITS in a byte string."""
    n = 0
    for byte in digest:
        if byte == 0:
            n += 8
            continue
        b = byte
        while b < 0x80:   # top bit not yet set
            n += 1
            b <<= 1
        break
    return n


def anon_pow_digest(challenge: str, sign_pub: str, nonce: str) -> bytes:
    return hashlib.sha256(_join("pm-anon-pow-v1", challenge, sign_pub, nonce)).digest()


def pow_ok(challenge: str, sign_pub: str, nonce: str, bits: int) -> bool:
    return leading_zero_bits(anon_pow_digest(challenge, sign_pub, nonce)) >= bits


def solve_pow(challenge: str, sign_pub: str, bits: int) -> str:
    """Find a nonce satisfying the puzzle (the client-side work). Returns the
    nonce as a hex string."""
    i = 0
    while True:
        nonce = format(i, "x")
        if leading_zero_bits(anon_pow_digest(challenge, sign_pub, nonce)) >= bits:
            return nonce
        i += 1


def anon_claim_signing_bytes(challenge, sign_pub, enc_pub, pow_nonce) -> bytes:
    # Signed by the ephemeral key to prove possession and bind the winning PoW +
    # both pubkeys to this claim on this connection (so a relay can't swap keys).
    return _join("pm-anon-claim-v1", challenge, sign_pub, enc_pub, pow_nonce)


def sign_event(sign_seed_hex: str, payload: bytes) -> str:
    key = nacl.signing.SigningKey(bytes.fromhex(sign_seed_hex))
    return key.sign(payload).signature.hex()


def verify_event(sign_pub_hex: str, payload: bytes, sig_hex: str) -> bool:
    try:
        nacl.signing.VerifyKey(bytes.fromhex(sign_pub_hex)).verify(payload, bytes.fromhex(sig_hex))
        return True
    except Exception:
        return False


# Franking commitment (DESIGN.md §3 / API.md §7b): `commit = PRF(fk, plaintext)`
# with a per-message key `fk` carried only to room members. A report reveals one
# message's (plaintext, fk); the server verifies the commitment opens — proving
# WHAT was sent — and the author's separate `sig` over `commit` proves WHO. These
# mirror client/crypto.py byte-for-byte (parity test in tests/test_crypto.py) so a
# member's commitment and the server's verification agree.
def commit_private(fk: bytes, plaintext: str) -> str:
    return nacl.hash.blake2b(
        plaintext.encode(), key=fk, digest_size=32, encoder=RawEncoder
    ).hex()


def open_commitment(commit: str, fk: bytes, plaintext: str) -> bool:
    return _hmac.compare_digest(commit, commit_private(fk, plaintext))


def hash_bytes(data: bytes) -> str:
    """Plaintext content hash carried in a blob descriptor (mirrors
    client/crypto.py byte-for-byte — the documented double-hex wart: PyNaCl's
    blake2b hex-encodes, then `.hex()` re-encodes → 128 hex chars). Lets the
    server bind a franking report's surrendered image to the authored descriptor's
    `hash` (API.md §7b), so a reporter can't swap in a different picture."""
    return nacl.hash.blake2b(data, digest_size=32).hex()


# --- account→profile-plane attestations (the only bridge between the planes) -
# An attestation is a SIGNED bearer token, so the two plane servers need no
# shared DB and no callback: the account server signs (it holds the seed), the
# chat server verifies offline with the public key and dedupes the nonce in its
# own spent-set. The chat server thus learns only "a valid, unspent token of
# this purpose" — never the account. Two purposes exist, each with the same
# shape but a distinct *audience tag* baked into the signed bytes so one can
# never be replayed as the other:
#   - PURPOSE_CLAIM      — a profile-claim voucher (humanity, DESIGN.md §3, §11)
#   - PURPOSE_EMAIL      — "the bearer's account verified an email" (one-way flag)
# (Future: blind-sign so even the issuer can't recognize the token.)
PURPOSE_CLAIM = "claim"
PURPOSE_EMAIL = "emailverify"
PURPOSE_IRL = "irlverify"   # "the bearer's account is verified as a real person"
PURPOSE_PAYING = "payingverify"   # "the bearer's account is a paying customer" (flows to all its profiles)

# Owner-asserted account email (account plane only; never reaches the profile
# plane). A deliberately permissive check — real validation is the round-trip.
MAX_EMAIL_LEN = 254
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def voucher_pubkey(seed_hex: str) -> str:
    """The ed25519 public key (hex) for a voucher signing seed."""
    return nacl.signing.SigningKey(bytes.fromhex(seed_hex)).verify_key.encode().hex()


def voucher_sign(seed_hex: str, nonce_hex: str, purpose: str = PURPOSE_CLAIM) -> str:
    """Issue a token: a `nonce⋮sig(purpose:nonce)` bearer credential. The nonce
    is the single-use identity the chat server dedupes; the signature (over the
    purpose-tagged nonce) proves issuance *and* binds the token to one purpose,
    so a claim voucher can't be presented as an email attestation or vice versa."""
    signed = f"{purpose}:{nonce_hex}".encode()
    sig = nacl.signing.SigningKey(bytes.fromhex(seed_hex)).sign(signed).signature.hex()
    return f"{nonce_hex}{_US}{sig}"


def voucher_verify(pubkey_hex: str, token: str, purpose: str = PURPOSE_CLAIM) -> str | None:
    """Verify a token against the issuer's public key *and* the expected purpose;
    return its nonce (the dedupe key) or None. No account information is
    conveyed. A token signed for a different purpose fails to verify."""
    try:
        nonce_hex, sig = token.split(_US, 1)
        signed = f"{purpose}:{nonce_hex}".encode()
        nacl.signing.VerifyKey(bytes.fromhex(pubkey_hex)).verify(signed, bytes.fromhex(sig))
        return nonce_hex
    except Exception:
        return None


# ---------------- Verifiable Credentials (IDENTITY.md Phase 2) ----------------
#
# A VC is an issuer-signed attestation BOUND TO A SUBJECT DID: "<issuer> says
# <subject DID> has <type>" (type = a badge slug — "irl"/"email", the humanness
# ladder). Unlike a bearer voucher (`nonce⋮sig`, transferable to any DID), a VC
# names its subject, so it only validates for that one DID — a verified human
# can't hand their "irl" credential to a sybil. `iss` is the issuer's ed25519
# public key (hex); a verifier trusts a set of issuer keys (one today, federation
# later). `nonce` is the single-use / revocation id (deduped like a voucher).
# `exp` = 0 means no expiry. NOTE: issuance is LINKABLE (the issuer sees the
# subject DID); unlinkable *presentation* is a separate, later layer (§3.4).
VC_VERSION = "pm-vc-v1"


def vc_signing_bytes(iss, sub, typ, iat, exp, nonce) -> bytes:
    return _join(VC_VERSION, iss, sub, typ, str(iat), str(exp), nonce)


def vc_sign(seed_hex: str, sub: str, typ: str, iat: int, nonce_hex: str,
            exp: int = 0) -> str:
    """Issue a DID-bound credential, signed by the issuer seed. Returns a token
    `iss⋮sub⋮typ⋮iat⋮exp⋮nonce⋮sig` (the signed fields + the detached signature,
    so a verifier recovers and re-checks them). `sub` is the subject's did:key."""
    iss = voucher_pubkey(seed_hex)
    body = (iss, sub, typ, str(int(iat)), str(int(exp)), nonce_hex)
    sig = nacl.signing.SigningKey(bytes.fromhex(seed_hex)).sign(
        vc_signing_bytes(*body)).signature.hex()
    return _US.join((*body, sig))


def vc_verify(pubkey_hex: str, token: str, now: float | None = None) -> dict | None:
    """Verify a VC token against a trusted issuer key: checks the signature, that
    the embedded `iss` equals the verifying key, and (if set) that it has not
    expired. Returns the claims dict {iss, sub, typ, iat, exp, nonce} or None. The
    CALLER enforces the binding (`sub` == the presenting DID), the expected `typ`,
    and single-use (dedupe the `nonce`)."""
    parts = token.split(_US)
    if len(parts) != 7:
        return None
    iss, sub, typ, iat_s, exp_s, nonce, sig = parts
    if iss != pubkey_hex:                       # issuer id must be the verifying key
        return None
    try:
        nacl.signing.VerifyKey(bytes.fromhex(pubkey_hex)).verify(
            vc_signing_bytes(iss, sub, typ, iat_s, exp_s, nonce), bytes.fromhex(sig))
    except Exception:
        return None
    exp = int(exp_s) if exp_s else 0
    if exp and (now if now is not None else time.time()) > exp:
        return None
    return {"iss": iss, "sub": sub, "typ": typ, "iat": int(iat_s), "exp": exp,
            "nonce": nonce}


# ---------------- Verifiable Presentations (IDENTITY.md Phase 3) ----------------
#
# Selective disclosure: the HOLDER bundles a *chosen subset* of its VCs into a
# presentation, signed by its own DID key — proving it controls the subject the
# VCs are about, WITHOUT involving the issuer. The holder picks what to reveal.
# (Phase 4 hides the DID itself; here the DID is still revealed — linkable.)
# Bound to an `audience` (who/what it's for — e.g. a room) + `created` time so a
# presentation can't be misdelivered or replayed out of context. The envelope uses
# RS (\x1e) since the VC tokens it carries use US (\x1f) internally.
_RS = "\x1e"
VP_VERSION = "pm-vp-v1"


def vp_signing_bytes(holder_did, audience, created, vc_tokens) -> bytes:
    # Binds the holder, the audience, the time, and the EXACT set+order of VCs.
    # (VC tokens contain US internally; harmless — signer and verifier rebuild the
    # identical bytes from the same parsed list.)
    return _join(VP_VERSION, holder_did, audience, str(created), *vc_tokens)


def vp_sign(sign_seed_hex: str, holder_did: str, audience: str, created: int,
            vc_tokens: list) -> str:
    """Build a holder-signed presentation token (fields RS-joined):
    `VP_VERSION, holder_did, audience, created, sig, *vc_tokens`."""
    sig = nacl.signing.SigningKey(bytes.fromhex(sign_seed_hex)).sign(
        vp_signing_bytes(holder_did, audience, created, vc_tokens)).signature.hex()
    return _RS.join([VP_VERSION, holder_did, audience, str(int(created)), sig, *vc_tokens])


def vp_verify(token: str, trusted_issuers, audience: str | None = None,
              now: float | None = None, max_age: float = 300) -> dict | None:
    """Verify a presentation. Checks: the holder signature (proves control of
    `holder_did` — its DID key), the audience (if given) and freshness, and every
    carried VC (issuer in `trusted_issuers`, valid signature, and `sub` == the
    holder — the VCs are *about the presenter*). Returns
    {holder, audience, created, creds:[claims]} or None. Selective disclosure: only
    the VCs the holder chose to include are present. The caller decides which
    credential types it required."""
    parts = token.split(_RS)
    if len(parts) < 5:
        return None
    version, holder_did, aud, created_s, sig = parts[:5]
    vc_tokens = parts[5:]
    if version != VP_VERSION:
        return None
    if audience is not None and aud != audience:
        return None
    try:
        created = int(created_s)
    except ValueError:
        return None
    now = now if now is not None else time.time()
    if max_age and abs(now - created) > max_age:
        return None
    try:
        holder_sign_pub = did_to_sign_pub(holder_did)
    except ValueError:
        return None
    if not verify_event(holder_sign_pub,
                        vp_signing_bytes(holder_did, aud, created_s, vc_tokens), sig):
        return None
    creds = []
    for vct in vc_tokens:
        iss = vct.split(_US, 1)[0]
        if iss not in trusted_issuers:           # only trusted issuers count
            return None
        claims = vc_verify(iss, vct, now=now)
        if claims is None or claims["sub"] != holder_did:   # VC must be about the holder
            return None
        creds.append(claims)
    return {"holder": holder_did, "audience": aud, "created": created, "creds": creds}


# ---------------- Anonymous tokens — blind RSA (IDENTITY.md Phase 4) ----------------
#
# Unlinkable, one-time "a verified human did this" tokens, used as the discovery
# anti-Sybil KNOCK credential (DISCOVERY.md §6b) and any future ephemeral
# humanness proof. FDH blind RSA (Chaum): the issuer (account plane) blind-signs a
# token the holder later redeems — the issuer can't link issuance to redemption
# (it only ever sees a blinded value). Crucially **publicly verifiable**: the
# redeeming/verifying plane holds only the PUBLIC key, so it can check tokens but
# CANNOT mint them — exactly what stops the discovery server from flooding mailboxes
# itself. Each token carries a random id; the verifier dedups it (one-time).
#
# Security notes: FDH-RSA blind signatures are one-more-unforgeable under RSA + ROM.
# The full-domain hash maps the token id into [0, n) via MGF1-SHA256 over >|n| bytes
# (negligible mod-n bias). SECURITY-CRITICAL + cross-client: any other client must
# reproduce _anontoken_fdh and the (id:sig hex) wire form byte-for-byte. Needs a
# proper crypto review before it is leaned on for more than anti-abuse.
ANONTOKEN_VERSION = "pm-anontok-v1"
ANONTOKEN_ID_BYTES = 32


def _mgf1_sha256(seed: bytes, length: int) -> bytes:
    out, counter = b"", 0
    while len(out) < length:
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def _anontoken_fdh(token_id: bytes, n: int) -> int:
    """Full-domain hash of a token id into [0, n). MGF1-SHA256 over (|n| + 16)
    bytes then reduce mod n — the 16 extra bytes make the bias negligible."""
    k = (n.bit_length() + 7) // 8
    h = _mgf1_sha256(ANONTOKEN_VERSION.encode() + b"\x1f" + token_id, k + 16)
    return int.from_bytes(h, "big") % n


def anontoken_new_id() -> bytes:
    return secrets.token_bytes(ANONTOKEN_ID_BYTES)


def anontoken_blind(token_id: bytes, n: int, e: int) -> tuple[int, int]:
    """Holder side: returns (blinded, unblinder). Send `blinded` to the issuer to
    sign; keep `unblinder` to recover the signature. The issuer learns nothing about
    `token_id` (blinded by a fresh random factor)."""
    m = _anontoken_fdh(token_id, n)
    while True:
        r = secrets.randbelow(n - 2) + 2
        if math.gcd(r, n) == 1:
            break
    blinded = (m * pow(r, e, n)) % n
    return blinded, pow(r, -1, n)


def anontoken_sign(blinded: int, n: int, d: int) -> int:
    """Issuer side: blind-sign. The caller MUST first reject blinded values outside
    (1, n-1) — degenerate inputs leak nothing useful but shouldn't be signed."""
    return pow(blinded % n, d, n)


def anontoken_unblind(blind_sig: int, unblinder: int, n: int) -> int:
    """Holder side: recover the signature on the (unblinded) token id."""
    return (blind_sig * unblinder) % n


def anontoken_verify(token_id: bytes, sig: int, n: int, e: int) -> bool:
    """Verifier side (PUBLIC key only): is `sig` a valid issuer signature on
    `token_id`? Cannot be produced without the private key (one-more-unforgeable)."""
    if not (0 < sig < n):
        return False
    return pow(sig, e, n) == _anontoken_fdh(token_id, n)


def anontoken_encode(token_id: bytes, sig: int) -> str:
    """Wire form of a redeemable token: `<id hex>:<sig hex>`."""
    return token_id.hex() + ":" + format(sig, "x")


def anontoken_decode(token: str) -> tuple[bytes, int] | None:
    try:
        id_hex, sig_hex = token.split(":", 1)
        tid = bytes.fromhex(id_hex)
        if len(tid) != ANONTOKEN_ID_BYTES:
            return None
        return tid, int(sig_hex, 16)
    except Exception:
        return None
