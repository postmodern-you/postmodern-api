#!/usr/bin/env python3
"""Generate the shared fuzz corpus consumed by the Flutter client's Dart fuzz suite.

The Bridge. Both the Python and the Flutter/Dart fuzz suites REPLAY this shared corpus,
so they converge on the same adversarial cases with zero cross-process plumbing. This
draws a deterministic, diverse sample from the `wire`/`pcm` protocol shapes, unions in
hand-picked edge cases, and writes one JSON value per line to fuzz_corpus/<kind>.jsonl:

  frames.jsonl — event-frame dicts (corrupted message/vote/reaction/delete/…) → ClientFold.ingest
  pcm.jsonl    — comment/markdown strings                                      → parsePcm
  blobs.jsonl  — PMBLOB1: descriptor bodies (valid + corrupt)                  → parseBlob
  links.jsonl  — URLs                                                          → analyzeLink

Deterministic for a given Hypothesis version (fixed seed, no example DB) → regenerating
gives a byte-identical diff. A Hypothesis upgrade may reshuffle the random sample, so
regenerate + commit when you bump it. Rerun after the suite turns up something new —
and if it ever finds a FALSIFYING example, add it to the KNOWN_* seeds so both fuzzers
pin it forever.

    python gen_fuzz_corpus.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))   # repo root: wire.py, pcm.py

from hypothesis import HealthCheck, given, seed, settings, strategies as st

import wire

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fuzz_corpus")

# ---- strategies: mirror the property-test shapes ---------------------------------
json_scalar = st.one_of(st.none(), st.booleans(),
                        st.integers(min_value=-(2**60), max_value=2**60), st.text(max_size=40))
_json = st.recursive(
    json_scalar,
    lambda c: st.lists(c, max_size=4) | st.dictionaries(st.text(max_size=10), c, max_size=4),
    max_leaves=6)

# frames: a valid event `type` + a random subset of real field names carrying
# arbitrary (corrupted) values — exactly what fold ingest must survive.
_EVENT_TYPES = ["message", "vote", "reaction", "delete", "notification", "pollvote"]
_FIELDS = ["id", "room", "parent", "ts", "text", "commit", "sig", "vote", "target",
           "emoji", "op", "seq", "did", "name", "post", "choice", "kind"]
S_frames = st.fixed_dictionaries({"type": st.sampled_from(_EVENT_TYPES)},
                                 optional={f: _json for f in _FIELDS})

# pcm: arbitrary text, and token-rich strings built from real PCM syntax fragments
# (incl. the injection/spoofer bytes the normalizer must strip).
_PCM_TOKENS = ["**b**", "_i_", "`c`", "> q", "@[al](did:key:z6Mkabc)", "[lbl](https://ex.com)",
               "pm:abc123", "\n\n", "- item", "# h", "~~s~~", "\x1f", "‮", "🔥", "](", "[]("]
S_pcm = st.one_of(
    st.text(max_size=400),
    st.lists(st.one_of(st.sampled_from(_PCM_TOKENS), st.text(max_size=16)), max_size=14).map("".join))

# blobs: descriptors serialized through the real wire encoder (valid bodies).
S_desc = st.dictionaries(
    st.text(st.characters(min_codepoint=0x21, max_codepoint=0x7e), min_size=1, max_size=16),
    json_scalar, max_size=8)

# links: arbitrary text + scheme:rest (dangerous + benign) + well-formed https.
_SCHEMES = ["https", "http", "javascript", "data", "file", "ftp", "mailto", ""]
S_links = st.one_of(
    st.text(max_size=120),
    st.builds(lambda s, r: f"{s}:{r}", st.sampled_from(_SCHEMES), st.text(max_size=60)),
    st.builds(lambda h, p: f"https://{h}/{p}", st.text(max_size=40), st.text(max_size=40)))

# ---- hand-picked edge cases (guaranteed coverage of the tricky shapes) -----------
KNOWN_FRAMES = [
    {"type": "message"}, {"type": "message", "id": None, "ts": "not-a-number"},
    {"type": "message", "parent": ""}, {"type": "message", "parent": None},
    {"type": "vote", "id": "", "vote": "up"}, {"type": "vote", "vote": 123},
    {"type": "reaction", "target": {"nested": 1}, "emoji": ""}, {"type": "delete"},
    {"type": "delete", "id": [1, 2, 3]}, {"type": "notification"},
    {"type": "pollvote", "choice": -1}, {"type": "message", "seq": "x", "commit": None},
]
KNOWN_PCM = ["", "**", "**unclosed", "[x](javascript:alert(1))", "@[a](did:key:z6M)",
             "pm:", "\x1f\x1f", "‮reversed‬", "> " * 6, "```\ncode\n```",
             "😀" * 4, "\n\n\n\n\n", "[]()", "[label](  )", "\r\n\r\n"]
KNOWN_BLOBS = ["PMBLOB1:", "PMBLOB1:{", "PMBLOB1:not-json", "PMBLOB1:[]", "PMBLOB1:null",
               'PMBLOB1:{"blob_id":123}', 'PMBLOB1:{"blob_id":"a","mime":null}',
               "not-prefixed", "", "PMBLOB1:" + "{}" * 3]
KNOWN_LINKS = ["javascript:alert(1)", "data:text/html,<script>", "file:///etc/passwd",
               "https://example.com/path", "http://a", "", "://noscheme", "https://",
               "ftp://host/x", "mailto:a@b.com", "HTTPS://EXAMPLE.COM", "https://xn--e1afmkfd.xn--p1ai"]


def _collect(strategy, n):
    out = []

    @seed(1729)
    @settings(max_examples=n, database=None, deadline=None,
              suppress_health_check=list(HealthCheck))
    @given(strategy)
    def run(x):
        out.append(x)

    run()
    return out


def _write(kind, values):
    """Dedupe on the serialized line, sort for a stable diff, write one JSON/line."""
    lines = sorted({json.dumps(v, ensure_ascii=False, sort_keys=True) for v in values})
    path = os.path.join(OUT, f"{kind}.jsonl")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return len(lines)


def main():
    os.makedirs(OUT, exist_ok=True)

    frames = _collect(S_frames, 400) + KNOWN_FRAMES
    pcm = _collect(S_pcm, 400) + KNOWN_PCM
    links = _collect(S_links, 400) + KNOWN_LINKS

    # blobs: real encoder output for valid descriptors + the corrupt raw bodies
    blobs = list(KNOWN_BLOBS)
    for d in _collect(S_desc, 400):
        try:
            blobs.append(wire.blob_descriptor_body(d))
        except ValueError:
            pass   # e.g. a key the encoder rejects — not a valid body, skip

    for kind, vals in [("frames", frames), ("pcm", pcm), ("blobs", blobs), ("links", links)]:
        n = _write(kind, vals)
        print(f"  {kind}.jsonl: {n} cases")


if __name__ == "__main__":
    main()
