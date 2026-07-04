"""Replay the shared fuzz corpus through the Python `wire`/`pcm` parsers.

The corpus (../fuzz_corpus/*.jsonl, produced by gen_fuzz_corpus.py) is replayed by both
the Python side (here) and the Flutter client's Dart fuzz suite. Replaying it here
guards that the committed cases stay well-formed AND that no case crashes the parsers
that MUST survive hostile input: parse_pcm / normalize_pcm, analyze_link, parse_blob.

Note: `frames.jsonl` targets the Dart client's hardened `ClientFold.ingest`; there is
no Python fold here, so frames are validated structurally only.
"""

import json
import os

import wire
from pcm import analyze_link, normalize_pcm, parse_pcm

CORPUS = os.path.join(os.path.dirname(os.path.dirname(__file__)), "fuzz_corpus")


def _load(kind):
    with open(os.path.join(CORPUS, f"{kind}.jsonl"), encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def test_corpus_present_and_correctly_typed():
    for kind, typ in [("frames", dict), ("pcm", str), ("blobs", str), ("links", str)]:
        vals = _load(kind)
        assert vals, f"{kind} corpus is empty — regenerate with gen_fuzz_corpus.py"
        assert all(isinstance(v, typ) for v in vals), f"{kind}: wrong element type"
    assert all("type" in f for f in _load("frames")), "every frame carries an event type"


def test_pcm_corpus_never_crashes_the_parsers():
    for s in _load("pcm"):
        try:
            assert isinstance(parse_pcm(s), list)
            assert isinstance(normalize_pcm(s, enforce_size=False), str)
        except ValueError:
            pass   # the spec's clean reject-on-overflow — never an unexpected exception


def test_links_corpus_never_crashes_the_analyzer():
    for u in _load("links"):
        m = analyze_link(u, "label")
        assert isinstance(m.rejected, bool) and isinstance(m.display_domain, str)


def test_blobs_corpus_never_crashes_parse_blob():
    for body in _load("blobs"):
        try:
            wire.parse_blob(body)   # descriptor dict / None, or a clean ValueError
        except ValueError:
            pass
