"""Replay the golden vectors against wire/pmcrypto — the cross-language parity anchors.

Every vector in vectors/*.jsonl is a known-answer case {op, in, out}: this asserts the
Python code computes exactly `out`. The Dart PmCrypto tests replay the SAME files, so a
byte-level divergence between the two implementations fails here or there. The `OPS`
dispatch is shared with gen_vectors.py, so expected values are never hand-copied.
"""
import json
import os

import pytest

from gen_vectors import OPS

VDIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "vectors")


def _all():
    out = []
    for fn in sorted(os.listdir(VDIR)) if os.path.isdir(VDIR) else []:
        if fn.endswith(".jsonl"):
            for i, line in enumerate(open(os.path.join(VDIR, fn), encoding="utf-8")):
                if line.strip():
                    out.append((fn, i, json.loads(line)))
    return out


VECTORS = _all()


def test_vectors_present():
    assert len(VECTORS) >= 20, "golden vectors missing — run `python gen_vectors.py`"


@pytest.mark.parametrize("fn,i,v", VECTORS, ids=[f"{fn}:{i}:{v['op']}" for fn, i, v in VECTORS])
def test_vector(fn, i, v):
    assert v["op"] in OPS, f"unknown op {v['op']}"
    got = OPS[v["op"]](v["in"])
    assert got == v["out"], f"{v['op']} ({fn} line {i}): got {got!r}, expected {v['out']!r}"
