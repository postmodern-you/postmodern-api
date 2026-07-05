#!/usr/bin/env python3
"""Generate golden (known-answer) test vectors for cross-language parity.

Companion to the fuzz corpus: the corpus proves "never crashes on garbage", these
prove "computes the SAME answer". Language-neutral JSON — `tests/test_vectors.py`
replays them against `wire`/`pmcrypto`, and the Dart `PmCrypto` tests replay the SAME
files. So cross-language parity is mechanically checked (no more hand-copied expected
values), and any third implementation gets a conformance suite for free.

Format: one JSON object per line, `{"op": <name>, "in": {...}, "out": <value>}`.
Validation is REPLAY: `assert OPS[op](in) == out`. Bytes are hex; big ints (RSA) are
decimal strings (Dart reads them as BigInt). The `OPS` dispatch below is shared by the
generator (computes `out`) and the test (re-checks it).

Deterministic vectors regenerate byte-identically. The key-material vectors (anon-token
RSA, sealed ciphertexts) can't be reproduced deterministically, so they're generated
ONCE and preserved on rerun — replay validates them regardless of which key was used.

    python gen_vectors.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import nacl.signing

import wire
import pmcrypto

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vectors")


# --- the shared dispatch: op name -> (in dict) -> computed, JSON-able output --------
OPS = {
    # signing bytes (the byte-exact signed domain) -> hex
    "message_signing_bytes": lambda i: wire.message_signing_bytes(
        i["id"], i["room"], i["parent"], i["ts"], i["commit"], i.get("post")).hex(),
    "vote_signing_bytes": lambda i: wire.vote_signing_bytes(i["id"], i["room"], i["vote"], i["ts"]).hex(),
    "reaction_signing_bytes": lambda i: wire.reaction_signing_bytes(
        i["room"], i["target"], i["emoji"], i["op"], i["ts"]).hex(),
    "pollvote_signing_bytes": lambda i: wire.pollvote_signing_bytes(
        i["room"], i["poll_id"], i["choice"], i["ts"]).hex(),
    "auth_signing_bytes": lambda i: wire.auth_signing_bytes(i["name"], i["nonce"]).hex(),
    "encpub_signing_bytes": lambda i: wire.encpub_signing_bytes(i["did"], i["enc_pub"]).hex(),
    # signatures (ed25519 is deterministic) + verify
    "sign_event": lambda i: wire.sign_event(i["seed"], bytes.fromhex(i["payload"])),
    "verify_event": lambda i: wire.verify_event(i["pub"], bytes.fromhex(i["payload"]), i["sig"]),
    # identity: DID <-> pubkey
    "did_key": lambda i: wire.did_key(i["sign_pub"]),
    "did_to_sign_pub": lambda i: wire.did_to_sign_pub(i["did"]),
    # canonical forms
    "canonical_json": lambda i: wire.canonical_json(i["obj"]),
    "blob_descriptor_body": lambda i: wire.blob_descriptor_body(i["descriptor"]),
    # hashes / commitments (franking)
    "hash_bytes": lambda i: wire.hash_bytes(bytes.fromhex(i["data"])),
    "commit_public": lambda i: pmcrypto.commit_public(i["text"]),
    "commit_private": lambda i: pmcrypto.commit_private(bytes.fromhex(i["fk"]), i["plaintext"]),
    "frank_key": lambda i: pmcrypto.frank_key(bytes.fromhex(i["epoch_key"]), i["msg_id"]).hex(),
    "blurhash_valid": lambda i: wire.blurhash_valid(i["s"]),
    # vouchers (account signs, chat verifies)
    "voucher_sign": lambda i: wire.voucher_sign(i["seed"], i["nonce"], i["purpose"]),
    "voucher_verify": lambda i: wire.voucher_verify(i["pub"], i["token"], i["purpose"]),
    # anonymous knock tokens (blind-RSA) — the deterministic FDH + a verify KAT
    "anontoken_fdh": lambda i: str(wire._anontoken_fdh(bytes.fromhex(i["token_id"]), int(i["n"]))),
    "anontoken_verify": lambda i: wire.anontoken_verify(
        bytes.fromhex(i["token_id"]), int(i["sig"]), int(i["n"]), int(i["e"])),
    # sealed / encrypted round-trips (open a KNOWN ciphertext -> plaintext)
    "open_blob": lambda i: pmcrypto.open_blob(bytes.fromhex(i["key"]), bytes.fromhex(i["sealed"])),
    "decrypt_room_text": lambda i: pmcrypto.decrypt_room_text(
        {int(k): bytes.fromhex(v) for k, v in i["epochs"].items()}, i["text"]),
}


def V(_op, **inp):
    """Build a vector: record the input and the output the code computes for it.
    (`_op` is underscored so an `op` field — e.g. reaction add/remove — can be a kwarg.)"""
    return {"op": _op, "in": inp, "out": OPS[_op](inp)}


# --- fixed sample material (deterministic) -----------------------------------------
SEED = "11" * 32
PUB = nacl.signing.SigningKey(bytes.fromhex(SEED)).verify_key.encode().hex()
DID = wire.did_key(PUB)
COMMIT = "de" * 32
FK = "77" * 32
VSEED = "22" * 32
VPUB = wire.voucher_pubkey(VSEED)
VNONCE = "33" * 32
VTOKEN = wire.voucher_sign(VSEED, VNONCE, wire.PURPOSE_CLAIM)
DESCRIPTOR = {"_pm_blob": 1, "blob_id": "0123456789abcdef0123456789abcdef", "mime": "image/png",
              "size": 20480, "w": 800, "h": 600, "caption": "a café ☕ — *bold*",
              "blurhash": "L6PZfSi_.AyE_3t7t7R**0o#DgR4", "hash": "deadbeef", "enc": True, "epoch": 0}


def deterministic():
    good_sig = wire.sign_event(SEED, b"hello world")
    return {
        "signing.jsonl": [
            V("message_signing_bytes", id="m1", room="bigboard", parent=None, ts=1700000000000, commit=COMMIT),
            V("message_signing_bytes", id="m1", room="bigboard", parent="p1", ts=1700000000000, commit=COMMIT, post="image"),
            V("vote_signing_bytes", id="m1", room="bigboard", vote="up", ts=1700000000000),
            V("reaction_signing_bytes", room="bigboard", target="m1", emoji="\U0001f525", op="add", ts=1700000000000),
            V("pollvote_signing_bytes", room="post-x", poll_id="pid1", choice=2, ts=1700000000000),
            V("auth_signing_bytes", name="alice", nonce="cafef00d"),
            V("encpub_signing_bytes", did=DID, enc_pub="ab" * 32),
            V("sign_event", seed=SEED, payload=b"hello world".hex()),
            V("verify_event", pub=PUB, payload=b"hello world".hex(), sig=good_sig),
            V("verify_event", pub=PUB, payload=b"hello world".hex(), sig="00" * 64),
        ],
        "identity.jsonl": [
            V("did_key", sign_pub=PUB),
            V("did_to_sign_pub", did=DID),
            V("canonical_json", obj={"z": [3, 2, 1], "a": "café ☕", "b": True, "n": None}),
            V("blob_descriptor_body", descriptor=DESCRIPTOR),
            V("hash_bytes", data=b"hello world".hex()),
            V("commit_public", text="hello ☕"),
            V("commit_private", fk=FK, plaintext="secret message"),
            V("frank_key", epoch_key="ab" * 32, msg_id="m1"),
            V("blurhash_valid", s="L6PZfSi_.AyE_3t7t7R**0o#DgR4"),
            V("blurhash_valid", s="not a blurhash"),
        ],
        "vouchers.jsonl": [
            V("voucher_sign", seed=VSEED, nonce=VNONCE, purpose=wire.PURPOSE_CLAIM),
            V("voucher_verify", pub=VPUB, token=VTOKEN, purpose=wire.PURPOSE_CLAIM),
            V("voucher_verify", pub=VPUB, token=VTOKEN, purpose=wire.PURPOSE_EMAIL),  # wrong purpose -> null
        ],
    }


def anontoken_once():
    """Fresh RSA key -> a deterministic-once FDH + verify KAT (blind-RSA math)."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub, priv = k.public_key().public_numbers(), k.private_numbers()
    n, e, d = pub.n, pub.e, priv.d
    tid = bytes(range(wire.ANONTOKEN_ID_BYTES))
    fdh = wire._anontoken_fdh(tid, n)
    sig = pow(fdh, d, n)   # a valid (unblinded) signature over the FDH
    return [
        V("anontoken_fdh", token_id=tid.hex(), n=str(n)),
        V("anontoken_verify", token_id=tid.hex(), sig=str(sig), n=str(n), e=str(e)),
    ]


def sealed_once():
    key = pmcrypto.room_key_gen()
    sealed = pmcrypto.seal_blob(key, {"hello": "world", "n": 42})
    ekey = pmcrypto.room_key_gen()
    ct = pmcrypto.encrypt_room_text({1: ekey}, 1, "secret ☕")
    return [
        V("open_blob", key=key.hex(), sealed=sealed.hex()),
        V("decrypt_room_text", epochs={"1": ekey.hex()}, text=ct),
    ]


def _write(fname, vectors):
    with open(os.path.join(OUT, fname), "w", encoding="utf-8") as f:
        f.write("\n".join(json.dumps(v, ensure_ascii=False) for v in vectors) + "\n")


def _write_once(fname, build):
    """Key-material vectors: generate ONCE, preserve on rerun (replay validates them)."""
    path = os.path.join(OUT, fname)
    if os.path.exists(path):
        return
    _write(fname, build())


def main():
    os.makedirs(OUT, exist_ok=True)
    total = 0
    for fname, vecs in deterministic().items():
        _write(fname, vecs)
        total += len(vecs)
    _write_once("anontoken.jsonl", anontoken_once)
    _write_once("sealed.jsonl", sealed_once)
    for f in ("anontoken.jsonl", "sealed.jsonl"):
        total += sum(1 for _ in open(os.path.join(OUT, f)))
    print(f"  wrote {total} vectors across {len(os.listdir(OUT))} files in vectors/")


if __name__ == "__main__":
    main()
