"""Client-side cryptography: key derivation, blob sealing, profile keys.

The server never sees the password or encKey (DESIGN.md §2):

    master  = argon2id(password, account_salt)
    authKey = KDF(master, "auth")   # proves identity; server stores a hash
    encKey  = KDF(master, "enc")    # seals the account blob; never sent

Profile keypairs (ed25519 signing + X25519 encryption) are generated here
and stored, as seeds, inside the sealed blob — so account-id + password is
sufficient to recover every profile on a new device.
"""

# --- byte-critical primitives: re-exported from `wire`, the single source of truth
# (these were an independent DUPLICATE copy here before the contract was extracted).
from wire import (  # noqa: F401
    _join,
    anon_claim_signing_bytes,
    commit_private,
    encpub_signing_bytes,
    hash_bytes,
    message_signing_bytes,
    open_commitment,
    pollvote_signing_bytes,
    reaction_signing_bytes,
    sign_event,
    solve_pow,
    vc_signing_bytes,
    vc_verify,
    verify_event,
    vote_signing_bytes,
    vp_sign,
    vp_signing_bytes,
    vp_verify,
)


import json

import nacl.hash
import nacl.public
import nacl.pwhash
import nacl.secret
import nacl.signing
import nacl.utils
from nacl.encoding import RawEncoder

SALT_BYTES = nacl.pwhash.argon2id.SALTBYTES  # 16


def new_salt() -> bytes:
    return nacl.utils.random(SALT_BYTES)


def derive_keys(password: str, salt: bytes) -> tuple[bytes, bytes]:
    """password + salt -> (authKey, encKey), independent via domain separation."""
    master = nacl.pwhash.argon2id.kdf(
        32,
        password.encode(),
        salt,
        opslimit=nacl.pwhash.argon2id.OPSLIMIT_INTERACTIVE,
        memlimit=nacl.pwhash.argon2id.MEMLIMIT_INTERACTIVE,
    )
    authkey = nacl.hash.blake2b(b"auth", key=master, digest_size=32, encoder=RawEncoder)
    enckey = nacl.hash.blake2b(b"enc", key=master, digest_size=32, encoder=RawEncoder)
    return authkey, enckey


def seal_blob(enckey: bytes, data: dict) -> bytes:
    return nacl.secret.SecretBox(enckey).encrypt(json.dumps(data).encode())


def open_blob(enckey: bytes, sealed: bytes) -> dict:
    return json.loads(nacl.secret.SecretBox(enckey).decrypt(sealed))


def new_profile_keys() -> dict:
    """Fresh signing + encryption keypairs. Seeds belong in the account blob;
    pubs go to the server's profile registry."""
    sign = nacl.signing.SigningKey.generate()
    enc = nacl.public.PrivateKey.generate()
    return {
        "sign_seed": sign.encode(RawEncoder).hex(),
        "sign_pub": sign.verify_key.encode(RawEncoder).hex(),
        "enc_seed": enc.encode(RawEncoder).hex(),
        "enc_pub": enc.public_key.encode(RawEncoder).hex(),
    }


def sign(sign_seed_hex: str, nonce: str) -> str:
    """Sign a server challenge nonce; returns the detached signature as hex."""
    key = nacl.signing.SigningKey(bytes.fromhex(sign_seed_hex))
    return key.sign(nonce.encode()).signature.hex()


# ---------------- room encryption (zero-trust message bodies) ----------------
#
# Compatible with the Flutter client's CryptoService: XChaCha20-Poly1305
# with one symmetric key per room *epoch*. Wire formats:
#   v1:base64(nonce || ciphertext)            epoch 0 (Flutter-compatible)
#   v2:<epoch>:base64(nonce || ciphertext)    later epochs (rotation)
# Keys are shared by sealing to a profile's X25519 identity key:
#   pk1:<pubkey_b64>                a knock announcing the sender's identity
#   inv1:<recipient>:<sealed_b64>   sealed raw epoch-0 key (Flutter-compatible)
#   inv2:<recipient>:<sealed_b64>   sealed JSON {"room", "epochs", "current"}

import base64

import nacl.bindings

ROOM_KEY_BYTES = 32
_NONCE = 24


def room_key_gen() -> bytes:
    return nacl.utils.random(ROOM_KEY_BYTES)


def derive_room_key(master: bytes, room: str) -> bytes:
    """Deterministic per-room key for a stateless bot: keyed BLAKE2b of the room
    name under the bot's master secret. Same (master, room) → the same 32-byte
    key, so a server-run bot re-derives a DM's key on demand instead of storing
    one per contact — O(1) state for unbounded contacts. The bot seals this key
    to the peer at accept exactly like a random one, so the peer is unaffected."""
    return nacl.hash.blake2b(
        room.encode(), key=master, digest_size=ROOM_KEY_BYTES, encoder=RawEncoder)


def encrypt_room_text(epochs: dict, current: int, text: str) -> str:
    """Encrypt under the current epoch key. Epoch 0 emits the v1 format for
    Flutter-client compatibility."""
    nonce = nacl.utils.random(_NONCE)
    cipher = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        text.encode(), None, nonce, epochs[current]
    )
    blob = base64.b64encode(nonce + cipher).decode()
    return f"v1:{blob}" if current == 0 else f"v2:{current}:{blob}"


def decrypt_room_text(epochs: dict, text: str) -> str | None:
    """Plaintext; the input unchanged when unencrypted; None when the
    needed epoch key is missing or the ciphertext doesn't authenticate."""
    if text.startswith("v1:"):
        epoch, blob = 0, text[3:]
    elif text.startswith("v2:"):
        try:
            _, epoch_s, blob = text.split(":", 2)
            epoch = int(epoch_s)
        except ValueError:
            return None
    else:
        return text
    key = epochs.get(epoch)
    if key is None:
        return None
    try:
        data = base64.b64decode(blob)
        return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
            bytes(data[_NONCE:]), None, bytes(data[:_NONCE]), key
        ).decode()
    except Exception:
        return None


def seal_b64(recipient_pub: bytes, data: bytes) -> str:
    box = nacl.public.SealedBox(nacl.public.PublicKey(recipient_pub))
    return base64.b64encode(box.encrypt(data)).decode()


def seal_open_b64(identity: "nacl.public.PrivateKey", sealed_b64: str) -> bytes | None:
    try:
        return nacl.public.SealedBox(identity).decrypt(base64.b64decode(sealed_b64))
    except Exception:
        return None


def identity_from_seed(enc_seed_hex: str, enc_pub_hex: str) -> nacl.public.PrivateKey:
    """The profile's X25519 identity. PyNaCl treats the stored seed as the
    secret key itself; libsodium's seed_keypair (used by the Flutter client)
    hashes it first — try both and return whichever matches the registered
    public key."""
    seed = bytes.fromhex(enc_seed_hex)
    direct = nacl.public.PrivateKey(seed)
    if direct.public_key.encode().hex() == enc_pub_hex:
        return direct
    _, sk_raw = nacl.bindings.crypto_box_seed_keypair(seed)
    return nacl.public.PrivateKey(sk_raw)


# ---------------- signed events + franking-ready commitments ----------------
#
# Each event is signed by the sender's ed25519 profile key, so a member (or
# a malicious server) cannot forge another profile's name. The signature
# covers a content *commitment*, binding the separately-fetched body to the
# signed skeleton.
#
# The commitment is franking-ready (DESIGN.md §3 / the API spec §7b): for encrypted
# messages it is PRF(fk, plaintext) with a per-message franking key fk
# derived from the room epoch key and message id. A future abuse report can
# reveal (plaintext, fk) for one message — proving what was sent — without
# exposing the room key or any other message. v1 computes and verifies the
# commitment; server-side report signing is left for later.

import hmac as _hmac

_US = "\x1f"




# v2 (IDENTITY.md 1c): authorship-by-signature — the author is NOT signed; the
# signing key IS the author (its did:key is on the frame and self-verifies). These
# cover CONTENT only and must stay byte-identical to wire.py (the parity test).










# ---- Verifiable Credentials + Presentations (IDENTITY.md Phase 2/3) ----
# Mirrors wire.py byte-for-byte. The client signs its own VPs (selective
# disclosure) and verifies peers' VPs/VCs locally (the issuer key comes from the
# `issuers` op). did_to_sign_pub lives in the shared wire module.
import time as _time
import wire as _wire

_RS = "\x1e"
VP_VERSION = "pm-vp-v1"












# Anonymous-session proof of work + claim binding (must stay byte-identical to
# wire.py). solve_pow is the client-side cost of minting a throwaway anon profile.
# SHA-256: the Dart client needs a separate hash dependency regardless (its
# libsodium binding doesn't expose crypto_generichash), and SHA-256 is in Dart's
# canonical `crypto` package.
def _anon_pow_digest(challenge: str, sign_pub: str, nonce: str) -> bytes:
    import hashlib
    return hashlib.sha256(_join("pm-anon-pow-v1", challenge, sign_pub, nonce)).digest()


def _leading_zero_bits(digest: bytes) -> int:
    n = 0
    for byte in digest:
        if byte == 0:
            n += 8
            continue
        b = byte
        while b < 0x80:
            n += 1
            b <<= 1
        break
    return n










def frank_key(epoch_key: bytes, msg_id: str) -> bytes:
    """Per-message franking key, derived so recipients (who hold the epoch
    key) can compute it but the server cannot."""
    return nacl.hash.blake2b(
        b"frank:" + msg_id.encode(), key=epoch_key, digest_size=32, encoder=RawEncoder
    )




def commit_public(text: str) -> str:
    """Integrity commitment for unencrypted text (no secrecy needed)."""
    return nacl.hash.blake2b(b"public:" + text.encode(), digest_size=32).hex()




# --- binary blob content (images/video/long articles): POSTS.md stage 2b ---



def encrypt_room_bytes(epochs: dict, current: int, data: bytes) -> bytes:
    """Encrypt raw bytes under the current epoch key (private rooms), so the
    object store only ever sees ciphertext. Wire form: nonce ‖ ciphertext."""
    nonce = nacl.utils.random(_NONCE)
    cipher = nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        data, None, nonce, epochs[current]
    )
    return nonce + cipher


def decrypt_room_bytes(key: bytes, blob: bytes) -> bytes:
    """Inverse of encrypt_room_bytes; raises if the ciphertext doesn't
    authenticate (AEAD), which itself catches a tampered blob."""
    return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
        bytes(blob[_NONCE:]), None, bytes(blob[:_NONCE]), key
    )


def seal_meta(epochs: dict, current: int, meta: dict) -> str:
    """Encrypt an event's skeleton metadata (author, parent, ts, commit/sig,
    or a vote's target/voter/vote) so the server relays it opaquely. Only the
    message id stays in the clear, as a body-addressing handle."""
    return encrypt_room_text(epochs, current, json.dumps(meta, sort_keys=True))


def open_meta(epochs: dict, meta_ct: str) -> dict | None:
    plain = decrypt_room_text(epochs, meta_ct)
    if plain is None:
        return None
    try:
        return json.loads(plain)
    except (ValueError, TypeError):
        return None
