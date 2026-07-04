# postmodern-api

The **Postmodern wire protocol** — the single source of truth for how the pieces
communicate. It owns the *interface*; the server + client repos own the
*implementation*. Two halves:

- **The specs** (human-readable, normative):
  - [`API.md`](API.md) — the full client-facing wire spec (transport, crypto, every op).
  - [`DISCOVERY.md`](DISCOVERY.md) — graph-private mutual contact discovery.
  - [`MESSAGING.md`](MESSAGING.md) — message/room/DM crypto + the post-match handoff.
- **The code** — the byte-exact primitives every part of the system must agree on:

- signed-event bytes (message / vote / reaction / auth — `\x1f`-joined, domain-tagged),
- the voucher and anon-token schemes (sign on the account plane, verify on the chat plane),
- PCM comment/markdown normalization (`pcm.normalize_pcm` — franking-critical, Dart-mirrored) + `canonical_json`, its structured analog,
- blob/media descriptor bodies (`PMBLOB1:`), blurhash validation, DID/base58 helpers,
- the protocol-version handshake (`PROTOCOL_VERSION` / `MIN_PROTOCOL` / `protocol_compatible`).

Why it exists: this code is implemented more than once (Python here, mirrored in Dart
in the client) and **must stay byte-identical** — a mismatch isn't cosmetic, it's a
franking or voucher-verification *failure*. Keeping the Python source in one place
kills the silent drift that comes from hand-copying `wire.py` between the two server
planes. (This repo was carved out after the account plane's copy was found carrying
stale, diverged `*_signing_bytes` functions.)

Open on purpose: the protocol is already public — the open-source client reveals all of
it — so publishing the contract costs no secrecy and invites interoperable clients.

## Consumers

| Repo | Uses |
|---|---|
| `postmodern-server` (chat) | the full module |
| `postmodern-accounts` (account) | voucher/anon-token signing, protocol version, email validation |
| the Flutter client | a hand-maintained **Dart mirror** (kept in parity via the shared fuzz corpus) |

## Install / depend

```bash
pip install -e .                                   # local dev (editable)
# or pin a tagged release TARBALL in a consumer's requirements.txt:
#   postmodern-api @ https://github.com/postmodern-you/postmodern-api/archive/refs/tags/v0.1.0.tar.gz
```

Installs a top-level `wire` module, so consumers keep `import wire` unchanged.

**Pin a tag, never a branch**, in anything reproducible (container builds, CI) — the
whole point is a versioned contract. Prefer the **tarball** URL over `git+https://…`:
pip needs a `git` binary for the latter, which slim base images (and thus lean
containers) don't ship.

## Versioning

Bump `PROTOCOL_VERSION` (wire-visible protocol changes) and the package `version`
together; tag the repo; bump the pin in each consumer. That ceremony is the feature —
it makes protocol drift explicit instead of silent.

The specs were self-contained on the way out: they reference each other, but the chat
repo's *internal* design docs (DESIGN/IDENTITY/POSTS — architecture + threat-model
rationale, which stay closed) are cited only as prose, not links, so this spec stands
alone for anyone implementing a client.

## Roadmap (not yet here)

- the **Dart** mirror package (the protocol's second implementation; today it lives in
  the Flutter client and is kept in parity via the shared fuzz corpus).
