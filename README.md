# postmodern-api

The **Postmodern wire protocol** — the single source of truth for the byte-exact
contract that every part of the system must agree on:

- signed-event bytes (message / vote / reaction / auth — `\x1f`-joined, domain-tagged),
- the voucher and anon-token schemes (sign on the account plane, verify on the chat plane),
- canonical JSON (`canonical_json` — the structured analog of PCM normalization),
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

## Roadmap (not yet here)

- `pcm` — the PCM comment/markdown normalizer (franking-critical; currently in the chat
  repo's `client/pcm.py`).
- `API.md` — the human-readable wire spec.
- the shared **fuzz corpus** + its generator (protocol-conformance data the Python and
  Dart fuzzers both replay).
- the **Dart** mirror package.
