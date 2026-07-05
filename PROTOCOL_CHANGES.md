# Changing the protocol

This is the workflow for making a change to the contract. `postmodern-api` is the
single source of truth, and a change here ripples to **three implementations that must
agree byte-for-byte**: the Python `wire`/`pcm` in this repo (used by the chat + account
servers) and the **Dart mirror** in the Flutter client. Follow this so a change lands
in lockstep instead of drifting.

## What counts as a protocol change

Anything that alters what crosses the wire, or the meaning of an op:

- a **canonical form** — signing bytes (message/vote/reaction/auth/encpub/VC/VP),
  `canonical_json`, `normalize_pcm`, blob descriptor bodies, voucher / anon-token
  formats, blurhash validation;
- a **new or changed** op, field, or error `code`;
- the **specs** — `API.md` / `DISCOVERY.md` / `MESSAGING.md`.

**Not** a protocol change (stays in the server/client repos): server-internal logic,
storage, moderation, UI — anything that doesn't change the bytes or the contract.

## The cardinal rule: byte-identical

A change to any **canonical form** MUST land identically in Python (`wire.py`/`pcm.py`)
and Dart. A one-byte difference is not a cosmetic bug — it's a **franking or
signature-verification failure**. Never touch a canonical form without regenerating the
fuzz corpus and updating the golden vectors on **both** sides.

## Do it in one pass — don't relay

This is the one workflow where the two-agent split (server side / client side) hurts: a
canonical-form change handed off via a `PYTHON_TODO → Flutter` relay drifts. **Own
`postmodern-api` and drive both mirrors in a single pass.** At minimum, land + tag the
contract first and treat the Dart mirror as a same-session follow-up, not a queued TODO.

## Steps

### 1. Change the contract (here)
- Edit `wire.py` / `pcm.py`.
- Update the spec: `API.md` (+ `DISCOVERY.md` / `MESSAGING.md` if relevant).
- If the change adds new wire shapes, extend `gen_fuzz_corpus.py` (`KNOWN_*` seeds),
  regenerate `fuzz_corpus/`, and add/curate golden vectors.
- Local Python consumers pick it up immediately via the editable install
  (`pip install -e ../postmodern-api`) — test against them before tagging.

### 2. Decide the version bump

| change | `PROTOCOL_VERSION` | package `version` | `MIN_PROTOCOL` |
|---|---|---|---|
| additive (new op/field, back-compat) | +1 | minor | unchanged |
| canonical-form / breaking wire change | +1 | minor or major | consider raising |
| non-wire code fix (bytes unchanged) | unchanged | patch | unchanged |
| drop support for an old peer | +1 | — | raise to the new floor |

Additive is the safe default: old peers ignore unknown fields/ops, and the `hello`
handshake (`PROTOCOL_VERSION` / `MIN_PROTOCOL` / `protocol_compatible`) gates true
incompatibility so nothing fails cryptically. Bump `PROTOCOL_VERSION` and the package
`version` together.

### 3. Verify, tag, and push the contract — FIRST
- `pip install -e ".[dev]" && pytest -q tests/` (the corpus replay) + any golden tests.
- Commit (identity: `cschlick` noreply, **no `Co-Authored-By` trailer** — repo rule).
- **Tag the new version and push it before touching any consumer.** A consumer that
  pins a tag which doesn't exist yet fails its build — always contract-first.

### 4. Bump the Python consumers
- In `postmodern-server` and `postmodern-accounts` `requirements.txt`, bump the pin to
  the new tag. Keep both on the **same** version (lockstep — they share the
  voucher/anon-token wire and must verify each other).
- Use the **tarball** URL, never `git+https://` — the slim container base image has no
  `git`, so a git dependency breaks the image build.
- Run each repo's tests; push. Their container CI fetches the new tarball.

### 5. Mirror into the Dart client
- Port the same change to the Dart `wire`/`pcm` mirror; mirror the
  `PROTOCOL_VERSION` / `MIN_PROTOCOL` constants.
- Update the Dart golden vectors; the Dart fuzz suite replays this repo's
  `fuzz_corpus/*.jsonl`, so re-point its reader if the location or shapes changed.
- Run the Dart parity + fuzz tests.

### 6. If a separate agent owns the client
Prefer step 5 in the same pass for canonical-form changes. If you must hand off, file a
`FLUTTER_TODO` entry (in `postmodern-server`) with: the new tag, **exactly** which
canonical form changed, the golden vectors to match, and whether `MIN_PROTOCOL` moved.

## Cross-plane pairing (vouchers / anon-tokens)

`voucher_*` and `anontoken_*` span the **account plane** (signs, holds the private key)
and the **chat plane** (verifies, holds the public key). A change must keep the
sign/verify pair consistent — bump both planes together and check the golden vectors
both repos pin. (Ideally the wire golden vectors live here in the contract repo so
there's one copy; if they're still duplicated in the consumers, keep them in sync.)

## Drift detectors — your safety net

- **Fuzz corpus** — both sides replay `fuzz_corpus/*.jsonl`; a canonical-form divergence
  surfaces as a crash or a parse mismatch.
- **Golden vectors** — pinned exact bytes for the signing / descriptor / voucher forms,
  identical across implementations.
- **`hello` handshake** — the runtime compat gate; a version mismatch shows an
  "update required" state instead of failing silently mid-session.

Keep all three current with every change — they are far cheaper than debugging a
franking mismatch in production.

## Rollback / coexistence

Old deployed servers and already-installed apps coexist by design. Because additive
changes are versioned and back-compatible, backing one out is graceful: un-bump the
consumer pin, or ship a client that speaks the older `PROTOCOL_VERSION`. **Breaking**
canonical-form changes are the ones never to ship without a `MIN_PROTOCOL` plan and all
three implementations moving together.
