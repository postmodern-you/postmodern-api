# Design: graph-private mutual contact discovery

Status: **verifiable core implemented** (crypto derivations §3, mailbox/knock/match
backend §4, full-sync directory §5) with tests (`tests/test_discovery.py`). The
heavy privacy-hardening layers (§6 anonymous credentials, §6 OHTTP relay, §7
room handoff, §5 OPRF/PIR directory) are **deferred and seamed**, not built — every
seam where they drop in is named below and marked in code. Last updated 2026-06-20.

Authoritative wire spec: `API.md` (§4.4 Contact discovery). Crypto:
`client/discovery.py`. Server storage: `server/discovery.py`. This doc is the
*why* — the threat model, the construction, and what is intentionally not built
yet.

## 1. The goal, in one sentence

Two people who have each independently saved the other's phone number connect
automatically — no QR exchange, no "accept friend request" — **and the server
never learns the social graph**, even if it is fully malicious and already holds
every phone number and every published public key.

This is the contact-discovery analogue of the two-plane design:
the server is *useful* (it routes the rendezvous) without being *trusted* (it
can't enumerate who-knows-whom).

## 2. Threat model

**Adversary:** a fully malicious server (or anyone who has compromised it). It
holds the entire directory (`number_hash → registration pubkey`) — we assume it
knows every phone number on earth and can hash them itself, so the number hash is
**not** a secret. It sees every byte of every knock and poll. It can inject,
drop, and reorder. It can register its own numbers (Sybil).

**What must stay hidden:** the *edges* of the social graph — which two parties
have discovered each other. Equivalently: the server must not be able to link a
rendezvous to the accounts on either side of it.

**Explicitly in scope (the server is allowed to know):**
- the directory itself (`number_hash → pubkey`) — by assumption;
- that *some* account published *some* key (publishing is authenticated);
- that *some* anonymous party knocked *some* mailbox.

**Out of scope / non-goals here:** hiding that a person uses the service at all
(membership), traffic-analysis at the network layer beyond what OHTTP addresses
(§6), and post-connection messaging privacy (that's the existing room/DM crypto,
the existing room/DM crypto — API.md §7a — reached via the handoff in §7).

## 3. The core construction (implemented)

The phone number is **only an index**. The rendezvous secret is a non-interactive
**static-static X25519 Diffie–Hellman** between the two parties' long-term
registration keys:

```
s_AB = DH(priv_A, pub_B) = DH(priv_B, pub_A)
```

Both parties compute the same `s_AB` offline (the other need not be online), and a
malicious server holding `pub_A` and `pub_B` **cannot** compute it (computational
Diffie–Hellman). Every rendezvous value is derived from `s_AB` by domain-separated
HKDF-SHA256 over a canonical context binding **both** public keys
(`ctx = sort(pub_A, pub_B)` — order-independent, prevents unknown-key-share):

| value | `info` tag | role |
|---|---|---|
| `mailbox_id` | `postmod/rendezvous/mailbox/v1` | where both parties knock |
| `channel_id` | `postmod/transport/channel/v1` | post-match transport address |
| `chan_key`   | `postmod/transport/chankey/v1` | post-match symmetric key seed |

`mailbox_id`, `channel_id`, and `chan_key` are **independent** (distinct tags), so
observing post-match channel traffic never links back to the rendezvous mailbox.

**Nullifier.** A knock carries a `nullifier = H(tag ‖ identity_secret ‖
mailbox_id)` from the knocker's *stable per-account* secret. The same human
knocking the same mailbox twice yields the **same** nullifier (so it counts once);
the two *different* parties of a mailbox yield **two distinct** nullifiers. A
mailbox with **≥2 distinct nullifiers = a mutual match**. The server learns a
count, never an identity.

**Why a third party can't interfere:** to knock mailbox `AB` you must derive
`mailbox_id`, which requires `s_AB`, which requires `priv_A` or `priv_B`. An
outsider holding only public keys cannot knock — so knocks can't be used to probe
or target a victim (free anti-DoS at the mailbox layer).

**`number_hash`** is a domain-separated SHA-256 of the normalized number — the
directory index, not a secret (see threat model).

## 4. Backend: directory + knocks (implemented)

`server/discovery.py` holds two tables, both in-scope:
- `discovery_directory(number_hash PK, disc_pub, ts)` — the directory.
- `discovery_knocks(mailbox_id, nullifier, ts, PK(mailbox_id, nullifier))` — opaque
  knocks; a match is `COUNT(DISTINCT nullifier) ≥ 2` for a mailbox.

Wire ops (`API.md` §4.4): `directory_publish` (**authed** — see §5),
`directory_snapshot`, `knock`, `knock_poll` (the last three **session-less**, see
§6). Pending knocks expire (`expire_knocks`) so a one-sided save doesn't linger
forever; re-knock on the next contact re-sync.

## 5. Directory privacy: publish vs. lookup (asymmetric by design)

**Publish is authenticated.** You prove you control the number (the existing
humanness ladder, assumed upstream) and the server stores `number_hash → your
pubkey`. The server knowing the directory is *in scope* — it's the index everyone
queries. What stays hidden is the **graph**, not the directory.

**Lookup must leak nothing.** If clients asked "is `number_hash X` registered?",
the server would learn each client's contact list. So instead the client
**full-syncs the whole directory** (`directory_snapshot`) and resolves its saved
contacts **locally** — the server never sees which numbers a client cares about.

> **Deferred (§5-OPRF/PIR):** full-sync is correct and leak-free but O(directory)
> per client; it's the right choice *while the directory is small*. At scale,
> replace it with an **OPRF-blinded lookup** or **private information retrieval**
> so per-contact lookup leaks nothing without shipping the whole table. The
> client seam is `ChatClient.sync_directory()`; the server seam is
> `DiscoveryStore.snapshot()`. **This cap is not silent — it's here in writing.**

## 6. Account-unlinkability of knocks (partially implemented)

A knock must not be linkable to the account that makes it, or the server could
reconstruct the graph from "account A knocked mailbox M". Two mechanisms:

**(a) Session-less transport — implemented, behind a swappable seam.** `knock`,
`knock_poll`, and `directory_snapshot` are in `NO_SESSION_OPS`: they require **no
profile/account auth**. The client routes them through a pluggable transport
(`client/negotiation.py::NegotiationTransport`), injected at `ChatClient(...,
negotiation=…)` and reached via `ChatClient._negotiation_rpc`. The default
`DirectWSTransport` sends each op over a **fresh, unauthenticated WebSocket**,
separate from the authed connection, so the server sees no account on the knock.
The contract is deliberately **one message in → one reply** (stateless), so the
ops map onto OHTTP unchanged — keep negotiation ops one-shot to preserve this.

> **Deferred (§6-OHTTP):** a session-less WS still exposes the client's source IP
> and timing, which a server could correlate with the authed connection. Production
> swaps in `OHTTPTransport` (stubbed in `client/negotiation.py`): each request is
> HPKE-sealed and POSTed to a **relay**, which forwards to a **gateway** beside the
> discovery origin — the relay sees the IP but not the request, the gateway the
> request but not the IP. Same request/reply dicts, different envelope; **no
> caller and no server-handler change**. This is a *network-metadata* property, so
> it's untestable on localhost — we run `DirectWSTransport` in dev and validate the
> OHTTP envelope at a pre-deploy integration milestone (relay+gateway compose).
> **CRITICAL:** the relay and gateway must be operated by **non-colluding**
> parties or the property collapses to a plain proxy — that procurement is an ops
> task, also deferred.

**(b) Anti-Sybil credential — stubbed.** Without a humanness check on knocks, the
server (which can register numbers) could flood mailboxes. Each knock carries a
`credential` field meant to be an **anonymous credential** (BBS+ / blind
signature) proving "a valid human" *without revealing which account*, deduplicated
by the nullifier.

> **IMPLEMENTED (§6-creds):** the knock `credential` is now a
> real **blind-RSA anonymous token** (`anoncred.verify_knock` + `wire.anontoken_*`).
> The account plane blind-signs tokens for an authenticated account (budgeted — the
> anti-Sybil cap), never seeing the token id, so it can't link issuance to a knock.
> The discovery plane verifies each knock token with the issuer **public** key — it
> **cannot mint** (so a curious/compromised discovery plane can't flood) — and spends
> the token's nullifier once (`discovery.spend_knock_nullifier`). Unlinkable to the
> account and across knocks. **Security caveats:** needs a crypto review; defends
> against a curious/compromised discovery plane + external Sybils, NOT a fully-
> malicious operator (who holds the issuer private key). Mailbox unguessability (§3)
> still independently blocks *targeted* abuse; this closes untargeted spam —
> open. **Not silently capped — documented here and at the seam.**

## 7. After a match: the handoff into a 2-member private room (implemented)

A match yields a shared `channel_id` + `chan_key` (§3) that both parties — and
only they — can derive. The handoff turns that into a normal private
conversation **with no DM-specific crypto** (full design: MESSAGING.md): a DM is
just a **2-member private room** on the existing epoch scheme (API.md §7a). We
deliberately do **not** use X3DH / Double Ratchet — the posture is server-blind
with replayable history, not forward secrecy (MESSAGING.md §1).

The flow (`ChatClient.handoff()`, poll-style + idempotent): (1) each side posts a
tiny `hello` intro to the **rendezvous channel** (`channel_post`/`channel_fetch`,
session-less) sealed under `chan_key` — the profile it DMs as + that profile's
X25519 `enc_pub` — so both learn and TOFU-pin each other's identity key; (2) the
deterministic initiator (lower profile name) creates an ordinary `dm` room with a
**random** id (kept off `channel_id` so the authed room can't be linked to the
negotiation-plane channel), invites the peer, and shares epoch-0 via the
**standard** `inv1` sealed-box path a group uses to admit a member; (3) the
initiator posts a `room` announce (sealed under `chan_key`) so the peer learns the
room id and joins. `chan_key` is used only for the introduction, never for room
content.

> **Implemented:** server channel mailbox (`discovery_channel` + `channel_post`/
> `channel_fetch`, session-less); client `ChatClient.handoff()`; the DM is a real
> 2-member E2EE room (tested: two strangers who only exchanged numbers exchange a
> decrypted message). The **decorrelation delay** is built too: on first observing
> a match, `handoff()` schedules a randomized cooldown (`HANDOFF_DELAY`, uniform
> jitter — a constant would just be subtracted off) and does nothing until it
> elapses, so the channel/room activity is timing-separated from the match. The
> wakeup is persisted in the blob, so it survives a restart.

## 8. Residual risks (with the deferred layers in mind)

- **Directory enumeration** — by assumption the server already has every number;
  publishing adds the pubkey. Accepted (it's the index, not a secret).
- **Knock metadata before OHTTP (§6a)** — source IP + timing on the session-less
  WS are correlatable until the OHTTP layer lands. Known gap, seamed.
- **Untargeted knock spam before credentials (§6b)** — the stub accepts all
  knocks; targeted abuse is already blocked by mailbox unguessability. Known gap.
- **Match-to-channel timing (§7)** — addressed: a randomized decorrelation delay
  (`HANDOFF_DELAY`) separates the match from the channel/room activity. Residual:
  the delay only helps if matches are batched/frequent enough that the cooldown
  window actually mixes them; for a lone match it shifts timing but can't blend
  into a crowd. Tune the window to traffic.
- **Full-sync cost (§5)** — O(directory) per client until OPRF/PIR. Fine while
  small; documented, not silent.

## 9. Build order (this is what shipped, and what's next)

1. ✅ Crypto derivations — `client/discovery.py` (`rendezvous`, `nullifier`,
   `number_hash`), tested for symmetry / independence / third-party-blindness /
   nullifier semantics.
2. ✅ Backend mailbox/knock/match + directory — `server/discovery.py`, wired into
   `server/server.py` (`directory_publish`/`directory_snapshot`/`knock`/`knock_poll`).
3. ✅ Session-less negotiation transport (§6a) + reference client methods
   (`register_discovery`/`sync_directory`/`discover`/`poll_discovery`).
4. ✅ End-to-end tests — one-sided→no-match, mutual→match with agreed channel
   secret, unregistered→none, no false self-match.
5. ✅ Anonymous credential verifier (§6b) — DONE: the knock `credential` is a real
   blind-RSA anonymous token (`anoncred.verify_knock` + `wire.anontoken_*`,
   the humanness-token scheme). Account blind-signs (budgeted, never sees the id); discovery
   verifies with the public key (can't mint) + nullifier dedup. Needs a crypto
   review; the Dart client must mirror `wire.anontoken_*` byte-for-byte.
6. ⏳ OHTTP relay+gateway (§6a) — implement `OHTTPTransport` (seam already in
   `client/negotiation.py`, default `DirectWSTransport`); procure non-colluding relay.
7. ✅ Room handoff (§7) — `ChatClient.handoff()`: intro over `chan_key`, create the
   2-member private room, share epoch-0 via the standard `inv1` path (MESSAGING.md
   §4), with a randomized decorrelation delay (`HANDOFF_DELAY`) before acting.
8. ⏳ OPRF/PIR directory (§5) — replace full-sync when the directory outgrows it.
