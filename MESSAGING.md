# Design: private messaging (one model for DMs and group rooms)

Status: **the room layer (epochs + sealed skeletons + key distribution) ships
today** — API.md §7a is authoritative for the wire formats. This doc is the
*model*: it states the deliberate privacy-over-maximal-security posture, why a DM
is just a 2-member private room (no separate system), and how contact discovery
introduces two strangers into one. Last updated 2026-06-20.

## 1. The posture: server-blind, not forward-secret

The goal is **privacy from the server**, with the convenience of the current
architecture: the server stores and relays ciphertext it cannot read, and **any
of a user's devices can replay the whole history** from the NATS stream after an
account recovery. We explicitly **do not** adopt Signal's Double Ratchet / X3DH.

Why not (the tradeoff, stated plainly):

- Forward secrecy deletes keys after use, so old ciphertext can never be
  re-decrypted. That directly fights "a new device syncs from seq 0 and reads
  everything," which is a property we want. Recovering it would require a
  per-conversation encrypted-backup subsystem we don't want to build.
- "Any device decrypts all history trivially" and "a stolen key can't read
  history" are the same coin, opposite faces — you cannot have both. We choose
  the convenience face: **blind to the server, escrowed to the account.** This is
  the iMessage-with-iCloud-backup / Telegram-cloud-chat posture, not the Signal
  posture.

**What this buys:** the server never sees plaintext or readable metadata in
private conversations (API.md §7a sealed skeletons); device change is a key
recovery, not a backup restore. **What it costs:** no per-message forward secrecy
or post-compromise security — compromise of a profile's identity key (or the
account blob) exposes that conversation's history. Epoch rotation (§3) gives
*coarse* removal-security (a kicked member lacks the new epoch), not per-message
FS. Accept this in the threat model; do not market it as Signal-equivalent.

## 2. One model: a private conversation = members + epochs

There is **no separate DM mechanism.** A direct message is a **private room with
two members.** N=2 and N≥3 run the identical code path — the same sealed-skeleton
format, the same epoch key, the same key-distribution control messages, the same
storage and replay. Member count is data, not a branch.

The one *primitive* the 2-party case uniquely affords — a non-interactive shared
secret via static-static DH — is **not** used to fork the messaging layer. It
lives only in the discovery introduction (§4), and even there it feeds the
*standard* key-distribution path rather than a DM-specific cipher.

Everything below is API.md §7a; it is restated here only to show it already covers
both cases:

- **Sealing.** Every message/vote in a private room is `enc:1` with a single
  sealed `meta` (author, parent, ts, commit, sig, vote target — all inside);
  bodies are ciphertext. The server sees only `kind`, room, `seq`, and a random
  `id`. XChaCha20-Poly1305, one symmetric key per **epoch**
  (`v1:` = epoch 0, `v2:<epoch>:` = later).
- **Key distribution** rides the normal relay as control messages the server
  can't distinguish from chat: `pk1:` (knock — announce your X25519 identity
  key), `inv1:`/`inv2:` (the epoch key(s) sealed to a recipient's identity key
  via a libsodium sealed box). This is **generate-a-key-and-seal-it-to-each-
  member** — it already works for any N, including 2.
- **Identity keys.** A profile's X25519 `enc_pub` (registered at claim) is where
  keys are sealed; clients TOFU-pin (`pins` in the blob) and refuse a changed key
  until re-pinned (defends against a server key-swap).

## 3. Storage and device change (what's in the blob vs. NATS)

This is the part that matters for "I don't want to back up each conversation":

- **Conversation content stays in NATS**, as sealed ciphertext, exactly as today.
  Nothing about messaging copies conversations into the blob.
- **Only the small epoch *keys* live in the blob**, under
  `room_keys[<room>] = {epochs:{<n>:key}, current:<n>}` (API.md §7a). That's a
  handful of 32-byte keys per conversation, not the messages.
- **Device change** = recover the account blob (account + password) → obtain the
  epoch keys → replay the NATS stream from seq 0 → decrypt. No per-conversation
  backup, no history-sync subsystem. A native client may additionally cache keys
  in platform secure storage.

So the blob is a **keyring**, not a message archive. That keeps the property the
current architecture is liked for, with no new storage layer.

## 4. Discovery → a DM is just creating a 2-member room

Contact discovery (DISCOVERY.md) connects two people who have no in-app contact
yet. Its match yields a shared `channel_id` + `chan_key` that **only the two
parties can derive** (static-static DH, DISCOVERY.md §3). The handoff turns that
into a normal private conversation **without inventing any DM crypto**:

1. **Introduce.** Each party posts a tiny `hello` intro to the rendezvous channel
   (`channel_post`/`channel_fetch`, keyed by `channel_id`), sealed under
   `chan_key`: the profile they choose to DM as (per-room identity) and that
   profile's X25519 `enc_pub`. Both now learn — and TOFU-pin — each other's
   identity key. (`chan_key` is used *only* for this introduction, never for room
   content.)
2. **Create.** The deterministic initiator (lower profile sort, first wins)
   creates a **2-member private room** with a **random** `dm-…` id — deliberately
   *not* `channel_id`, so the authed room creation can't be linked to the
   negotiation-plane channel — then posts a `room` announce (sealed under
   `chan_key`) so the peer learns the id and joins.
3. **Key it via the standard path.** Epoch-0 is generated and shared with `inv1:`
   sealed to the other member's `enc_pub` — the **identical** mechanism a group
   uses to admit a member. Nothing here branches on N=2.
4. **Done.** From here it is a private room in full (§2/§3). It can even **grow
   into a group** by adding members (rotate epoch, `inv1`/`inv2` to each) — same
   code path, no "convert DM to group" special case.

**Decorrelation delay (✅).** `handoff()` waits a randomized cooldown
(`HANDOFF_DELAY`, uniform jitter, persisted in the blob) after first observing a
match before any channel/room activity, so the server can't time-correlate
"mailbox M matched" with "channel C came alive" (DISCOVERY.md §6/§8). Tune the
window to traffic — it mixes a match into others within the window; a lone match
is only time-shifted, not blended.

## 5. Why this is the right amount of crypto

- **No new cipher, no new session protocol, no backup subsystem.** The handoff is
  ~an introduction message + a room create + the existing `inv1` share.
- **One code path for all private conversations** — fewer formats, fewer tests,
  one threat model. DMs inherit every property and bugfix of the room layer for
  free.
- **The static-static DH is reused, not re-implemented** — it's the same
  derivation discovery already uses, confined to the introduction step.

## 6. Build order

1. ✅ Private-room epoch encryption + sealed skeletons + key distribution
   (API.md §7a) — shipped.
2. ✅ Contact discovery core (DISCOVERY.md) — shipped; match returns
   `channel_id`/`chan_key`.
3. ✅ **The handoff (§4):** `ChatClient.handoff()` — intro-over-`chan_key`
   (exchange + TOFU-pin `enc_pub` via the `channel_post`/`channel_fetch` mailbox),
   create the 2-member `dm` room, share epoch-0 via the standard `inv1` path.
   Tested end-to-end (two strangers exchange a decrypted message), with a
   randomized decorrelation delay (`HANDOFF_DELAY`) before acting on a match.
4. ⏳ DM-specific UX (the room kind/labelling, contact list) — client-side,
   no new crypto.
5. (Not planned) forward secrecy / Double Ratchet — out of scope by the §1
   posture; revisit only if the threat model changes.
