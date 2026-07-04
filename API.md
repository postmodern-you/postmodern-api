# Client API definition

Everything a client needs to implement against the server. Covers the
shipped protocol through phase 3 (crypto identity,
skeleton/body fold, private rooms with roles, E2EE with sealed skeletons,
signed events). This file is authoritative for the wire protocol; the
README has only a summary.

> **Recent additions** (all backward compatible — extra fields/ops only;
> client catch-up guide in `FLUTTER_SYNC.md`):
> - `rooms` entries now carry `kind` and a JSON-bool `private` (§4.2).
> - **Profile pages & avatars** (§4.1): `profile_info` returns the full public
>   record (`display_name`, `created_ts`, `human_backed`, `bot`, `avatar_hash`,
>   `avatar_url`, `avatar_small_url`, `default_variant`); new ops `get_avatar`
>   (small/large) and `profile_update` (owner-only edits). Every profile gets a
>   default robot avatar at claim. Caps in §6.
> - **Avatar storage** (§4.1): **custom** avatars (small + large) live in the
>   PRIVATE object store and are served as short-lived **presigned** URLs
>   (`get_avatar`/the card return `avatar_url`/`avatar_small_url`); **default** robots are generated on demand
>   and served as bytes (never stored). `get_avatar` carries both `avatar` and
>   `avatar_url` — resolve the URL first, else the bytes. With no object store,
>   custom avatars fall back to inline bytes.

## 1. Transport and connection model

- WebSocket, default `ws://host:8765`. Every frame is one JSON object (text).
- **On-wire TLS:** when the server is configured with a cert (`CHAT_TLS_CERT`/
  `CHAT_TLS_KEY`; `ACCOUNT_TLS_*` for the account plane) it serves `wss://` and
  the public profile endpoint becomes `https://` — a forward-secure TLS 1.3
  session terminated at the **origin** (the fleet LB is an L4 byte-relay, so it
  passes the encrypted stream through; terminate as close to the origin as the
  trust boundary allows). Unset → `ws://` (local dev). The client picks the
  scheme from the URL; for real certs nothing else is needed (system trust
  verifies), for a self-signed/local cert pass a CA via `ChatClient(ssl=…)`. This
  is independent of the at-rest E2E layer (§7a): TLS protects bytes in transit,
  E2E keeps the server blind to stored content.
- Server replies and pushes are JSON objects with a `type` field. Errors are
  always `{"type": "error", "message": "<human-readable reason>"}`, plus an optional
  **`code`** — a stable machine-readable tag for clients to branch retry/gate logic
  on (so a `message` wording change can't break them). `message` is for humans; match
  on `code` when present, fall back to text otherwise. Common codes (both planes):
  `auth_required`, `rate_limited`, `blob_conflict` (stale-version blob CAS),
  `anon_forbidden` (op not available to an anonymous session), `account_banned`;
  account-plane also `device_in_use`, `irl_not_verified`, `irl_spent`, `not_paying`,
  `anon_budget`. Untagged errors omit `code` entirely. (The per-room posting gate is
  a distinct reply `type` — `login_required` — not an error.)
- **Two planes, two connections.** A connection is permanently locked to the
  plane of the first operation it attempts (`account_*`/`blob_*`/`voucher_*`
  → account plane; everything else → profile plane). Speaking to the wrong
  plane returns an error and changes nothing. Clients must open one
  connection per plane.
- The **account connection** is strictly request/response: every request
  produces exactly one reply frame.
- The **profile connection** is request/response *until* the first `sync`
  (or, in public rooms, `history`) succeeds; from then on, unsolicited live
  frames (`message`, `vote`) arrive interleaved. Clients must dispatch
  frames by `type`, not assume the next frame answers the last request. The
  reference client always uses `sync`; `history` is a thin-client
  convenience for public rooms only.
- Exceptions to one-reply-per-request: `message` and `vote` send **no reply
  on success** (the event arrives later as a live frame, like everyone
  else's); they reply only with an `error` frame on validation failure.

### 1a. Protocol versioning (`hello` handshake)

The wire protocol carries a monotonically increasing integer
`wire.PROTOCOL_VERSION` plus `wire.MIN_PROTOCOL` (the oldest peer this build still
interoperates with). After launch, a deployed server and an already-installed app
can be different versions, so each side negotiates with a **`hello`** op
(**pre-auth, on both planes**, so an out-of-date app can react before logging in):

```json
{"type":"hello", "protocol":<int>, "min_protocol":<int>}
-> {"type":"hello", "server":"chat"|"account", "protocol":<int>,
    "min_protocol":<int>, "features":[<slug>,…], "compatible": true|false|null}
```

- **`compatible`** is the server's verdict computed from the client's declared
  `(protocol, min_protocol)`: `client.protocol >= server.min_protocol AND
  server.protocol >= client.min_protocol`. `null` if the client omitted its
  versions. The client computes the same from the reply (symmetric).
- **Breaking changes:** bump `PROTOCOL_VERSION`; raise `MIN_PROTOCOL` to the oldest
  still-supported peer. A too-old app gets `compatible:false` → show "please update"
  (don't fail cryptically). The reference client surfaces this as the typed
  `IncompatibleServer` exception via `await client.require_compatible()`.
- **Additive changes:** keep `MIN_PROTOCOL`; advertise the new capability in
  **`features`** so a client lights it up only when present (and old clients ignore
  it). Clients should already round-trip unknown fields and ignore unknown ops.
- The handshake is **informational** — it gates nothing server-side, so
  pre-versioning clients that never send `hello` are unaffected. Call `hello` at
  startup; cache the reply.

## 2. Client-side cryptography (normative)

All primitives are libsodium-compatible. Hex and base64 encodings as stated.

### 2.1 Key derivation

```
salt    = 16 random bytes                       (generated at account creation)
master  = argon2id(password, salt,
                   opslimit = 2,                (libsodium INTERACTIVE)
                   memlimit = 67108864,         (64 MiB)
                   outlen   = 32)
authKey = blake2b(data = "auth", key = master, outlen = 32)
encKey  = blake2b(data = "enc",  key = master, outlen = 32)
```

- `authKey` (hex) is sent to the server to prove identity. The server stores
  only a hash of it.
- `encKey` **never leaves the client**. The password never leaves the client.

### 2.2 Account blob

- Plaintext: a JSON object. Full schema as the reference client uses it:

```json
{
  "profiles":  {"<name>": {"sign_seed":"<hex32>", "sign_pub":"<hex32>",
                           "enc_seed":"<hex32>",  "enc_pub":"<hex32>"}},
  "room_keys": {"<room>": {"epochs": {"<n>": "<base64 key>"}, "current": <n>}},
  "pins":      {"<name>": "<base64 X25519 enc_pub>"},
  "sign_pins": {"<name>": "<hex ed25519 sign_pub>"},
  "contacts":   {"<profile>": {"<name>": {"state": "...", "room": "..."}}},
  "seen":       {"<profile>": {"<room>": <last-seen seq>}},
  "room_names": {"<profile>": {"<global room>": "<display name>"}},
  "credentials": {"<profile>": ["<VC token>", ...]}
}
```

  `profiles` holds each profile's key seeds; `room_keys` the per-epoch
  symmetric keys for E2EE rooms (§7a); `pins` / `sign_pins` the TOFU-pinned
  peer keys for sealing room keys and verifying signatures respectively;
  `credentials` the issuer-signed, DID-bound Verifiable Credentials a profile has
  earned (the `irl`/`email` badges) — kept for the holder's
  records and future (anonymous) presentation.
  Only `profiles` is always present; clients must round-trip unknown fields.
- Sealing: libsodium SecretBox (XSalsa20-Poly1305) under `encKey`, with a
  fresh random 24-byte nonce. Wire format: `base64(nonce || ciphertext)`.
- Versioning: integer, starts at 0 (no blob). A write must carry
  `current + 1`; on conflict, re-fetch (`blob_get`), merge, retry.

### 2.3 Profile keys and challenge signing

- Signing: ed25519 (authenticates the profile and signs every event, §7b).
  Encryption: X25519 (receives sealed room keys, §7a). Generate both at
  claim time; keep seeds in the blob, send pubs (hex, 32 bytes each) to the
  server.
- Challenge: the server sends `nonce` as a 64-char hex string. Sign the
  **UTF-8 bytes of that string** (not the decoded bytes) with the profile's
  ed25519 key; send the detached signature hex-encoded (64 bytes).

## 3. Account plane operations

The account plane is a **separate server**, default
`ws://host:8766`. Connect here for these ops; the chat server (§4, :8765)
rejects them.

| request | reply on success |
|---|---|
| `{"type":"hello", "protocol"?, "min_protocol"?}` | `{"type":"hello", "server":"account", "protocol", "min_protocol", "features":[…], "compatible"}` — protocol-version handshake (§1a). **Pre-auth.** |
| `{"type":"attest_challenge"}` | `{"type":"attest_challenge", "nonce":"<32 hex>"}` — a single-use device-attestation nonce, bound to *this* connection, ~5 min TTL (`CHAT_ATTEST_CHALLENGE_TTL`). The next `account_create` on the same socket consumes it. Pre-auth. |
| `{"type":"account_create", "account", "salt", "authkey", "platform"?, "attestation"?}` | `{"type":"account_created", "account", "device_attested"}` — connection is now authenticated. **Device attestation** (optional; §3a): `platform` `"ios"`/`"android"` + a platform `attestation` built over the challenge nonce earn `device_attested: true` + the full voucher budget; omitted (web/desktop) ⇒ unattested fallback. A genuine device that already made an account is rejected: `{"type":"error","code":"device_in_use"}`. |
| `{"type":"account_login", "account"}` | `{"type":"account_salt", "salt"}` |
| `{"type":"account_auth", "account", "authkey"}` | `{"type":"account_authenticated", "account", "blob", "blob_version", "vouchers_left", "device_attested"}` (`blob` is base64 or `null`) |
| `{"type":"blob_get"}` | `{"type":"blob", "blob", "version"}` |
| `{"type":"blob_put", "blob", "version"}` | `{"type":"blob_saved", "version"}`; error mentions `conflict` and the current version. The blob is opaque (server-encrypted); size-capped at `CHAT_MAX_ACCOUNT_BLOB` (oversized ⇒ `too large`) and **rate-limited** per account (token bucket; bot accounts exempt) |
| `{"type":"password_change", "salt", "authkey", "blob", "version"}` | `{"type":"password_changed", "version"}` — **secure password rotation** (authenticated session only; reaching it proves the *current* password). The client derives a new `(authkey, encKey)` from the new password under a fresh `salt`, re-seals the blob under the new `encKey`, and the server **atomically** swaps `salt` + auth verifier + `blob` (CAS on `version`, like `blob_put`). The password and derived keys never reach the server (it stores only a hash of `authkey`). A *forgotten* password can't be reset this way — the blob is sealed under the old key, unrecoverable without it (would need a separate recovery-key feature). Advertised via the **`password_change`** account `hello` feature. Client: `ChatClient.change_password(new_password)`. |
| `{"type":"voucher_get"}` | `{"type":"voucher", "voucher", "vouchers_left"}` — `voucher` is a **signed token** (`nonce ⋮ sig`) verified by the chat server offline (§11) |
| `{"type":"account_info"}` | `{"type":"account", "id", "created_ts", "email", "email_verified", "device_attested", "irl_verified", "irl_spent", "paying", "anon_tokens_left", "anon_issuer":{"n","e"}, "billing", "blob_version", "vouchers_left"}` (`irl_spent` = the account used its one irl grant; `paying` = account credibility flag that flows to all profiles; `anon_tokens_left` = remaining blind knock-token budget; `anon_issuer` = the blind-token issuer's **public** key (hex), which the client needs to blind token ids before `anon_token_issue`) |
| `{"type":"account_update", "billing"?}` | same `account` frame, updated (billing only; email has its own ops below) |
| `{"type":"email_set", "email"}` | `{"type":"email_verification_sent", "email"}` — sets/changes the account email (marks it **unverified**) and sends a one-time verification token. Changing the email always re-requires verification. In a dev deployment the reply also carries `dev_token` (the token), gated by `CHAT_EMAIL_DEV_ECHO`; **never enabled in production** (auto-off for the SMTP backend) |
| `{"type":"email_verify", "token"}` | `{"type":"email_verified", "email_verified": true}` — confirms the token (single-use, TTL `CHAT_EMAIL_VERIFY_TTL`); error if wrong/expired |
| `{"type":"email_attest"}` | `{"type":"email_attestation", "attestation"}` — once verified, mints an **unlinkable bearer** attestation (purpose-tagged `emailverify`, **no DID, no account reference**) the client carries to `profile_attest` (§4.1). **Carries no DID — the account↔profile firewall: the issuer must never learn which profile this is for; the chat plane binds it to the holder's DID at redemption.** Error `email not verified` otherwise. Unbudgeted. |
| `{"type":"irl_attest"}` | `{"type":"irl_attestation", "attestation"}` — same bridge, a bearer attestation purpose-tagged `irlverify`. Requires the account to be **irl-verified** (operator/KYC — `account_server/verify_irl.py`) and is **single-use per account**. No DID/account reference (the firewall). Errors: `account is not irl-verified` (`code:"irl_not_verified"`), `irl already used — one profile per account` (`code:"irl_spent"`). |
| `{"type":"paying_attest"}` | `{"type":"paying_attestation", "attestation"}` — a bearer attestation purpose-tagged `payingverify` for the **`paying`** badge (account-level credibility). Requires a **paying** account (set by billing or `account_server/set_paying.py`). **Unbudgeted and repeatable** — unlike `irl`, it is meant to **flow to ALL the account's profiles** (each redemption unlinkable to the account and to the others). No DID/account reference (the firewall). Error: `account is not a paying customer` (`code:"not_paying"`). |
| `{"type":"anon_token_issue", "blinded":["<hex>", …]}` | `{"type":"anon_tokens", "sigs":["<hex>", …]}` — blind-sign a batch of **anonymous knock tokens** (DISCOVERY.md §6b). The client sends **blinded** token ids (blinded with `anon_issuer` from `account_info`); this plane blind-signs each (it never sees the ids → unlinkable issuance) and decrements the account's token budget. The client unblinds + stores them, then spends one per `knock` (verified on the chat plane with the public key, which **cannot mint**). Batch ≤ `ANON_TOKEN_MAX_BATCH` (64); errors: `blinded must be a list of 1..64 hex ints`, `invalid blinded value`, `anon token budget exhausted` (`code:"anon_budget"`). |

Notes:
- `account_create` authenticates the connection immediately; no separate
  login needed on first run.
- All operations after the first three require an authenticated account.
- The profile-claim `voucher` is single-use; account budget defaults to 5
  (`CHAT_VOUCHER_BUDGET`). (A paid, transferable *token economy* was prototyped
  and removed for the legal complexity of anonymous P2P
  payments; it's documented there for future re-introduction.)

### 3a. Device attestation (optional sybil-resistance signal)

A native app can prove `account_create` came from a **genuine, unmodified app on
a real device** and that the **device hasn't already made an account** — a
sybil-resistance signal layered with the voucher budget and email verification
(not a hard wall). Two goals, two platform primitives:

- **Genuineness** → `device_attested` (account-wide flag): iOS **App Attest**,
  Android **Play Integrity**. Sets the voucher budget.
- **One account per device**: iOS **DeviceCheck** (2 persistent bits), Android
  **Device Recall** — survive reinstall; the device id never leaves the device.

Flow: `attest_challenge` → build the platform attestation over the returned
nonce → `account_create` with `platform` + `attestation` **on the same socket**.
Shapes:
- iOS: `"attestation": {"app_attest": {"key_id","object"}, "device_check":"<b64>"}`
- Android: `"attestation": {"play_integrity":"<token>"}`

**Web/desktop have no attestation** — so it's always *attested vs not*, never
*attested-or-rejected*: an unattested create still succeeds (unattested budget),
never a hard failure. Policy (`CHAT_ATTEST_POLICY`): `off` (ignore), `soft`
(default — record the signal; unattested falls back), `strict` (a *claimed-native*
create that fails verification is rejected; web, sending no `platform`, is still
allowed). Budgets: `CHAT_VOUCHER_BUDGET` (attested) and
`CHAT_VOUCHER_BUDGET_UNATTESTED` (defaults to the full budget — no penalty unless
the operator lowers it). Errors carry a `code`: `device_in_use`, `attest_failed`,
`attest_no_challenge`.

Verification is pluggable (`CHAT_ATTEST_BACKEND`): `stub` (dev/test) or
`platform` (real Apple/Google — credential-gated; **Phase 1 ships the wire
contract + policy + stub**, with the real verifiers as the documented next step).

## 4. Profile plane operations

### 4.1 Identity

| request | reply on success |
|---|---|
| `{"type":"hello", "protocol"?, "min_protocol"?}` | `{"type":"hello", "server":"chat", "protocol", "min_protocol", "features":[…], "compatible"}` — protocol-version handshake (§1a). **Pre-auth** (works with no profile). |
| `{"type":"profile_claim", "name", "voucher", "sign_pub", "enc_pub", "enc_pub_sig", "bot"?, "bot_secret"?}` | `{"type":"profile_claimed", "name", "bot"}` — **`enc_pub_sig`** (required) is the profile's signature over `wire.encpub_signing_bytes(did, enc_pub)` binding its `enc_pub` to its DID (#15); the server rejects a bad/missing binding (`invalid enc_pub binding signature`). `anon_claim` carries the same field. `bot` (default false) marks an automated/LLM-backed profile; set once here, **immutable** and public so it can't masquerade as human. The name is screened by a server-side **profanity/slur filter** (`profile name not allowed`) and a **reserved-handle list** (`profile name is reserved` — admin/support/system/etc.); see §6. Server-run **bot handles** (`CHAT_WELCOME_BOT`/`CHAT_SERVER_BOTS`) are also reserved from users: claiming one requires `bot_secret` = `CHAT_BOT_CLAIM_SECRET` (the operator's bot runner sets it; users omit it and get `profile name is reserved`) |
| `{"type":"profile_challenge", "name"}` | `{"type":"challenge", "name", "nonce"}` |
| `{"type":"profile_auth", "name", "signature"}` | `{"type":"profile_authenticated", "name", "human_backed", "bot", "welcome_bot", "is_system_mod"}` — `welcome_bot` is the server's configured welcome bot to auto-add as a contact (or null); **`is_system_mod`** (bool) is whether this DID is a system moderator (config `CHAT_SYSTEM_MODS`), so the client gates the `system_delete` affordance to actual mods |
| `{"type":"profile_attest", "attestation", "badge"?}` | `{"type":"profile_attested", "name", "badge", "credential", "badges": [..]}` (+ `"email_verified": true` when `badge="email"`) — grant a humanness badge, **firewall-preserving**. Verifies the account-issued **bearer** attestation offline against the voucher key for the badge's purpose (`email`→`emailverify`, `irl`→`irlverify`), dedupes its nonce (single-use), grants the badge, then **re-issues a DID-bound Verifiable Credential signed with the chat plane's VC key** (`sub` = THIS profile's DID) — the DID binding is added here, by the plane that already knows the DID, so the account never learns it. The reply echoes the chat-issued `credential` for the holder's blob (`credentials`, used by VPs). The bearer token is transferable pre-redemption (accepted); presentation-layer non-transferability lives in the VP (bound to its holder). **One-way**, idempotent, no account reference reaches the chat plane. Errors: `badge is not attestation-grantable`, `invalid attestation`, `attestation already spent` |
| `{"type":"profile_info", "name"}` | `{"type":"profile", "name", "did", "sign_pub", "enc_pub", "human_backed", "bot", "created_ts", "display_name", "bio", "avatar_hash", "avatar_url", "avatar_small_url", "default_variant", "avatar_is_default"}` — a profile's full public record. **`did`** is the profile's self-minted **`did:key`** — `did:key:z` + base58btc(0xed01 ‖ ed25519 `sign_pub`); it's the profile's permanent id, locally verifiable (`did == did_key(sign_pub)`, and a signed event's author is whichever DID's key signed it). As of **1c-A** the DID is the **author of record** on every signed event (authorship-by-signature, §7b); `name` is still the addressing handle and an advisory display label. All ed25519 DIDs start `did:key:z6Mk`. `created_ts` is unix seconds; `display_name` is the owner-asserted label (falls back to the handle); `bio` is the owner-asserted "about" text for the profile page (`null` when unset); `avatar_hash` is the cache key for the small avatar (null only if none); `avatar_url` is a short-lived **presigned** URL for the **large custom** profile-page image (or an external URL the owner set directly; `null` for a default — defaults are generated on demand, not stored); `avatar_small_url` is a presigned URL for the **small custom** image (`null` for a default or an inline upload); both are minted fresh per request and expire (~15 min) — fetch and cache by `avatar_hash`; `default_variant` is the assigned robot whose default image is generated from it; **`avatar_is_default`** is `true` while the avatar is still the assigned droid (small + large) and `false` once the user sets a custom picture. **`email_verified`** is `true` once an account-plane email attestation has been applied (`profile_attest`) — a coarse public anti-throwaway badge, **not** identity (conveys no email/account); distinct from the future "verified name". **`badges`** is the profile's public badge slug list (e.g. `["email","irl"]`): stored badges plus a derived `email` entry when `email_verified`. Does **not** carry avatar bytes (fetch via `get_avatar`). |
| `{"type":"profile_infos", "names":[..]}` | `{"type":"profiles", "infos": {"<name>": {"name","did","sign_pub","display_name","bot","anon","banned"}, ..}}` — **batch** sign-key resolution (#22). **`anon`** flags an anonymous guest: guest handles carry **no name prefix** (they're pronounceable two-word handles like `brave_otter` in the same namespace as real users), so this flag — TOFU-pinned alongside the key, like `bot` — is how a client labels a guest author. **`banned`** is the profile's current platform-ban status (#27; mutable, NOT pinned — re-read each time). the **lean** public record for many handles in ONE reply, so a client verifies a whole thread's vote/reaction tallies (and authorship) in a single round-trip instead of one `profile_info` per distinct voter. Lean by design — it omits the heavy avatar-presign/badge work `profile_info` does (this is the hot signature-verify path). Unknown handles are simply **absent** from `infos`. Capped at **200** names per call (page beyond that). Session-less public directory data, like `profile_info`. Advertised via the **`batch_profile_info`** `hello` feature. |
| `{"type":"permalink", "id"}` | `{"type":"permalink", "id", "found", "kind", "room", "board", "post_id", "parent", "message"}` — **resolve a permalink.** The canonical reference to a post/comment is just its **globally-unique message `id`** (opaque + stable, so the client builds any URL from it and the URL scheme can change later). Given an id, returns where it lives + a preview: **`kind`** `"post"`/`"comment"`, the **`room`** it lives in, the thread's **`board`** + root **`post_id`** (a comment's room is `post-<post_id>`), the **`parent`** comment (or null), and the folded **`message`** record (text **inlined**, tallies, comment count) for a preview card. A **deleted** id still resolves (the tombstone — link shows "deleted", not 404). The fold holds only PUBLIC content, so a private/unknown id → **`found: false`** (permalinks can't leak private rooms). Public + session-less. **PCM token:** embed one inline as **`pm:<32 hex>`** (recognized at render time only — not normalized, so franking is unaffected); the client resolves + navigates it. Client: `permalink(id)`, `open_permalink(id)` (resolve + jump, across rooms); `pcm.permalink_token(id)` / `extract_permalinks`. |
| `{"type":"resolve", "did"\|"name"}` | `{"type":"resolved", "did", "name", "sign_pub", "enc_pub", "enc_pub_sig", "avatar_hash", "display_name"}` — resolve a profile **both ways**: pass `did` to get its current `@handle`, or `name` to get its DID. A **minimal DID document** — returns the DID's verifiable key set + current handle. **`enc_pub_sig`** is the profile's ed25519 signature (over `wire.encpub_signing_bytes(did, enc_pub)` = `\x1f`-joined `"pm-encpub-v1" ⋮ did ⋮ enc_pub`) verifiable against `did_to_sign_pub(did)`, so a client gets a peer's **`enc_pub` trustlessly from the DID** (no first-contact MITM on the room-key seal — the handle→DID step stays advisory). `enc_pub` is **permanent** (mint-once, like the DID; the version tag leaves room for a future rotatable binding). Public + session-less. |
| `{"type":"get_avatar", "name", "size"?, "meta_only"?}` | `{"type":"avatar", "name", "size", "avatar", "avatar_url", "content_type", "avatar_hash", "avatar_is_default", "avatar_path"}` — `size` is `"small"` (default) or `"large"`. **`avatar_is_default`** (bool) tags whether it's the generated default (render a letter-circle) vs a custom upload — so the client decides from this one reply, no extra `profile_info`. **`avatar_path`** is the CORS-enabled byte endpoint for this size on **this** server (`/<name>/avatar` or `/<name>/avatar/large`) — resolve it against the chat host and **prefer it on web** for the LARGE image (the presigned `avatar_url` isn't browser-CORS-fetchable; the small is already inlined as `avatar` bytes). **`meta_only: true`** returns just `avatar_hash` + `avatar_is_default` + `avatar_path` (no bytes/URL, nothing generated or presigned) — to decide whether to fetch at all. The reply carries **both** `avatar` (base64 bytes \| null) and `avatar_url` (string \| null) for either size: **resolve `avatar_url` first** (a short-lived **presigned** URL the client fetches directly; expires ~15 min, minted per request), else render the `avatar` bytes. A **custom** avatar lives in the **private** object store. The **small** thumbnail is served as inline `avatar` bytes **even with a store** — the server fetches the object and base64s it (a few-KB payload that avoids the cross-origin/CORS fetch web/CanvasKit can't do on a private presign, and the URL expiry); the **large** profile-page image is served as a presigned `avatar_url` (loaded only on the profile screen; falls back to the small object). A **default** robot is **generated on demand** → served as `avatar` bytes with `avatar_url: null` (never stored). When no object store is configured, a custom avatar is inline `avatar` bytes. Cache by `avatar_hash` regardless of how you got the image (don't cache the URL — it expires). |
| `{"type":"profile_update", "display_name"?, "bio"?, "avatar"?, "content_type"?, "avatar_url"?}` | `{"type":"profile_updated", ...same fields as the `profile` reply}` — **edits the authenticated profile only**. Any provided field is applied; omitted fields are left unchanged; an **empty string clears** (display_name → reverts to handle; bio → cleared (null); avatar → reverts to the generated default robot; avatar_url → cleared). `avatar` is base64 image bytes (the small custom thumbnail) — the server stores it in the object store when one is configured (and `get_avatar`/the card then serve it as `avatar_small_url`), else inline. |
| `{"type":"issuers"}` | `{"type":"issuers", "issuers": ["<ed25519 pubkey hex>", …]}` — the credential **issuer** public keys this server trusts, so a client can verify a peer's **Verifiable Presentation** locally. One today: the **chat plane's VC issuer key** (`VC_ISSUER_PUBKEY`) — the rung VCs are chat-issued at `profile_attest` (the account issues only the unlinkable bearer humanness token; §3.4). Federation-ready. Session-less. (A client needing a hard trust root should pin these out of band; fetching here trusts the server to name its own issuers.) |
| `{"type":"handle_change", "name"}` | `{"type":"handle_changed", "name", "did"}` — change the authenticated profile's **@handle**. The **DID is unchanged** — keys, history, memberships, badges, and inbox are all DID-keyed and stay put; only the mutable display handle moves. The new handle passes the **same gates as a claim** (charset/reserved/profanity/server-bot). The released handle is **tombstoned for a cooldown** (`CHAT_HANDLE_COOLDOWN`, 30d default) so it can't be immediately grabbed to impersonate — the owner may reclaim its own within the window; another claimant gets `profile name is cooling down`. Anon (key-derived) handles can't be changed. |
| `{"type":"avatar_upload", "data", "content_type"?}` | `{"type":"avatar_uploaded", "avatar_url"}` — upload the **large** profile-page avatar (`data` base64, ≤ 4 MiB) to the **private** object store; the server keeps the object key and returns a short-lived **presigned** `avatar_url` (re-minted on each `get_avatar`/card read). Errors if the server has no object store configured. Use this for the large image; `profile_update`'s inline `avatar` is the small chat thumbnail. (`profile_update`'s `avatar_url` field, by contrast, sets an **external** image URL, returned verbatim.) |

Notes:
- Claim order matters server-side: name availability is checked **before**
  the voucher is spent, so a name collision does not burn the voucher —
  retry with a different name and the same voucher.
- A failed `profile_auth` consumes the challenge; request a new one.
- `historian` is reserved and can never be claimed.
- Claiming a profile **auto-creates** its private notification inbox, a room named
  `wire.inbox_room(did)` = `inbox-<sha256(did)[:24]>` (kind `inbox`) — derived from
  the permanent **DID** (1c-B) so it survives a handle change. (The `-inbox` suffix
  remains a reserved handle/room namespace, see §5/§6.)
- **Bots** are ordinary profiles claimed with `bot: true` — anyone may make one
  (it costs a voucher like any profile). The flag is immutable and surfaced
  everywhere a profile is (`profile_claimed`, `profile_authenticated`,
  `profile_info` all carry `bot`), so clients must label bots clearly. A bot is
  driven by a client (e.g. `bots/runner.py`); the server treats it like any
  other profile.
- **Profile pages & avatars.** A profile carries owner-asserted public metadata:
  a `display_name` and two avatars. The **small** avatar is a chat thumbnail
  (≤16 KiB) served by `get_avatar` (cache it by `avatar_hash`); the **large**
  avatar is for a profile page (object-store URL, or a served default droid).
  Every profile is given a **default droid avatar at claim**, picked
  deterministically from its handle — so `avatar_hash` is non-null from the
  start and there is no blank state. Metadata is editable only by the profile
  owner (`profile_update`) and is **mutable** (unlike `bot`); it is **unsigned**
  in v1 — a malicious server could swap it, while keys stay TOFU-pinned (an
  owner-signed metadata record is deferred). Render the small avatar in chat and
  fetch the large one only when opening a profile page.
- All chat operations below require a profile-authenticated connection.

### 4.2 Chat

| request | reply on success |
|---|---|
| `{"type":"room_create", "room", "private"?, "kind"?, "parent"?}` | `{"type":"room_created", "room", "private", "kind", "parent"}` — creator becomes the **sponsor**; `private` defaults to **true**; `kind` `"room"` (default) or `"dm"` (contact-room tag). `inbox` and `board` are server-reserved — **board creation is disabled** (`kind:"board"` → error); there is one shared board (`bigboard`, auto-created) that all posts go to. **`parent`** nests this as a **subroom** of another chat room — you must be a **member of the parent** to create one (gated discovery, see `subrooms`); the parent must be `kind:"room"`. Subrooms keep their own `private` (default true, since private→public is one-way) and join policy |
| `{"type":"contact", "action": "request"\|"accept", "name", "room"?}` | `{"type":"contact_sent", "name", "action"}` — routes a contact handshake notification to the profile's inbox (`room` is the new DM room on accept) |
| `{"type":"clear_history", "room"}` | `{"type":"history_cleared", "room"}` — purge a room's events from the stream; **inboxes only** for now, sponsor only |
| `{"type":"room_publish"}` | `{"type":"room_published", "room", "public_from"}` — sponsor only, one-way private→public |
| `{"type":"room_policy", "policy"}` | `{"type":"policy_set", "room", "policy"}` — mods set `"open"`/`"invite"` |
| `{"type":"room_style", "style"?, "sort"?, "anchor"?, "threshold"?}` | `{"type":"style_set", "room", "thread_style", "sort_mode", "anchor", "threshold"}` — mods set any of: `style` `"flat"`/`"tree"`, `sort` `"new"`/`"top"`/`"best"`, **`anchor`** `"top"`/`"bottom"` (where the client opens / scroll start), `threshold` int or `null`. All are render *suggestions* echoed in the `joined` frame and overridable per-reader |
| `{"type":"room_vote_limit", "limit"}` | `{"type":"vote_limit_set", "room", "vote_limit"}` — **sponsor only**; per-message tally cap (`0` = unlimited). *Enforced*: historian + live fold clamp tallies, so it is not client-overridable. Announced in-room |
| `{"type":"room_require_cred", "cred"}` | `{"type":"require_cred_set", "room", "require_cred"}` — **sponsor only**; gate the room on a **Verifiable Credential**. `cred` is an attestation badge slug (e.g. `"irl"`); empty/null clears the gate. A non-sponsor/mod joiner must then present a valid VP for that type (see `join`). `cred` must be a known attestable type. Announced in-room |
| `{"type":"request_join", "room"}` | `{"type":"request_sent", "room"}` — ask to join a private open room |
| `{"type":"join_requests"}` | `{"type":"join_requests", "room", "requests": [..]}` — mods list pending requests |
| *(inbox)* | each profile auto-gets a private room `wire.inbox_room(did)` (= `inbox-<sha256(did)[:24]>`, derived from the DID — 1c-B) at claim; mod actions affecting it publish a durable `notification` event there. Read missed ones by `join`+`sync`ing the inbox. |
| `{"type":"invite", "name"\|"did", "from_start"?}` | `{"type":"invited", "room", "name", "did", "from_seq"}` — mods only; also approves a pending request; `from_start` (default true) picks the member's history floor |
| `{"type":"kick", "name"\|"did"}` | `{"type":"kicked", "room", "name"}` — mods kick members, only the sponsor kicks mods, nobody kicks the sponsor. The kicked profile is **barred** from rejoining or requesting (any policy) until a mod invites them back; all their connections get a `you_were_kicked` push |
| `{"type":"mod_grant", "name"\|"did"}` / `{"type":"mod_revoke", "name"\|"did"}` | `{"type":"mod_granted"/"mod_revoked", "room", "name", "did"}` — sponsor only |
| `{"type":"room_transfer", "name"\|"did"}` | `{"type":"sponsor_transferred", "room", "sponsor", "did"}` — **sponsor only**; hand the room to another **member**. The new profile becomes sponsor; the old sponsor is demoted to mod. Announced in-room; new sponsor gets a `sponsor_granted` inbox notification |

> **Addressing by DID or @handle (1c-B):** membership/ownership is keyed internally by the **DID** (the permanent id), so an addressing op (`invite`/`kick`/`mod_grant`/`mod_revoke`/`room_transfer`/`contact`) accepts **either** a `did` (preferred — stable) **or** a `name` @handle, and resolves to the DID. Rosters (`room_members`/`room_invitees`/`join_requests`/`mods`, and `joined`'s `members`/`mods`/`sponsor`) are resolved back to **current @handles** for display.
| `{"type":"join", "room", "presentation"?}` | `{"type":"joined", "room", "name", "members": [..], "private", "sponsor", "mods": [..], "kind", "join_policy", "thread_style", "sort_mode", "anchor", "threshold", "vote_limit", "require_cred"}` — the presentation hints + enforced vote cap. **Presentation hints** tell the client how to render/open the room: **`thread_style`** `"flat"`/`"tree"`, **`sort_mode`** `"new"`/`"top"`/`"best"`, **`anchor`** `"top"`/`"bottom"` (where to open: the top for a ranked feed, or the bottom/newest for chat). Server defaults by `kind`: a post's **comment room** → `tree` / `best` / `top`; a **board** → `flat` / `best` / `top`; a plain **chat room / dm** → `flat` / `new` / `bottom`. A mod overrides via `room_style` + **`require_cred`** (the room's credential gate, or null). **Credential-gated rooms (Phase 3):** if `require_cred` is set, a non-sponsor/mod joiner must include **`presentation`** = a **Verifiable Presentation** (`wire.vp_sign`) bound to this room (`audience` = room name), fresh, signed by the joining DID, carrying a trusted-issuer VC of the required type — else `this room requires a verifiable credential: <type>`. **Session-less read-only join:** a connection with **no profile** may join a **public** room (returns `name: null`, `members: []`, no membership recorded) to set read context for `ranked`/`history`/`sync`/`bodies` — already-public content served from `public_from`. Private rooms refuse it; writing/participating still needs a profile. |
| `{"type":"history", "limit"?}` | `{"type":"history", "from": "historian", "messages": [..]}` — **public rooms only**; private rooms error ("use sync") |
| `{"type":"ranked", "sort"?, "limit"?, "room"?}` | `{"type":"ranked", "room", "sort", "messages": [..]}` — a bounded top-K page from the fold ranked across the WHOLE room (`sort` ∈ `"best"` (Wilson, default) \| `"top"` (net score) \| `"new"`); no live delivery. **Public (fold-backed) rooms only.** Optional **`room`** ranks that **PUBLIC** room **without joining and without touching the connection's current room** — session-less (like `feed`), so a persistent board tab and concurrent comment dives don't contend for the connection's room. A private/credential-gated/unknown `room` → error; omitting `room` ranks the joined room. |
| `{"type":"sync", "since"?, "tail"?, "sort"?, "depth"?, "shape"?}` | `{"type":"synced", "room", "upto", "floor"}`, then event frames (see §4.3) — raw metadata replay for client-side folding. **`tail=N`** bounds the open to the last N events (the cheap way to open a huge room), never below `since`/floor. On a **threaded public room** (`thread_style:"tree"` — a post's comment room) a flat newest-N tail is content-broken: it orphans replies whose parent fell outside the window (they render as fake roots), so the thread structure vanishes. There `tail` instead opens the newest- (or `sort`-best-) **N comment roots plus their subtrees** — thread-COMPLETE, no orphans — capped at a ceiling so a viral thread stays bounded. **`sort`** ∈ `"new"` (default; most-recent roots) \| `"best"`/`"top"` (highest net-score roots); ignored on flat/private rooms (plain newest-N). **`depth`** (#23) bounds each subtree to that many reply levels — `0` = roots only, `2` = roots + two levels (a SHALLOW teaser open: fold ~tens of events, drill deeper via `subtree`); `shape:"shallow"` is shorthand for `depth:2`; omit for full subtrees. The event at `upto` (and anything newer than the fold had recorded) is always delivered, so the caught-up marker is reached regardless of the filter — no client change needed. |
| `{"type":"subtree", "root", "room"?, "sort"?, "limit"?, "depth"?}` | `{"type":"subtree", "room", "root", "sort", "messages":[..]}` — the replies under one comment `root` (#23), served from the fold like `ranked` (same message shape + server-reported tallies): **one level by default**, or bounded **`depth`**; **`sort`** ∈ `"new"` (default, reading order)\|`"top"`\|`"best"`; **`limit`** caps the rows (the recursion + LIMIT run in SQL, so a huge subtree never materialises). The drill-in for a shallow tree open. Reads the joined room, or an explicit **PUBLIC** `room` without joining (session-less). Advertised via the **`subtree`** `hello` feature. |
| `{"type":"bodies", "ids": [..], "room"?}` | `{"type":"bodies", "room", "bodies": {"<id>": {"text","name","ts"}, ..}}` — lazy body hydration, batched. Optional **`room`** (a readable PUBLIC room) hydrates that room's bodies **without joining / touching the current room** — the companion to explicit-room `ranked`, so a board tab renders posts it ranked join-free. Omitting `room` reads the joined room. |
| `{"type":"content_url", "blob_id", "mode":"put"\|"get", "size"?, "room"?}` | `{"type":"content_url", "blob_id", "mode", "url"}` — presigned object-store URL for **direct** blob transfer (`url` null ⇒ use content_put/get). With the `tiered` body store, `size` (put) gates S3: below `CHAT_BODY_S3_THRESHOLD` the server returns null and the client uses NATS. The client records which tier it used in the blob descriptor. **`mode:"get"`** reads from the **joined** room, or from a **public** room named in `room` with **no join and no session** (feed thumbnails) — a private room's content requires a joined connection. **`mode:"put"`** is a write: it needs a **joined** room (hence a session). Distinct from the account-plane `blob_put`/`blob_get` |
| `{"type":"content_put", "blob_id", "data"}` | `{"type":"content_stored", "blob_id"}` — server-mediated blob upload (base64; opaque to the server — ciphertext in private rooms); `≤ CHAT_MAX_BLOB_BYTES`. Requires a joined room (a write) |
| `{"type":"content_get", "blob_id", "room"?}` | `{"type":"content_data", "blob_id", "data"}` — server-mediated blob download (base64). Reads from the **joined** room, or from a **public** room named in `room` with **no join and no session** (so a guest's feed renders real thumbnails); a private room's content requires a joined connection |
| `{"type":"content_get_batch", "items":[{"blob_id","room"?},…], "room"?}` | `{"type":"content_batch", "items":[{"blob_id","data"}\|{"blob_id","error"}]}` — fetch **many** blobs in **one** round-trip (so an image-heavy feed/board page isn't N serial `content_get`s). Each item resolves with the **same** rules as `content_get` (per-item `room`, else the top-level default `room`, else the joined room; public served join-free/session-free, private needs membership). **Per-item independent** — a bad/missing/over-budget blob yields `{blob_id, error}` while the rest return `data`; **order preserved**. Capped at **50** items and a total byte budget (an item that won't fit → `error`, fetch it singly). Read-only; in the anon allow-list and callable session-less |
| `{"type":"message", "id", "ts", "text", "commit", "sig", "parent"?, "post"?}` | *(no reply on success; arrives as a live `message` frame)* — client-signed, see §7b. `post` is the optional **post type** (`null`/absent = a plain message; else a token matching `[a-z0-9_]{1,32}` — `text`, `image`, `video`, `event`, `for_sale`, …). It is part of the **signed** skeleton (in sealed `meta` for private rooms), so it can't be forged/relabeled/stripped; the signature includes it only when set, so plain messages are unchanged. A body of `QUOTE1:{"room","id","text"}` is a quote; the server rejects a public post that quotes a **private** room. |
| `{"type":"vote", "id", "vote": "up"\|"down", "ts", "sig", "room"?}` | *(no reply on success; arrives as a live `vote` frame)* — client-signed. Optional **`room`** targets another **PUBLIC** room (e.g. vote a board post while joined to its `post-<id>` comment room) — the sig is room-bound so it's verified against the named room, applied there; a private/unknown target → error (no ACL bypass). Same optional `room` on **`reaction`** (parity). Gated by the **`room_targeted_vote`** `hello` feature. Encrypted/sealed votes stay current-room. |
| `{"type":"delete_message", "id"}` | `{"type":"message_deleted", "room", "id"}` — delete a post/comment in the **current** room (join it first; **public** rooms only). Allowed for the message's **author** (self-delete) or a **mod/sponsor** of the room. Leaves a **tombstone**: the skeleton stays in history (so clients render "post/comment deleted") but the **body is purged**, and the message now folds with **`deleted: true`** (+ `deleted_by`) and no content. A live **`delete`** frame (`{type:"delete", id, room, by, post}`) fans out to joined members. When a mod deletes someone *else's* message, the author gets an inbox **`post_deleted`**/`comment_deleted` notification. (The message must already be folded — delete what you can see.) |
| `{"type":"system_delete", "id"}` | `{"type":"message_deleted", "room", "id", "by"}` — **system-wide** public moderation: a **`SYSTEM_MODS`** profile (config `CHAT_SYSTEM_MODS`, default **`harold`**) deletes **ANY public post/comment by id** — across all public rooms, **no join, no per-room mod role** (the server resolves the room from the globally-unique id). Like `delete_message` it tombstones (`deleted:true`, `deleted_by`, live `delete` frame, author notified), but instead of purging it **REPLACES the stored body** with `"message deleted by <mod>"`, so a raw `bodies` fetch returns the notice. The `messages` fold holds only public-room events, so **private content is unreachable** (a private id → "no such message"). A non-system-mod → "not authorized". **Authorized by DID:** the configured `CHAT_SYSTEM_MODS` handle is resolved to its DID once (or DIDs given directly via `CHAT_SYSTEM_MOD_DIDS`) and the connection's `did` is checked against it — so a handle change/transfer can't carry the power; the handles are also **reserved server-bot handles** (claimable only with the bot secret), so they can't be squatted. Advertised via the **`system_moderation`** `hello` feature. |
| `{"type":"ban", "did"}` / `{"type":"unban", "did"}` | `{"type":"banned", "did"}` / `{"type":"unbanned", "did"}` — **platform-wide ban by DID** (#27), **`SYSTEM_MODS` only** (same DID-bound gate as `system_delete`; non-mod → "not authorized", unknown DID → "no such profile", self → "can't ban yourself"). Sets a **mutable** `banned` flag on the profile (`unban` clears it; `banned_by` records the acting mod). **Enforcement:** a banned DID's content writes (`message`/`vote`/`reaction`/`pollvote`/`report`) are rejected with "your account is banned"; reads stay allowed. The flag surfaces in `profile_info`/`profile_infos` (so a profile renders a "banned" tombstone) and is **stamped per message** (`banned:true`) on the public serve paths — `ranked`, the `feed`, and `history`/`sync` snapshots — so a banned author's existing posts tombstone inline everywhere (the author's *current* status at serve time, not signed; ban wins over the deleted stub). Advertised via the **`ban`** `hello` feature. |
| `{"type":"mention", "id", "names": [..]}` | *(no reply on success)* — notify mentioned profiles; the client extracts `@names` from its own plaintext, the server routes to those that are room members. **Bot summon:** a mentioned **bot** is also notified when the room is **PUBLIC** even if it is *not* a member — `@chad …` pings chad's inbox, and its runner joins the room and replies in-place (a bot reply to the summoning message). Non-bot non-members are never notified; private rooms stay member-only (don't reveal a sealed room). See `bots/runner.py` (`_reply_to_mention`). **Continue a thread (#28/#29):** **replying to a message** in a PUBLIC room (no `@` needed) fires a `"replied"` inbox notice to the parent's author (`_ping_reply`, skipping self-replies; private rooms excluded — parent author unreadable). For a **bot** that drives the next turn (`_reply_to_thread`, capped per thread); for a **human** it's a durable "↩️ Replied to you in <room>" notice so quiet 1:1 threads get noticed — de-duped per connection within a window so a reply burst from one person isn't a storm (cross-user replies to one author still each ping). No client change: the reply already carries `parent`. |

> **Mod-review crosspost (server-internal, no client op).** When image moderation is on (and `CHAT_MOD_REVIEW` ≠ 0, the default), the server crossposts every scanned **public** image's verdict to each system mod's **private** mod-review room (`wire.modreview_room(did)`, member = that mod only) for human review — cleared → the image inline + a verdict caption; rejected → a text-only verdict line (the bytes are deleted). Each verdict ends with a **`pm:<id>` permalink** (PCM token) back to the original post, so the mod can tap straight through to it (resolves the post/comment, or its tombstone if a rejected image's post was removed); only the already-public original is reachable that way. The verdict text lives **only** in that private room and is never delivered to any other client (leaking nsfw/nudenet thresholds would let content be tuned to evade the scanner). The mod reads it like any room (`join` + `sync`/`history`). A cleared entry's blob descriptor carries **`src_room`** (the original public room) — a client honoring it fetches the image cross-room (`content_get`/`content_url` with `room`) instead of copying bytes; the verdict caption shows regardless. |
| `{"type":"rooms", "since"?: {room: seq}}` | `{"type":"rooms", "rooms": [{"name", "events", "kind", "private", "unread"?}, ..]}` — only rooms this profile is a **member** of. `private` is a JSON bool (authoritative; prefer it over a key-presence heuristic for the locked/unlocked icon); `kind` is the room class (§5). `events` is the room's total frame count. Optional `since` = your per-room last-seen seqs (client-held, sent each call → no server read receipts); each room with a watermark gains **`unread`**, the count of MESSAGE frames with `seq > since` (votes/reactions excluded; works on private rooms via the blind index, server reads no content) |
| `{"type":"leave"}` | `{"type":"info", "message": "left room"}` — **step out**: drops membership but KEEPS your invite, so you can rejoin freely (used routinely, e.g. closing a DM view). Does not rotate the key. Error if not in a room |
| `{"type":"self_kick"}` | `{"type":"unsubscribed", "room"}` — **permanently leave** ("unsubscribe"): revokes your OWN invite (barred until re-invited, like a kick) and announces `departed` so the sponsor re-keys — your key stops decrypting future messages. The sponsor must transfer the room before unsubscribing. Distinct from `leave` |
| `{"type":"room_invitees"}` | `{"type":"room_invitees", "members": [..]}` — the room's invited roster (ACL); the sponsor diffs it against recorded key-holders to detect a permanent departure and re-key. Cf. `room_members` (currently joined, fluctuates) |
| `{"type":"subrooms", "room"}` | `{"type":"subrooms", "room", "rooms": [{"name","kind","private"}, ..]}` — **gated discovery of nested rooms**: the direct subrooms of `room`, returned **only if you're a member** of it — so a subroom is invisible until you've been let into its parent. Finding a subroom isn't entering it: a private subroom still needs its own invite |
| `{"type":"room_delete", "room"}` | `{"type":"info", "message": "room deleted", "room"}` — **delete a room outright**: purges its events from the stream (skeletons + bodies + blobs), drops all server state (record, memberships, invites, mods, kicked, join requests, the live room + any historian/consumer). **Private rooms only** (a published/public room is append-only and can't be un-spoken); **inboxes excluded** (use `clear_history`). **Sponsor only**, *except* a **2-person room** (e.g. a DM) where **either participant** may delete. **Recursive:** deleting a room deletes its whole subtree (subrooms, their subrooms, …) — the policy gate applies to the root; descendants cascade regardless of their own sponsor. Other members of any deleted room get a `room_deleted` push **and** a durable inbox `notification`, so their client purges its local fold. Irreversible |

### 4.3 The skeleton/body event model

Messages are split at publish time. The room's event stream
carries only tiny **skeleton** events — id, optional `parent` (threading),
author, timestamp, **no text** — while each message's content lives on a
per-message body subject, fetched on demand with `bodies` (max 50 ids per
request; unknown ids are silently omitted from the reply).

Event frames (delivered after `history` or `sync`); `ts` is integer
milliseconds, `commit`/`sig` are defined in §7b. Cleartext form (public
rooms, control messages):

```json
{"type":"message", "id":"<hex32>", "parent":"<hex32>"|null, "room":"r",
 "name":"alice", "ts": 1781234567890, "seq": 42,
 "commit":"<hex>", "sig":"<hex>"}
{"type":"vote", "id":"<message id>", "room":"r", "voter":"bob", "vote":"up",
 "ts": 1781234570010, "seq": 43, "sig":"<hex>"}
```

Notification frames (delivered when syncing a inbox): `{"type":
"notification", "id", "room", "seq", "action", "ref_room", "by", "ts",
"msg_id"?}` where `action` is one of
`invited`/`kicked`/`mod_granted`/`mod_revoked`/`sponsor_granted`/`mentioned`/
`contact_request`/`contact_accepted`/`published` (`msg_id` is set for mentions; `ref_room` is
the DM room for `contact_accepted`, the room for `published`). These are
unsigned cleartext system
events, folded into the client's notification store. **Privacy note**: a
mention in a private room reveals the mention edge (who mentioned whom, in
which room) to the server, since the client must name the targets for
routing — the message *content* stays sealed, but the mention graph does
not. Clients that prefer full privacy can skip the `mention` op in private
rooms (forgoing offline mention delivery) and detect `@self` locally
instead.

Sealed form (private rooms, §7a): the same fields, but everything except
`kind`/`id`/`room`/`seq` is encrypted into `meta`. Clients decrypt `meta`
to reconstruct the cleartext frame above before folding:

```json
{"type":"message", "id":"<hex32>", "room":"r", "enc":1, "seq":42,
 "meta":"v1:…"}    // meta opens to {parent,name,ts,commit,sig}
{"type":"vote", "id":"<random hex32>", "room":"r", "enc":1, "seq":43,
 "meta":"v1:…"}    // meta opens to {target,voter,vote,ts,sig}
```

History message objects have the same shape plus folded vote state
(`votes`, `voters`). **No history or event frame ever carries message
text** — hydrate via `bodies`.

**Blob messages (a client convention).** Binary content (images, video,
long articles) is posted as a normal message whose body text is a small JSON
descriptor prefixed by `BLOB_PREFIX` — `{_pm_blob, mime, size, blob_id, hash,
enc, epoch, caption, tier}` — signed/committed like any message; the bytes live
in the object store under `blob_id` (ciphertext in private rooms). The descriptor
is sealed in private rooms, so the server sees only the opaque `blob_id`.
**Canonical serialization (normative — both clients match):** because the
descriptor body is what gets `commit`ted (franked, §7b), it must be byte-identical
across clients for the same logical post — the structured analog of
`normalize_pcm`. The body is `BLOB_PREFIX` + **canonical JSON**: keys **sorted**,
**no whitespace**, **raw UTF-8** (non-ASCII unescaped), and numeric fields kept as
**ints** (no floats — they serialize differently across languages). Python:
`wire.blob_descriptor_body` / `wire.canonical_json`; Dart: `_canonicalJson`
(sorted keys + `jsonEncode`). Golden vectors: `tests/test_blob_descriptor.py`. For
images it also carries an **inline preview** (generated client-side at upload —
the server can't, being blind to private pixels): `w`/`h`, an `avg_color`
placeholder, a **`blurhash`**, and a downscaled `thumb_blob_id` (+ `thumb_hash`/
`thumb_size`/`thumb_mime`/`thumb_tier`) — a separate same-key-encrypted blob.
Viewers fetch the thumbnail for display (batchable via `content_get_batch`) and the
full `blob_id` only on demand; no thumb ⇒ fall back to the full. Field contract +
client guidance in FLUTTER_TODO.

**Every image upload MUST carry a valid `blurhash`** (mime `image/*`) — so a viewer
always has an instant placeholder, and as a forge-resistant gate on media bodies.
`wire.blurhash_valid` is the shared structural check (no decode): the base83
charset; the length⇔component checksum the first character dictates
(`len == 4 + 2·numX·numY`, size flags 0–80); and the DC term (chars 2–5) being a
real 24-bit RGB (`< 2**24`). Enforced at **two points**: the server rejects a
public/cleartext image body whose `blurhash` is absent or malformed
(`"image uploads require a valid blurhash"`); and the client refuses to upload an
image it can't generate a valid blurhash for — the *only* enforcement in **private
rooms**, whose descriptor is sealed and so unreadable to the server. Non-image
blobs need no blurhash.

**Image moderation — quarantine until vetted** (optional; on when the server has
`CHAT_MODERATION_URL` set — see server/moderation.py). When a PUBLIC image post is
published, its full blob *and* its thumbnail are **quarantined** and the server
hands the full image to an external moderation service
([postmodern-imagemod](../postmodern-imagemod/API.md)) — `POST /scan` then poll
`GET /scan/{job_id}`. The blurhash rides the (cleartext) descriptor and renders
instantly, so a viewer sees the placeholder immediately while the bytes wait. Until
the verdict lands, `content_get`/`content_get_batch` return
`{blob_id, quarantined:true}` (no `data`) and `content_url` returns `url:null,
quarantined:true` — the client keeps showing the blurhash and retries. Outcomes:
**clear** → bytes serve normally; **reject** (failed the scan) and **unverified**
(no verdict before the TTL — e.g. the service was down past the retry window) →
bytes deleted and the fetch returns `{blob_id, removed:true, reason:"rejected"|
"unverified"}`. A scan that just *errors* (service unreachable) leaves the blob
quarantined; a janitor periodically **re-scans** it (so a transient outage
recovers) and, past `CHAT_MODERATION_QUARANTINE_TTL`, gives up (delete + mark
unverified) so nothing unvetted lingers. The image is handed to the scanner **by a
presigned object-store URL** when the backend can presign (bytes go store →
scanner, never through the chat server), else by direct upload. Scope is public
images only: a **private** room's bytes are E2E-encrypted, so the server can't scan
them (and the firewall forbids shipping plaintext) — private images are never
quarantined. With moderation off (default), nothing is quarantined. Reference
client raises the typed `ContentQuarantined` (keep the blurhash, retry) vs
`ContentRemoved(reason)` (bytes gone — show removed/unavailable, don't retry). In
dev, postmodern-imagemod/dummy_server.py stands in for the real ML pipeline
(waits ~1s, then passes); `bash scripts/dev.sh` launches it when `MOD_DUMMY=1`.

**`sync` is the client-side-fold feed**: the client states the last stream
seq it has folded (`since`, omit or 0 for everything); the server replies
`synced` with `upto` — the room's latest seq at that moment, the caught-up
marker — then delivers every skeleton/vote event after `since` as one
ordered feed, backlog flowing seamlessly into live. The recommended client
loop: ingest events into a local fold (see §5a), treat `fold.last_seq >=
upto` as caught-up, render the last N messages, hydrate only the bodies
you display. `sync` and `history` both (re)start live delivery; use one or
the other per join.

### 4.4 Contact discovery (graph-private)

Two people who each saved the other's phone number connect automatically, and the
server never learns the social graph. Full design + threat model: `DISCOVERY.md`.
Client crypto: `client/discovery.py`. The construction: the number is only an
**index**; the rendezvous secret is a static-static X25519 DH
`s_AB = DH(privA,pubB) = DH(privB,pubA)` the server can't compute, from which a
`mailbox_id`, `channel_id`, and `chan_key` are derived by domain-separated HKDF.

All hex fields below are 32 bytes (64 hex chars). Number normalization: strip
whitespace (normalize to E.164 upstream); `number_hash` is a domain-separated
SHA-256 (`client/discovery.py::number_hash`).

**`directory_publish`** — *authed* (profile plane). Publish your account's static
registration pubkey under a number hash you control. The server knowing
`number_hash → pubkey` is in-scope; the *graph* is what stays hidden.
```json
{"type":"directory_publish", "number_hash":"<hex>", "disc_pub":"<hex>"}
-> {"type":"directory_published", "number_hash":"<hex>"}
```

**`directory_snapshot`** — *session-less*. The whole directory, so the client
resolves its contacts **locally** and the server never learns which numbers it
looked up. (Full-sync while small; OPRF/PIR later — DISCOVERY.md §5.)
```json
{"type":"directory_snapshot"}
-> {"type":"directory", "entries":[{"number_hash":"<hex>","disc_pub":"<hex>"}, …]}
```

**`knock`** — *session-less* (send it over a **separate, unauthenticated**
connection so it's account-unlinkable — DISCOVERY.md §6). Deposit a rendezvous
knock; the reply says whether the mailbox is now mutually matched (≥2 distinct
nullifiers). `credential` is the anti-Sybil "valid human" proof — a **blind-RSA
anonymous knock token** `"<id hex>:<sig hex>"` (from `anon_token_issue`, DISCOVERY.md §6b). The server verifies it with the issuer **public** key
(it can't mint) and spends its nullifier **once**, so each token knocks a single
time. Unlinkable to the account and to other knocks. Errors: `invalid knock
credential`, `knock credential already used`.
```json
{"type":"knock", "mailbox_id":"<hex>", "nullifier":"<hex>", "credential":"<id hex>:<sig hex>"}
-> {"type":"knocked", "mailbox_id":"<hex>", "matched": true|false}
```

**`knock_poll`** — *session-less*. Which of your pending mailboxes have matched
(≤500 per call).
```json
{"type":"knock_poll", "mailbox_ids":["<hex>", …]}
-> {"type":"knock_matches", "matched":["<hex>", …]}
```

**`channel_post` / `channel_fetch`** — *session-less*. The rendezvous channel for
the post-match handoff (MESSAGING.md §4): the two parties exchange a `chan_key`-
sealed intro keyed by `channel_id` (unguessable, so only they can reach it; payload
opaque, ≤4096 b64 bytes; `item_id` is a server-computed content hash, so re-posts
dedup).
```json
{"type":"channel_post", "channel_id":"<hex>", "payload":"<b64 sealed>"}
-> {"type":"channel_posted", "channel_id":"<hex>"}
{"type":"channel_fetch", "channel_id":"<hex>"}
-> {"type":"channel", "items":["<b64 sealed>", …]}
```

**Client flow:** `register_discovery(number)` once (publishes your key);
`sync_directory()` then `discover(number)` for each saved contact (derives the
mailbox, knocks); `poll_discovery()` to surface matches; `handoff()` to turn each
match into a DM. The handoff sets the DM up as an **ordinary 2-member private
room** (§7a) — intro+pin `enc_pub` over the channel, then epoch-0 via the standard
`inv1` path. No DM-specific crypto. See DISCOVERY.md §7 / MESSAGING.md §4.

## 5. Semantics clients must implement correctly

- **`sync`/`history` is the live-delivery switch.** After `join`, no live
  frames flow until the client requests `sync` (any room) or `history`
  (public rooms). Both return a consistent snapshot / catch-up point; live
  delivery then starts right after it. No gaps, no duplicates: a client
  folds the snapshot then appends live frames, period.
- **Re-requesting `history`** mid-session returns the full current snapshot
  (which includes messages already seen live) and re-syncs live delivery
  after it. `sync` is instead incremental — pass the highest folded `seq`
  as `since` and only newer events arrive.
- **`limit`** is clamped server-side to 0–500 (default 500; non-numeric
  values fall back to the default), counting most-recent messages. When the
  snapshot is empty — empty room *or* `limit: 0` — live delivery starts
  from the **beginning of the room**, replaying everything as live frames.
- **Vote folding** (matches server behavior; required of any folding
  client): one vote per voter per message, the **latest by stream `seq`
  wins**. A client verifies each vote's `sig` against the voter's pinned key
  (§7b) and counts only verified votes — so keep every signed vote event and
  apply latest-wins *after* verification, never collapse on receipt (a
  forged later vote must not displace a real one). Votes referencing unknown
  message ids are dropped.
- **(§5a) Client-side fold contract**: ingest every `message`/`vote` event
  keyed by stream `seq`; ingestion must be idempotent (events can be seen
  twice across reconnects — dedupe messages by `id`, votes by `(id, voter,
  seq)`). Persist the highest seq seen per room and pass it as `since` on the
  next `sync` for incremental catch-up. Because votes always follow their
  message in stream order and the feed always extends to the present, any
  suffix window has complete tallies for every message in it. The reference
  implementation is `client/client_fold.py` (`ClientFold`).
- **Parents are unvalidated references**: the server checks only the id
  format, not existence — render unknown parents as orphans, don't error.
- **`seq`** is the JetStream stream sequence: globally increasing across
  all rooms, strictly increasing within a room. Use it for ordering and
  sync, not for counting.
- **Room names**: a room has one **global** name (unique, used everywhere on
  the wire — routing, membership, the stream) and an optional per-user
  **display name** (client-side, in the blob under `room_names`). Display
  defaults: a DM shows the other contact's profile name; everything else
  (including inboxes, whose global name `<profile>_inbox` is already
  unique and meaningful) shows the global name until the user renames it.
  Display names never reach the server; clients resolve them back to the
  global name for any op. Resolution is **alias-first**: your own name wins —
  a typed name matching one of your display aliases (or a contact's name)
  resolves to *that* room, even if some unrelated global room shares the
  name, because the alias is what you call your room. To reach a colliding
  global room, skip resolution and use its literal global name (the CLI
  exposes this as `/join --global <name>`).
- **Last-seen watermark** is a client concern (no server op): each client
  keeps a per-room read marker in the blob (`blob.seen[<profile>][<room>] =
  seq`), advanced when you leave/switch rooms. On re-entry the client draws a
  "new messages" divider at that seq — a single watermark, not per-message
  read state. It lives in the blob, so it follows you across devices.
- **Contacts** live in clients' encrypted blobs (`blob.contacts[<profile>]`),
  so the contact *list* is private to the user. The handshake is
  client-driven over inbox notifications: A `contact request`s B → B sees
  it (`contact_request` in their inbox) → B `add_contact(A)` accepts,
  creating a private DM room (`kind="dm"`) with both as members and notifying
  A (`contact_accepted` carrying the room). The server only routes the
  notices and hosts the room — it never holds the contact list, though the
  resulting room membership reveals the pair (as any shared room would).
  `kind="dm"` on the room lets clients filter contact rooms.
- **Room classes** (`kind` in the `joined`/`rooms` frames): `room`
  (standard), `inbox` (a profile's notification inbox), `dm` (a contact 1:1 room),
  `board` (a feed of posts), `comments` (a post's discussion room). Standard rooms
  are the default. `inbox` is auto-created at profile claim, server-reserved by
  name suffix, and not deletable. **`board` is server-only**: clients can't create
  boards (`room_create` with `kind:"board"` is rejected) — there is one shared
  public board, `bigboard` (`wire.BIGBOARD`), auto-created at server startup and
  reserved from users, that all posts go to (one board until traffic warrants
  sub-category boards). A top-level message is a *post* only in a `board`; the
  reference client's `Message.is_post` factors in the room kind (`is_top_level`
  is the structural test alone). Reference client: `bigboard()` joins it.
- **Posts & comments.** A post is a parentless message in a `board`. When one is
  published (public board, parent absent), the server **auto-creates a comment
  room** `post-<post id>` (`kind="comments"`, sponsored by the poster) — the
  post's distinct discussion locus, so comments don't clutter the feed. Any
  client derives it from the post id (`wire.post_room`). Comments are messages
  in that room (threaded via `parent` like any room). Reference client:
  `post(text)`, `comment(post, text, parent?, *, image?, mime?)`, `post_room(post)`.
  Each post object in **`feed`** and **`ranked`** (and `history`/`sync`) carries
  **`comment_count`** — the number of message frames in its `post-<id>` room — so a
  "N comments — dive in" footer renders without a per-post fan-out. Computed with
  one grouped query per page; approximate/eventually-consistent (a UI hint). It's
  0 for a message with no comment room (a non-post / a comment itself).
  A comment can carry **both an image and text** (mixed media): pass `image`+`mime`
  and the `text` rides along as the blob descriptor's `caption` (one media message,
  not two), so it renders as a `blob` message whose `text` is the caption. Same
  mechanism for any room message — a blob descriptor always has a `caption` slot.
- **Link posts** (post type **`link`**, Reddit-style): a `title` + a `url`. The body
  is a `PMBLOB1:` descriptor `{link, title, caption, thumb_blob_id, thumb_mime}` whose
  **`caption` is a PCM masked link** `[title](url)` (so it renders `title (domain)`
  like any link). The client uploads NO image; instead the **server unfurls** it —
  on publish (public board) it fetches the target's `og:image` — falling back to
  the page's **favicon** (apple-touch-icon → `<link rel=icon>` → `/favicon.ico`) when
  there's no preview image — downscales it to a JPEG, and stores it at
  **`thumb_blob_id`** in the object store. Viewers load that
  one reliable, cached preview via the normal `content_get`/`fetch_thumbnail` (no
  client ever hits the link). The fetch is SSRF-guarded (http(s) only; hosts must
  resolve to public IPs unless an allowlist is set) and size/timeout-capped; a
  failed unfurl just yields no thumbnail (the masked link still renders). Off via
  `CHAT_LINK_UNFURL=0`. Reference client: `post_link(url, title)`; the message folds
  as `kind: "link"` with `link`/`title` and the caption as `text`.
- **Deleting** a post/comment (`delete_message`; author or room mod/sponsor) leaves
  a **tombstone**: the message stays in history with **`deleted: true`** (+
  `deleted_by`) but its body is purged. Clients render a "post/comment deleted"
  stub — the message keeps its `id`/`parent`/`ts`/tallies so the thread structure
  (and any replies under a deleted comment) still renders; reference client:
  `delete_message(id)`, and `messages()`/`ranked_page()` return the stub with
  `deleted=True` and empty `text`.
- **Threading** is entirely client-side, built from the `parent` edge every
  message already carries. The room's `thread_style` (in the `joined` frame,
  `"flat"` or `"tree"`) is the sponsor's *suggestion* of how to render — clients
  may honor it or let the user choose, since both views are just renderings of the
  same parent-linked graph. **A post's `post-<id>` comment room defaults to
  `"tree"`** (comments are threaded by nature); every other room kind defaults to
  `"flat"`. Either is overridable via `room_style`. Flat = chronological with
  a quote of the replied-to message; tree = replies nested under their
  parent (siblings in seq order, a reply to a missing parent renders as a
  root). The reference client's `build_thread()` does the tree assembly.
- **Ranking & thresholds** are likewise client-side. The `joined` frame's
  `sort_mode` (`new`/`top`/`best`) and `threshold` (int or `null`) are mod
  *suggestions*; `present_view()` applies them and `client.view(...)` lets a
  reader override per-session. `best` is the Wilson 95% lower bound
  (`wilson_score`), `top` is net up−down. A threshold hides replies below the
  given net score (in tree view, the whole subtree), returning a hidden-count
  the client can show abbreviated. The `vote_limit` field is different: it is
  a sponsor-set, *enforced* per-message tally cap (clamped by both the
  historian and the live fold), so it is **not** overridable.
- **`members`** in `joined` is the persisted **membership** roster (the
  profiles who have joined) — *not* who is currently present, and it does
  not include the `historian`. There is no live "present" list.
- **Clearing history**: `clear_history` purges a room's events from the
  stream. For now it's allowed only on **inboxes**, by their sponsor (a user
  emptying their own notification inbox). Clients should drop their local
  fold for the room afterward.
- **Deleting a room**: `room_delete` removes a room entirely (events + all
  server state), as opposed to `leave` (just your membership) or the in-memory
  idle eviction (transparent; the room is recreated on next join). It's the
  only true delete. **Private rooms only**, **inboxes excluded**, **sponsor
  only** except a **2-person room** (DM) where either side may delete. The
  rest of the room's members are notified (`room_deleted` push + durable inbox
  note) so they can purge their local fold. Irreversible: a published/public
  room can't be deleted, in keeping with the append-only model.
- **Membership vs. presence**: `join` makes the profile a *member* of the
  room (persistent, server-side) and connects the live view. Switching to
  another room with `join` disconnects the view but keeps the membership;
  only `leave` removes it. `rooms` lists memberships, not presence.
- **Rooms must be created before they're joined** — `join` on an unknown
  name errors ("no such room — create it first"). `room_create` defaults to
  **private**: invite-only and end-to-end encrypted, joinable only by the
  sponsor, mods, and invited profiles. A public room (`private: false`) is
  open to anyone by name. Invites persist, so leaving a private room doesn't
  revoke re-entry — only `kick` does.
- **Publishing (private → public, one-way)**: the sponsor may `room_publish`
  to open a private room. It records `public_from` = the room's current seq.
  From then on the room is open by name, but a new (non-member) joiner's
  access floor is `public_from` — they read only from publication onward.
  Pre-publish members (who hold the room key) keep reading the encrypted
  prefix; new content is published cleartext. A published room keeps **no
  historian** (its encrypted prefix can't be folded server-side), so use
  `sync`. There is no reverse op.
- **Roles**: the *sponsor* (creator) is a special case of *mod* and can
  grant/revoke mod. Mods invite and kick. Role state arrives in the
  `joined` frame (`sponsor`, `mods`).
- **Join policy** (private rooms; in the `joined` frame as `join_policy`):
  `"open"` (default) lets a non-member `request_join`, which notifies the
  room's connected members so a mod can approve by inviting; `"invite"`
  rejects requests (mods add only — stops request spam). Mods set it with
  `room_policy`.
- **Unsolicited push frames** — not replies; a client must dispatch by
  `type` and not treat them as RPC answers:
  - `{"type":"join_request", "room", "name"}` — to room members when someone
    requests to join.
  - `{"type":"invited_you", "room", "by"}` — to the invitee (wherever
    they're connected) when a mod invites/approves them.
  - `{"type":"mod_action", "room", "action", "by", "name"}` — to room
    members for every mod action (invite, kick, mod_grant, mod_revoke,
    publish, policy_*), so moderation is transparent.
  - `{"type":"you_were_kicked", "room", "by"}` — to every connection of a
    kicked profile (whether or not they were present in the room).
  - `{"type":"room_deleted", "room", "by"}` — to every connection of each
    other member when a room is deleted (`room_delete`). The client must
    purge its local fold for the room (and drop a now-dead DM contact); a
    durable inbox `notification` (`action:"room_deleted"`) covers members
    who were offline. *(The deleter gets a plain `info` ack instead, so the
    push type can't collide with reply correlation.)*
- **History floor**: an invite's `from_seq` is the lowest stream seq that
  member may read (0 = full history). `sync` clamps `since` to the floor
  and reports it in the `synced` frame (`floor`); clients must advance
  their fold's sync position to the floor, since earlier events will never
  arrive. Sponsor and mods always have floor 0. (Under E2EE the same flag
  becomes key-enforced: past epoch keys handed over, or not.)
- **Historian only for born-public rooms.** The server keeps a
  historian-backed index (and the `history` op) only for rooms *created*
  public. Private rooms — and rooms published from private (which have an
  encrypted prefix the server can't fold) — keep no historian; their history
  is the event stream, consumed via `sync` + `bodies` and folded
  client-side. The `history` op errors ("use sync") whenever there's no
  historian.
- After profile auth a connection is in no room; `join` is required before
  any chat operation.

## 6. Validation rules (server-enforced; mirror them client-side for UX)

| field | rule |
|---|---|
| account id | `[a-zA-Z0-9_-]{1,64}` |
| profile name | `[a-zA-Z0-9_-]{1,32}`, not `historian`, not `*-inbox`, **not a reserved system handle** (admin/support/system/… → `profile name is reserved`; operator-editable `server/reserved_names.txt`), **not a server-bot handle** unless `bot_secret` matches (`CHAT_WELCOME_BOT`/`CHAT_SERVER_BOTS` → `profile name is reserved`), and **not on the profanity/slur blocklist** (server-side; leet- and embedding-aware → `profile name not allowed`) |
| room name | `[a-zA-Z0-9_-]{1,64}` |
| message text | 1–4096 chars |
| display name | ≤ 64 bytes (UTF-8) |
| bio | ≤ 500 bytes (UTF-8) |
| small avatar | base64 of ≤ 16384 bytes (decoded); larger ⇒ use `avatar_upload` |
| large avatar (`avatar_upload`) | base64 of ≤ 4 MiB (decoded) |
| avatar_url | string ≤ 1024 chars |
| email | `[^@\s]+@[^@\s]+\.[^@\s]+`, ≤ 254 chars (account plane; real check is the verification round-trip) |
| billing | JSON object |
| salt / authkey / pubkeys | hex, exactly 16 / 32 / 32 bytes |

## 7. Canonical flows

### First run (new account + first profile)

```
account ws:  account_login {account}          -> error (unknown)
             [generate salt, derive keys]
             account_create {account,salt,authkey} -> account_created
             voucher_get                      -> voucher
profile ws:  profile_claim {name,voucher,pubs} -> profile_claimed
account ws:  blob_put {sealed blob, version:1} -> blob_saved
profile ws:  profile_challenge {name}         -> challenge
             profile_auth {name,signature}    -> profile_authenticated
             join {room}                      -> joined
             history {}                       -> history; live frames begin
```

### Returning device / new device (recovery)

```
account ws:  account_login {account}          -> account_salt
             [derive keys from password+salt]
             account_auth {account,authkey}   -> account_authenticated (blob!)
             [decrypt blob -> profile seeds]
profile ws:  profile_challenge / profile_auth -> authenticated
             join + history                   -> chatting again
```

No local state is required beyond the account id and password.

### Adding a second profile to an existing account

```
account ws:  voucher_get                      -> voucher
profile ws2: profile_claim                    -> profile_claimed
account ws:  blob_put {version: current+1}    -> blob_saved
             (on conflict: blob_get, merge profile in, retry)
```

## 7a. Room encryption (private rooms, zero-trust)

Private rooms are end-to-end encrypted by the clients; the server stores and
relays ciphertext it cannot read. This is entirely a client concern — no
server op is encryption-aware — but clients must agree on the formats so
they interoperate (the Python and Flutter reference clients do).

- **Sealed skeletons (private rooms)**: a regular message/vote in a private
  room is published with `enc: 1` and a single encrypted `meta` blob; the
  server sees only `kind`, the room, the stream `seq`, and a cleartext `id`
  (a random handle it needs to address the body). Everything else —
  author `did` (+ advisory `name`), `parent` (threading), `ts`, `commit`,
  `sig`, and for votes the target/voter/direction — is inside `meta`, sealed
  under the room epoch key. Bodies carry only ciphertext. A member without the key sees
  nothing (events park as pending and decrypt when a key arrives); the
  server can produce no readable metadata even under compromise. Control
  messages (knock/invite) stay cleartext — they bootstrap the key — and so
  do all events in public rooms (the historian needs them).
- **Cipher**: XChaCha20-Poly1305 (libsodium AEAD), one symmetric key per
  room *epoch*. Message text on the wire is:
  - `v1:base64(nonce ‖ ciphertext)` — epoch 0 (Flutter-compatible)
  - `v2:<epoch>:base64(nonce ‖ ciphertext)` — later epochs
  Text without a known prefix is treated as plaintext (public rooms).
- **Key storage & recovery**: epoch keys live in the account blob under
  `room_keys[<room>] = {epochs: {<n>: base64key}, current: <n>}`, so
  account + password recovers them on any device. (A native client may also
  cache them in platform secure storage.)
- **Key distribution** rides the normal message relay as control messages
  (the server can't distinguish them from chat):
  - `pk1:<identity_pub_b64>` — a *knock*: announces the sender's X25519
    identity key, asking a member to share the room key.
  - `inv1:<recipient>:<sealed_b64>` — the raw epoch-0 key, sealed (libsodium
    sealed box) to the recipient's identity key (Flutter-compatible).
  - `inv2:<recipient>:<sealed_b64>` — sealed JSON `{room, epochs, current}`
    for multi-epoch shares.
  Clients filter these out of the displayed message list, along with a
  hidden `room-claim` marker used to seed a new room with ciphertext.
- **Identity keys**: a profile's X25519 `enc_pub` (registered at claim,
  fetch via `profile_info`) is where room keys are sealed. Clients TOFU-pin
  the keys they seal to (stored in the blob under `pins`); a changed key is
  refused until explicitly re-pinned — this defends against a malicious
  server swapping a registered key.
- **Epochs and the history floor**: rotating the key (new epoch, re-shared
  to current members) makes removal cryptographic — a kicked member lacks
  the new epoch. Adding a member "from now" rotates first and shares only
  the new epoch, so the server-enforced history floor (§5 `from_seq`) is
  also key-enforced. Adding "from start" shares all epochs.
- **Departure always rotates**: a member dropped from the ACL is re-keyed out,
  always (independent of the proactive policy). `kick` rotates immediately
  (the kicker re-shares to the remaining members). For a permanent voluntary
  departure (`self_kick`/"unsubscribe"), the **sponsor** re-keys — on the
  `departed` notice while online, and on its next join via a roster diff
  (recorded key-holders − current invitees), which also catches departures that
  happened while the sponsor was away. The diff is against the **invitees (ACL)**,
  not the joined roster, so a routine `leave` (re-joinable step-out, keeps the
  invite) does **not** rotate — only true ACL removal does.
- **Proactive rotation (policy, on by default)**: besides removal, the room's
  **sponsor** rotates the epoch once the current one is too old or has carried too
  many messages (`maybe_rotate_room_key()`, called on send and on join;
  sponsor-only so two members can't fork the epoch). Defaults are sane and
  unaggressive (`rotate_after_secs` ≈ 1 week, `rotate_after_msgs` = 500); set
  either to `None` to disable. Old epochs are **retained**, so history stays
  decryptable — this bounds a key's exposure window and gives a natural point to
  adopt a new cipher (crypto-agility); it is **not** forward secrecy (that would
  require discarding old keys, which would break the replayable-history posture —
  MESSAGING.md §1).

## 7b. Signed events and franking-ready commitments

Every message and vote is signed by the sender's ed25519 profile key.
**Authorship-by-signature (v2): the author is NOT in the
signed bytes — the signing key IS the author.** The signature covers content
only; the author is the **`did:key`** of whichever key signed (self-certifying),
so name-spoofing is structurally impossible. The *client* assigns `id` (16 random
bytes hex) and `ts` (integer ms), computes a content `commit`, and signs; the
server stamps **`did`** = the authenticated profile's DID **and** `name` = its
current advisory handle, verifies, then publishes. Recipients verify
independently (the real guarantee).

- **Canonical signing payload** (`wire.py`), fields joined by `\x1f`. v2 dropped
  the author field from all four (it shrank, and the tag bumped `v1`→`v2`):
  - message: `"pm-msg-v2" ⋮ id ⋮ room ⋮ parent|"" ⋮ str(ts_ms) ⋮ commit` —
    **append `⋮ post` only when `post` is set** (a non-empty type). Plain
    messages omit it. When set, the type is bound by the signature.
  - vote: `"pm-vote-v2" ⋮ id ⋮ room ⋮ vote ⋮ str(ts_ms)`
  - reaction: `"pm-react-v2" ⋮ room ⋮ target ⋮ emoji ⋮ op ⋮ str(ts_ms)`
  - pollvote: `"pm-pollvote-v2" ⋮ room ⋮ poll_id ⋮ str(choice) ⋮ str(ts_ms)`
  `sig` is the detached ed25519 signature, hex. Every event frame (and the
  sealed `meta` in private rooms) carries the author's **`did`**; verify the sig
  against that DID's key (`did:key` decodes directly to the ed25519 `sign_pub` —
  no lookup needed). The advisory `name`/`voter`/`reactor` is then bound to the
  DID via the client's **TOFU pin** (`did_key(pinned_key_for_name) == did`), so a
  server can't relabel a real event under another handle.
- **Vote verification** works the same way: each vote carries `did` + `sig` over
  its canonical (content-only) payload. A folding client counts only votes whose
  signature verifies against the voter's DID key (and whose advisory handle binds
  to that DID), and (because forged votes must not displace real ones) keeps every
  signed vote event, applying latest-wins **after** verification, ordered by
  stream `seq`. A vote a client can't verify is simply not counted.
- **`commit`** binds the separately-fetched body to the signed skeleton, so
  a substituted body is detected. It is computed two ways:
  - encrypted message: `commit = blake2b(key=fk, plaintext)` (raw → 64 hex)
    where the per-message franking key `fk = blake2b(key=epoch_key, "frank:"+id)`.
  - plaintext message (public room, control message):
    `commit = blake2b("public:"+text)`.
  Authorship (`sig`) is verifiable even without the room key; the body
  binding additionally needs the key (to recompute `fk`).
  > **Encoding quirk (normative — both clients match):** the public `commit` and
  > the blob-descriptor `hash` are **double-hex-encoded** (128 chars): the
  > reference computes `blake2b(...).hex()` where PyNaCl's `blake2b` already
  > hex-encodes, so `.hex()` re-encodes. The encrypted `commit`/`fk` (RawEncoder)
  > are plain 64-hex. This is a known wart, not a bug — the Flutter client
  > replicates it for byte compatibility; **don't "normalize" one side alone.**
- **Franking (implemented — the `report` op).** Because `commit` opens to the
  plaintext under a *per-message* key carried only to room members, a member of a
  PRIVATE room can report one message — proving *what* was sent and *who* sent it —
  without exposing the room key or any other message. The author's existing `sig`
  over `commit` (their DID **is** the verify key) supplies authorship, so **no
  event wire change** was needed.
  - **Op:** `{"type":"report", "room", "id", "plaintext", "fk", "commit", "sig",
    "reportee_did", "parent", "ts", "post", "image_b64"?}` → `{"type":"reported", "id"}`.
    The reporter (a member; `messages()` gives them `commit`/`sig`/`did`) reveals only
    this message's `plaintext` + franking key `fk` (recovered by trying its epoch keys
    until one reproduces `commit` — survives rotation).
  - **Server verifies, zero trusted state:** the room is private; `(id, room)` is a
    real event in the blind `enc_events` fold; `open_commitment(commit, fk,
    plaintext)` (WHAT); and `verify_event(did_to_sign_pub(reportee_did),
    message_signing_bytes(id, room, parent, ts, commit, post), sig)` (WHO). A swapped
    plaintext/fk breaks the commitment; a forged commit breaks the signature — so a
    reporter can only ever surface a message the reportee *actually authored*.
  - **Images (the primary case) — first-class.** For a media message the committed
    `plaintext` is the blob **descriptor** (`BLOB_PREFIX` + canonical JSON), *not* the
    caption. Since the bytes are sealed under a room key the mod lacks, the reporter
    also sends **`image_b64`** = the decrypted image; the server binds it with
    **`hash_bytes(image_b64) == descriptor.hash`** (the proof already covers the
    descriptor, so a reporter can't swap in a different picture), stores it cleartext
    in the review room, and authors a **blob message** there so the mod sees the
    actual image inline. Text reports omit `image_b64`.
  - **Same code for any N:** a DM (N=2) and a group room are identical — the handler
    keys only on "room is private" + the proof.
  - **Self-report rejected:** you can't report your own message (`reportee_did ==`
    your DID → error). Duplicate reports of one message are **not** deduped —
    multiple reports are signal.
  - **Where it lands:** every verified report is server-authored (cleartext) into the
    shared review room **`wire.FRANKING_REPORTS_ROOM`** (`"franking-reports"`,
    `kind="modreview"`, invite-only, members = the `SYSTEM_MODS`) for human review —
    a **text** report carries content+reporter+reportee; an **image** report is a
    viewable blob entry whose caption carries the same. Reporter + reportee are
    written as canonical **`@[handle](did)`** mention tokens (tappable profile links
    in the client) and a **`room:`** line gives the sealed source room's NAME (an
    identifier a mod can act on — still no permalink to the private body). Off via
    `CHAT_FRANKING_REVIEW=0` (the op still verifies; it just files nowhere).
    Advertised via the **`report`** `hello` feature.

## 7c. Verifiable Credentials & Presentations

Both token formats live in `wire.py` (mirror byte-exact in every client). A
**Verifiable Credential (VC)** is an issuer-signed, DID-bound attestation; a
**Verifiable Presentation (VP)** is a holder-signed bundle of chosen VCs. For the
humanness rungs, the VC issuer is the **chat plane** (`VC_ISSUER_PUBKEY`): it
re-issues a DID-bound VC at `profile_attest` after verifying the account plane's
*unlinkable bearer* humanness token — so the DID binding never reaches the account
(the account↔profile firewall).

- **VC token** — `\x1f`-joined `iss ⋮ sub ⋮ typ ⋮ iat ⋮ exp ⋮ nonce ⋮ sig`.
  `iss` = issuer ed25519 pubkey hex (= the verifying key); `sub` = subject DID;
  `typ` = badge slug (`irl`/`email`); `iat`/`exp` unix secs (`exp` 0 = none);
  `nonce` = single-use id. `sig` = issuer's ed25519 over
  `_join("pm-vc-v1", iss, sub, typ, str(iat), str(exp), nonce)`. Verify: sig valid,
  `iss` trusted, not expired; caller enforces `sub` and `typ`.
- **VP token** — `\x1e`-joined (record separator, since VCs use `\x1f`):
  `"pm-vp-v1" ⋮ holder_did ⋮ audience ⋮ created ⋮ sig ⋮ vc1 ⋮ vc2 …`. `sig` =
  the **holder's** ed25519 (its DID key) over
  `_join("pm-vp-v1", holder_did, audience, str(created), *vc_tokens)`. Verify: holder
  sig valid (proves control of the subject), `audience` matches, `created` fresh
  (default ±300s), and every VC verifies against a trusted issuer **with `sub` ==
  `holder_did`**. Selective disclosure = the holder chooses which VCs to include.
  The DID is revealed (linkable); anonymous presentation (Phase 4) hides it.
- **Anonymous knock token (Phase 4) — REAL, blind RSA.** `wire.anontoken_*` (FDH
  Chaum blind RSA): the discovery anti-Sybil knock credential (DISCOVERY.md §6b).
  Issuance is **blinded** (`anon_token_issue`): the client blinds a random 32-byte
  token id with the issuer public key `(n,e)`, the account blind-signs, the client
  unblinds → a signature on the id. Redeemed token wire form: `"<id hex>:<sig hex>"`;
  verify `sig^e mod n == FDH(id)` (full-domain hash = `MGF1-SHA256("pm-anontok-v1"⋮id)`
  over `|n|+16` bytes, mod n). **Publicly verifiable** (verifier holds only `(n,e)` →
  can't mint), unlinkable (issuer only ever saw the blinded value), one-time (the id
  is the nullifier, deduped). SECURITY-CRITICAL; mirror byte-for-byte; needs a crypto
  review. `anoncred.KNOCK_UNLINKABLE = True`.
- **Anonymous *presentation* of an identity rung (Phase 4) — still seamed.** The
  credential-gate path (`anoncred.verify_rung_proof`) is **not** yet unlinkable
  (`RUNG_PROOF_UNLINKABLE = False`): it's a Phase-3 VP that reveals the DID. The
  client's `present_anon` is the forward-looking shape (currently == a VP). §3.5
  explains why this is low-value here (multi-profile already gives unlinkable
  pseudonymity); the blind-token (or BBS+) machinery can back it later.

## 8. Privacy obligations on the client

The server is designed not to learn which profiles share an account
A client preserves this only if it:

1. never sends account credentials or blob material on a profile
   connection (the plane lock enforces direction, not content);
2. keeps `encKey`, seeds, and the decrypted blob out of logs and crash
   reports;
3. ideally avoids trivially correlating the planes itself (e.g. don't put
   the account id in the profile connection's user-agent or query string).

## 9. Public HTTP profile (unauthenticated)

The chat server also answers **plain HTTP GET** on its WebSocket port (a
non-WebSocket request is served as HTTP; a WS upgrade proceeds unchanged), so a
profile has a shareable public URL. Read-only, no auth, no account linkage —
only what any client can already read via `profile_info`, plus the small avatar
inline. Put it behind your TLS reverse proxy in production (`https://server.tld/<name>`).

| request | response |
|---|---|
| `GET /<name>` | `200` JSON public profile card (below), or `404 {"error":"no such profile","name"}` |
| `GET /<name>/avatar` | `200` the **small** avatar as IMAGE BYTES (`Content-Type` the image type, `Access-Control-Allow-Origin: *`, `Cache-Control: public, max-age=300`); `302` to an external URL if the avatar is one; `404` if unknown |
| `GET /<name>/avatar/large` | `200` the **large** (profile-page) avatar as IMAGE BYTES, same headers; serves the custom large, else the custom small, else the generated default droid |
| `GET /healthz` | `200 ok` |
| anything else | `404 {"error":"not found"}` |

The `/<name>/avatar[/large]` byte endpoints are the **web-fetchable** way to load
an avatar: the object store is a **private** bucket reachable only via presigned
URLs on R2's API host, which a browser **can't CORS-fetch** (so a CanvasKit client
renders a broken/empty image from `avatar_url`/`avatar_small_url`). These endpoints
serve the bytes from **this** origin with `Access-Control-Allow-Origin: *`. On web,
load the **large** profile image from `<chat-http-host>/<name>/avatar/large`
(resolve against the host you reached over WS). The small chat thumbnail is still
delivered inline via `get_avatar` (no extra fetch). Avatars are already public
data, so serving the bytes here exposes nothing new.

Always JSON (`Content-Type: application/json`, `Access-Control-Allow-Origin: *`,
`Cache-Control: public, max-age=30`). The card:

```json
{
  "name": "alice", "display_name": "Alice", "bio": "…|null",
  "kind": "human|bot|unknown", "created_ts": 1700000000.0,
  "avatar_url": "…|null",        // large CUSTOM image presigned R2 URL (NOT web-CORS-fetchable) when set
  "avatar_small_url": "…|null",  // small CUSTOM image presigned R2 URL when set
  "avatar_path": "/alice/avatar/large",  // CORS-enabled large-image byte endpoint on THIS server — prefer on web
  "avatar_small_path": "/alice/avatar",  // CORS-enabled small-image byte endpoint (resolve against the chat host)
  "avatar_hash": "…|null",
  "avatar": "<base64>|null",     // small thumbnail inline (inline custom upload, or generated default); null when avatar_small_url is set
  "avatar_content_type": "image/png|null",
  "sign_pub": "…", "enc_pub": "…",   // public keys (TOFU-pin)
  "email_verified": true,
  "badges": ["email", "irl"]
}
```

**Badges** are short public slugs. `email` is derived from `email_verified`
(§4 `profile_attest`). `irl` ("verified real person") is granted via the same
**unlinkable account→profile attestation** (`irl_attest` → `profile_attest
{badge:"irl"}`, §3/§4): the operator marks an account irl-verified on the clear
side (`account_server/verify_irl.py`; a real KYC provider would call the same
hook) and the user carries the resulting token to whichever profile they choose —
the chat server never learns the account. The attestation is the **only** way to
confer a badge — there is no operator/direct grant on the chat plane (that would
require holding the account↔profile link). **`irl` is one grant per account**:
an irl-verified account mints exactly **one** signed `irlverify` token, ever
(`irl_attest` is single-use; no re-mint, no operator reset), and the chat server
dedupes its nonce so the grant lands on exactly one profile. It is **not**
non-transferable, and that is unavoidable: the token carries no account reference
(so the planes stay unlinkable), which makes it a **bearer** credential — the
holder can redeem it on any profile, including another account's. So the badge
attests *"a verified account spent its one grant here,"* not *"this profile's
operator is the verified person."* Sold/lost/misspent ⇒ forfeited.

**Account-credibility badges flow to all profiles (the common case).** Most badges
are *not* scarce like `irl` — they're account-level credibility meant to ride
**every** persona: `email` (verified email) and `paying` (paying customer) are
**unbudgeted and repeatable**. The account mints a fresh bearer token per profile
(`email_attest` / `paying_attest`), each redemption unlinkable to the account and
to the other profiles — so one human's many pseudonyms can each show "verified /
paying" credibility **without identification or being linked to each other**. That
is the point of the account↔profile firewall: *sybil-resistant pseudonymity*. `irl`
is the deliberate exception (one-per-account) precisely because its value is
uniqueness — spreading it would defeat it. (`paying` is gated account-side by
`account_server/set_paying.py` / a billing hook.)

`badges` also rides the authenticated `profile_info` /
`profile_updated` replies. `irl` is *strong* identity; render it distinctly from
the coarse `email` badge. Server-side, badges live in a single registry
(`server/badges.py`): each is *derived* (computed from the profile record, e.g.
`email`) or *stored* (granted into `profile_badges`, e.g. `irl`) — adding one is
a one-line `Badge(...)` entry. The wire stays a slug list; clients map known
slugs to icons/labels and ignore unknown ones.

IP/timing correlation by the server remains possible by design in v1; do
not promise users more than at-rest unlinkability.

### 9a. Deployment — web public-profile page

The Flutter web client renders a shareable profile page at `https://<host>/<name>`
by fetching this card (it does **not** open a WebSocket for it). For that to work
in production, the deployment has to satisfy three things:

1. **The card must be reachable from the browser, same-origin as the app.** The
   client derives the fetch base from its **configured chat URL** (`CHAT_URL` /
   `--dart-define=CHAT_URL`), not the page origin — because the card is served on
   the chat server's port. So set `CHAT_URL` to the **proxied** host you actually
   serve (e.g. `wss://server.tld`, *not* `…:8765`); the client then fetches
   `https://server.tld/<name>`. (You need `CHAT_URL` pointed there anyway for the
   WebSocket to work on 443.) `Access-Control-Allow-Origin: *` already covers the
   dev case where the app and the card are on different origins/ports.
2. **A browser navigation to `/<name>` must load the SPA, not the JSON.** By
   default `GET /<name>` returns JSON to *everyone*, so a hard navigation would
   show raw JSON. Put the app behind a reverse proxy that **content-negotiates by
   `Accept`**: serve the app's `index.html` (so the SPA boots and renders the
   page) for `Accept: text/html` (browsers + link-unfurl crawlers), and proxy to
   this JSON endpoint for `Accept: application/json` (the client's fetch already
   sends this). For rich link previews, the HTML served to crawlers should carry
   OpenGraph/Twitter `<meta>` filled from this same card (`og:title`=display name,
   `og:description`=bio, `og:image`=`avatar_url`) — crawlers read those tags and
   don't run JS. *(Recommended but not yet built server-side; the JSON contract
   above is unchanged either way.)*
3. **Asset origin.** The HTML shell must load the Flutter build assets
   (`flutter_bootstrap.js`, `main.dart.js`, `/assets/*`) from a reachable origin —
   simplest is the same proxy serving both the app and this endpoint.

If the app and the card are ever on genuinely separate hosts, point the client's
chat URL (or a dedicated define) at the card host; the contract and CORS are the
same.
