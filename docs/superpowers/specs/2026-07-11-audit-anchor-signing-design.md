# Design — Audit-Anchor Ed25519 Signing

**Date:** 2026-07-11
**Status:** Draft design, pending independent review + Peter approval (key provisioning)
**Branch:** `feat/audit-anchor-signing`
**Companion to:** `docs/superpowers/specs/2026-06-09-agent-audit-log-design.md` (§4 specified anchor signing; the shipped code dropped it — this design closes that gap)

## Goal

Sign each weekly external audit anchor with a dedicated registry Ed25519 key and publish the public key, so any third party can verify — **offline, without trusting GitHub's commit-authorship record** — that a given anchor was issued by AIR. This adds **authenticity** and **non-repudiation** to the anchor.

## What signing does and does NOT buy (scope honesty)

- **DOES:** authenticity (an anchor provably came from AIR's key, not an imposter with repo write-access or a MITM), non-repudiation (AIR cannot later disown an anchor it signed), and offline verifiability (verify from the JSON + published key alone).
- **Does NOT:** protect against AIR tampering with its *own* audit chain. AIR holds the signing key, so it could re-sign a rewritten tip. Operator-tamper evidence still rests on **public observability** (§6 of the whitepaper), unchanged. The whitepaper must keep that honest framing; signing is defense-in-depth layered on top, not a replacement.

## Current state (verified against code)

- `api/src/audit.mjs`: `buildAnchor(db, now)` → `{ anchored_at, tip_hash, entry_count }`; `publishAnchor(anchor, { putFile })` commits `anchors/{date}.json` = `JSON.stringify(anchor)`. No signing.
- `api/src/crypto-utils.mjs`: `jcsCanonicalize` (RFC 8785) + `sha256Hex`. No signing helper.
- Worker runtime does Ed25519 **verify** (`index.js:631`, `crypto.subtle`); Ed25519 **sign** is supported by Web Crypto in Workers + Node but is not yet used.
- Secrets today: `env.ADMIN_KEY`, `env.AUDIT_ANCHOR_TOKEN`. **No signing key exists.**
- Publish is wired in `scheduled()` (`index.js:185`, weekly `0 3 * * SUN`) and the manual admin trigger `POST /api/v1/admin/cron/publish-anchor` (`:122`).
- OpenAPI: `AuditAnchor` (anchored_at, tip_hash, entry_count) + `AuditVerifyResult.last_anchor`.

## 1. Key provisioning (PETER ACTION — the gating dependency)

A **dedicated** anchor-signing keypair (separate from the Foundation agent key / any attester key — separation of concerns; this key signs only anchors).

- **Peter generates the keypair and sets the private half as a Worker secret** — the private key never passes through chat or the assistant.
  - `wrangler secret put AUDIT_ANCHOR_SIGNING_KEY` — value: **standard base64 of the PKCS#8 DER** Ed25519 private key. (WebCrypto Ed25519 `importKey` accepts a private key only as `"pkcs8"` or `"jwk"`, **never `"raw"`** — a raw seed will not import. Confirmed against the review, MAJOR 1.)
- **Public key** (safe to handle): the **authoritative pin** is a documented constant in the `air-site` source (`ANCHOR_PUBLIC_KEY_B64URL`) + the OpenAPI copy (both outside a repo-write attacker's reach; they must match), and ideally echoed in the widely-distributed whitepaper PDF. A `KEY.json` in the `audit-anchors` repo is a **non-authoritative convenience copy only** — verifiers MUST fetch the key from the authoritative source, not from the anchors repo (MAJOR 3).

## 2. What is signed

The JCS-canonical bytes of the **three core fields only**:

```
signed_bytes = utf8( jcsCanonicalize({ anchored_at, entry_count, tip_hash }) )
signature    = Ed25519_sign(AUDIT_ANCHOR_SIGNING_KEY, signed_bytes)
```

- JCS sorts keys, so the payload is deterministic and third-party reproducible (same guarantee the entry-hash already relies on).
- `anchored_at` is inside the signed payload, so a signature is not replayable onto a different date/tip.
- Signature encoding: **base64url** (standard, verifiable by any Ed25519 library) with an explicit `algorithm: "Ed25519"` field. (Multibase `z…` base58btc is the attestation convention; base64url chosen here for anchor-verification ergonomics — flagged as a reversible decision.)

## 3. Published anchor shape (new)

```json
{
  "anchored_at": "2026-07-12T03:00:00Z",
  "tip_hash": "…",
  "entry_count": 128,
  "algorithm": "Ed25519",
  "key_id": "<first 16 hex of sha256(public_key_raw)>",
  "signature": "<base64url Ed25519 sig over jcs({anchored_at,entry_count,tip_hash})>"
}
```

`key_id` lets a verifier confirm the anchor was signed by the pinned key before checking the signature. `public_key` is NOT embedded (trust must come from the out-of-band pinned key, not a self-asserted key in the same file an attacker could rewrite).

## 4. Code changes

- **`api/src/audit.mjs`** (stays network-free, dependency-injected):
  - `export async function signAnchor(anchor, { sign, keyId })` — `sign` is an injected `async (bytes) => Uint8Array`; returns `{ ...anchor, algorithm: "Ed25519", key_id, signature }`. Pure of secrets → unit-testable with a Node-generated test key.
  - `export async function verifyAnchorSignature(anchor, publicKeyRaw)` — recompute JCS of the 3 core fields, verify base64url signature; returns bool. Also usable by `/audit/verify`.
  - `buildAnchor` unchanged (still returns the signable 3-field payload).
- **`api/src/index.js`**:
  - Helper to import `env.AUDIT_ANCHOR_SIGNING_KEY` → a `crypto.subtle` CryptoKey once per invocation; expose `sign(bytes)` + `keyId`.
  - Both call sites (scheduled + manual): `buildAnchor` → `signAnchor` → `publishAnchor`.
  - **Graceful degradation:** if `AUDIT_ANCHOR_SIGNING_KEY` is unset, publish unsigned (today's behavior) with a `console.warn`, so the cron never breaks pre-provisioning. Once the secret is set, every anchor is signed.
  - Optionally set `last_anchor.signature_valid` in `/audit/verify` by verifying the fetched anchor against the pinned public key.
- **`api/openapi.yaml`**: add optional `algorithm`, `key_id`, `signature` to `AuditAnchor` and to `AuditVerifyResult.last_anchor` (+ optional `signature_valid`); document the pinned public key + verification recipe.

## 5. Backward compatibility

- Historical anchors already committed to `audit-anchors` stay **unsigned** — they are NOT re-signed (re-signing a past-dated anchor would be backdating; dishonest). `signature` is optional in the schema; verifiers treat its absence as "pre-signing era."
- Deploy-forward, every new anchor is signed.

## 6. Verification path (third parties + docs)

- Publish the pinned public key (OpenAPI + `audit-anchors/KEY.json`).
- Publish a short verifier recipe (fetch anchor → JCS the 3 core fields → Ed25519-verify the base64url signature against the pinned key).
- After ship + deploy, upgrade whitepaper §6.4 to note anchors are Ed25519-signed and offline-verifiable — while KEEPING the observability framing as the operator-tamper defense.

## 7. Tests (`api/test/audit.test.mjs` additions, TDD)

- `signAnchor` + `verifyAnchorSignature` round-trip with a Node-generated Ed25519 test key.
- Signed payload = JCS of exactly the 3 core fields (byte-stable, pinned).
- Tamper any core field (tip_hash/entry_count/anchored_at) → verify fails.
- Wrong key → verify fails.
- `key_id` derives deterministically from the public key.
- Graceful degrade: publish path with no signer still emits a valid unsigned anchor.
- Update root `package.json` `test:api` if it is an explicit file list (the audit-log H4a lesson).

## 8. Rollout (Peter-gated)

1. Peter: generate keypair + `wrangler secret put AUDIT_ANCHOR_SIGNING_KEY`; hand over the public key.
2. Land code + tests (branch → PR); independent code + security review.
3. Deploy worker (Peter-gated). Smoke: `POST /admin/cron/publish-anchor`, fetch the new `anchors/{date}.json`, confirm `signature` present and `verifyAnchorSignature` passes against the pinned key.
4. Commit the pinned public key to `audit-anchors` (`KEY.json`).
5. Upgrade whitepaper §6.4 + regenerate PDF/HTML + redeploy site.

## Scope guardrails (YAGNI)

In: sign the anchor, publish + pin the public key, verify helper, OpenAPI, tests, one honest whitepaper upgrade.
Out: re-signing historical anchors; key rotation tooling (documented as future — note the `key_id` field makes rotation additive later); per-entry signing (a separate deferred item); multibase re-encoding of existing attestation signatures.

## Decisions (resolved 2026-07-11)

1. **Dedicated new keypair** for anchors — approved.
2. **base64url** signatures with an explicit `algorithm` field — approved.
3. Degrade behavior — **hard-require (no key, no publish)**, per Peter 2026-07-11 (supersedes both the original "graceful-degrade" pick and the review's cutover-hybrid). The Worker signs every anchor; if the signing key is unset it publishes **nothing** (logs a warning) — there is no unsigned-publish path at all. Rationale: the key is a single operator-held secret Peter controls, so keeping an unsigned fallback only adds a downgrade surface. **Consequence:** the secret MUST be provisioned before/at the code deploy, else the weekly anchor pauses until it is. A published `ANCHOR_SIGNING_EFFECTIVE` date still lets verifiers reject any unsigned anchor dated after it (a repo-write attacker could drop an unsigned file even though AIR's server never publishes one).

## Security review resolutions (independent review → REWORK → addressed)

- **MAJOR 1 — key format.** Secret is **PKCS#8 DER base64**, imported via `crypto.subtle.importKey("pkcs8", …, ["sign"])`. The raw-seed option is dropped (won't import). A real PKCS#8→import→sign→verify test + a fixed KAT are in `api/test/audit.test.mjs`.
- **MAJOR 2 — downgrade hole.** Resolved harder than the review proposed: **hard-require** (Peter's call). The Worker has no unsigned-publish path — if the key is unset it publishes nothing. Verifiers still reject any unsigned anchor dated after the published `ANCHOR_SIGNING_EFFECTIVE` date (guards against a repo-write attacker dropping an unsigned file). This fully removes the silent-downgrade surface.
- **MAJOR 3 — key-pin location.** Authoritative pin = the `air-site` source constant + OpenAPI (+ whitepaper), NOT the attacker-writable `audit-anchors` repo. `KEY.json` there is a convenience copy only.
- **MAJOR 4 — replay/rollback.** Signing binds the 3 fields but not the anchor *series*: a repo-write attacker could replay an old validly-signed anchor at a new path. The verifier recipe therefore also (a) binds filename ↔ `anchored_at`, (b) enforces **monotonic non-decreasing `entry_count`** across anchors, and (c) keeps the git commit history as the append-only rollback witness. The whitepaper must state **signing gives authenticity, not rollback-resistance** — "offline-verifiable" ≠ "GitHub history unnecessary."
- **Minors:** verifier trusts the pinned key (never `key_id`/`algorithm`); `key_id` = first 16 lowercase-hex of `sha256(raw 32-byte pubkey)` (a non-security hint); bytes→base64url encoder added to `crypto-utils.mjs`; Node ≥18.4 required for WebCrypto Ed25519 (CI runs v25).
