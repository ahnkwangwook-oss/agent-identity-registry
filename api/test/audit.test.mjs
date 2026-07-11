import { test } from "node:test";
import assert from "node:assert/strict";
import { makeTestD1 } from "./helpers/d1.mjs";
import { canonicalizeChangedFields, auditEntryHash, GENESIS, recordAuditEvent, computeChainTip, verifyAuditChain, buildAnchor, publishAnchor, signAnchor, verifyAnchorSignature, anchorKeyId, anchorSigningBytes } from "../src/audit.mjs";
import { ed25519SignerFromPkcs8Base64 } from "../src/crypto-utils.mjs";
import { base64urlToBytes } from "../src/did-keys.mjs";
import { generateKeyPairSync } from "node:crypto";

test("0006: agent_audit_log table exists with UNIQUE(prev_hash)", async () => {
  const db = makeTestD1();
  await db.prepare(`INSERT INTO agent_audit_log (air_id, event, changed_fields, actor, created_at, prev_hash, entry_hash)
    VALUES ('AIR-TEST-0001-AAAA','registered',NULL,'registrant','2026-01-01T00:00:00Z','GENESIS','h1')`).bind().run();
  const row = await db.prepare("SELECT air_id, event, actor, prev_hash FROM agent_audit_log WHERE entry_hash='h1'").first();
  assert.equal(row.air_id, "AIR-TEST-0001-AAAA");
  assert.equal(row.prev_hash, "GENESIS");
  await assert.rejects(db.prepare(`INSERT INTO agent_audit_log (air_id, event, actor, created_at, prev_hash, entry_hash)
    VALUES ('AIR-TEST-0002-BBBB','updated','owner','2026-01-01T00:01:00Z','GENESIS','h2')`).bind().run());
});

test("canonicalizeChangedFields: sorted + JCS array; empty → ''", () => {
  assert.equal(canonicalizeChangedFields(null), "");
  assert.equal(canonicalizeChangedFields([]), "");
  assert.equal(canonicalizeChangedFields(["description","capabilities"]),
               canonicalizeChangedFields(["capabilities","description"]));
  assert.equal(canonicalizeChangedFields(["b","a"]), '["a","b"]');
});

test("auditEntryHash: deterministic + genesis-aware + chains on prev_hash", async () => {
  const content = { air_id: "AIR-TEST-0001-AAAA", event: "registered", changedFields: null, actor: "registrant", created_at: "2026-01-01T00:00:00Z" };
  const h1 = await auditEntryHash(content, GENESIS);
  const h1again = await auditEntryHash(content, GENESIS);
  assert.equal(h1, h1again);
  const h2 = await auditEntryHash(content, h1);
  assert.notEqual(h1, h2);
  assert.match(h1, /^[0-9a-f]{64}$/);
});

async function record(db, e) {
  const stmt = await recordAuditEvent(db, e);
  await stmt.run();
}
test("chain: record events → verify valid; tamper → first_broken_id", async () => {
  const db = makeTestD1();
  await record(db, { airId: "AIR-AAAA-AAAA-AAAA", event: "registered", changedFields: null, actor: "registrant", now: "2026-01-01T00:00:00Z" });
  await record(db, { airId: "AIR-AAAA-AAAA-AAAA", event: "updated", changedFields: ["description"], actor: "owner", now: "2026-01-01T00:01:00Z" });
  let v = await verifyAuditChain(db, {});
  assert.equal(v.valid, true);
  assert.equal(v.count, 2);
  await db.prepare("UPDATE agent_audit_log SET actor='admin' WHERE id=1").bind().run();
  v = await verifyAuditChain(db, {});
  assert.equal(v.valid, false);
  assert.equal(v.first_broken_id, 1);
});
test("chain: UNIQUE(prev_hash) blocks a fork", async () => {
  const db = makeTestD1();
  await record(db, { airId: "AIR-AAAA-AAAA-AAAA", event: "registered", changedFields: null, actor: "registrant", now: "2026-01-01T00:00:00Z" });
  const tip = await computeChainTip(db);
  assert.equal(tip.count, 1);
  const a = await recordAuditEvent(db, { airId: "AIR-BBBB-BBBB-BBBB", event: "updated", changedFields: ["description"], actor: "owner", now: "t2" });
  const b = await recordAuditEvent(db, { airId: "AIR-CCCC-CCCC-CCCC", event: "updated", changedFields: ["description"], actor: "owner", now: "t3" });
  await a.run();
  await assert.rejects(b.run());
});

test("buildAnchor returns tip + count for the current chain", async () => {
  const db = makeTestD1();
  await record(db, { airId: "AIR-AAAA-AAAA-AAAA", event: "registered", changedFields: null, actor: "registrant", now: "2026-01-01T00:00:00Z" });
  const a = await buildAnchor(db, "2026-01-07T03:00:00Z");
  assert.equal(a.entry_count, 1);
  assert.equal(a.anchored_at, "2026-01-07T03:00:00Z");
  assert.match(a.tip_hash, /^[0-9a-f]{64}$/);
});

test("publishAnchor delegates to the injected putFile with a dated path + JSON body", async () => {
  let captured;
  const fakePutFile = async (args) => { captured = args; return { ok: true, commit: "abc123" }; };
  const anchor = { anchored_at: "2026-01-07T03:00:00Z", tip_hash: "deadbeef", entry_count: 5 };
  const res = await publishAnchor(anchor, { putFile: fakePutFile });
  assert.equal(res.ok, true);
  assert.ok(captured.path.includes("2026-01-07"));      // dated path
  assert.deepEqual(JSON.parse(captured.content), anchor); // exact JSON body
  assert.ok(typeof captured.message === "string" && captured.message.length > 0); // commit message
});

test("publishAnchor throws if no putFile is provided", async () => {
  await assert.rejects(publishAnchor({ anchored_at:"x", tip_hash:"y", entry_count:0 }, {}));
});

// ---- Anchor signing (Ed25519) --------------------------------------------
// A test-only signer: a fresh Ed25519 keypair + an injected sign() matching
// exactly the crypto.subtle path the Worker uses. No secrets, no real key.
async function makeTestSigner() {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const publicKeyRaw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  const sign = async (bytes) => new Uint8Array(await crypto.subtle.sign("Ed25519", kp.privateKey, bytes));
  const keyId = await anchorKeyId(publicKeyRaw);
  return { publicKeyRaw, sign, keyId };
}

test("anchorSigningBytes: JCS of exactly the 3 core fields, metadata-independent", () => {
  const core = { anchored_at: "2026-07-12T03:00:00Z", tip_hash: "abc", entry_count: 7 };
  const withMeta = { ...core, algorithm: "Ed25519", key_id: "x", signature: "y", extra: "z" };
  assert.deepEqual(anchorSigningBytes(core), anchorSigningBytes(withMeta));
  // Pinned canonical form — keys sorted: anchored_at, entry_count, tip_hash.
  assert.equal(new TextDecoder().decode(anchorSigningBytes(core)),
    '{"anchored_at":"2026-07-12T03:00:00Z","entry_count":7,"tip_hash":"abc"}');
});

test("anchorKeyId: deterministic 16-hex-char id from the public key", async () => {
  const { publicKeyRaw } = await makeTestSigner();
  const id1 = await anchorKeyId(publicKeyRaw);
  const id2 = await anchorKeyId(publicKeyRaw);
  assert.equal(id1, id2);
  assert.match(id1, /^[0-9a-f]{16}$/);
});

test("signAnchor + verifyAnchorSignature: valid round-trip", async () => {
  const { publicKeyRaw, sign, keyId } = await makeTestSigner();
  const anchor = { anchored_at: "2026-07-12T03:00:00Z", tip_hash: "abc123", entry_count: 42 };
  const signed = await signAnchor(anchor, { sign, keyId });
  assert.equal(signed.algorithm, "Ed25519");
  assert.equal(signed.key_id, keyId);
  assert.match(signed.signature, /^[A-Za-z0-9_-]+$/); // base64url, no padding
  // Core fields preserved unchanged.
  assert.equal(signed.tip_hash, "abc123");
  assert.equal(signed.entry_count, 42);
  assert.equal(await verifyAnchorSignature(signed, publicKeyRaw), true);
});

test("verifyAnchorSignature: any core-field tamper fails", async () => {
  const { publicKeyRaw, sign, keyId } = await makeTestSigner();
  const signed = await signAnchor({ anchored_at: "2026-07-12T03:00:00Z", tip_hash: "abc123", entry_count: 42 }, { sign, keyId });
  assert.equal(await verifyAnchorSignature({ ...signed, tip_hash: "tampered" }, publicKeyRaw), false);
  assert.equal(await verifyAnchorSignature({ ...signed, entry_count: 43 }, publicKeyRaw), false);
  assert.equal(await verifyAnchorSignature({ ...signed, anchored_at: "2026-07-13T03:00:00Z" }, publicKeyRaw), false);
});

test("verifyAnchorSignature: a signature from a different key fails", async () => {
  const a = await makeTestSigner();
  const b = await makeTestSigner();
  const signed = await signAnchor({ anchored_at: "t", tip_hash: "h", entry_count: 1 }, { sign: a.sign, keyId: a.keyId });
  assert.equal(await verifyAnchorSignature(signed, b.publicKeyRaw), false);
});

test("verifyAnchorSignature: an unsigned (legacy) anchor returns false, never throws", async () => {
  const { publicKeyRaw } = await makeTestSigner();
  assert.equal(await verifyAnchorSignature({ anchored_at: "t", tip_hash: "h", entry_count: 1 }, publicKeyRaw), false);
  assert.equal(await verifyAnchorSignature(null, publicKeyRaw), false);
});

// The single most likely thing to break: the REAL Worker key-import path.
// The signing secret is a PKCS#8 DER private key (base64) — NOT a raw seed
// (WebCrypto Ed25519 importKey rejects "raw" for private keys).
test("ed25519SignerFromPkcs8Base64: real PKCS#8 import → sign → verify round-trip", async () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pkcs8Base64 = privateKey.export({ type: "pkcs8", format: "der" }).toString("base64");
  const publicKeyRaw = base64urlToBytes(publicKey.export({ format: "jwk" }).x);
  const sign = await ed25519SignerFromPkcs8Base64(pkcs8Base64);
  const keyId = await anchorKeyId(publicKeyRaw);
  const signed = await signAnchor({ anchored_at: "2026-07-12T03:00:00Z", tip_hash: "abc", entry_count: 3 }, { sign, keyId });
  assert.equal(await verifyAnchorSignature(signed, publicKeyRaw), true);
});

test("signAnchor: Ed25519 is deterministic — same key + anchor → identical signature", async () => {
  const signer = await makeTestSigner();
  const anchor = { anchored_at: "t", tip_hash: "h", entry_count: 1 };
  const a = await signAnchor(anchor, signer);
  const b = await signAnchor(anchor, signer);
  assert.equal(a.signature, b.signature);
});

test("verifyAnchorSignature: algorithm-confusion + key_id are not trust inputs", async () => {
  const { publicKeyRaw, sign, keyId } = await makeTestSigner();
  const signed = await signAnchor({ anchored_at: "t", tip_hash: "h", entry_count: 1 }, { sign, keyId });
  // A different claimed algorithm must be rejected (never let the anchor pick the alg).
  assert.equal(await verifyAnchorSignature({ ...signed, algorithm: "RSA" }, publicKeyRaw), false);
  // A forged key_id does NOT bypass verification — trust is the pinned key, and the
  // real signature still verifies under it (key_id is only a hint).
  assert.equal(await verifyAnchorSignature({ ...signed, key_id: "deadbeefdeadbeef" }, publicKeyRaw), true);
});

test("verifyAnchorSignature: malformed signature returns false, never throws", async () => {
  const { publicKeyRaw } = await makeTestSigner();
  assert.equal(await verifyAnchorSignature({ algorithm: "Ed25519", signature: "!!!not-base64!!!", anchored_at: "t", tip_hash: "h", entry_count: 1 }, publicKeyRaw), false);
  assert.equal(await verifyAnchorSignature({ algorithm: "Ed25519", signature: "AAAA", anchored_at: "t", tip_hash: "h", entry_count: 1 }, publicKeyRaw), false);
});

test("verifyAnchorSignature: a wrong-length public key returns false, never throws", async () => {
  const { sign, keyId } = await makeTestSigner();
  const signed = await signAnchor({ anchored_at: "t", tip_hash: "h", entry_count: 1 }, { sign, keyId });
  // 14 bytes is exactly what base64urlToBytes("SET_AT_PROVISIONING") yields — a
  // non-32-byte key must never crash importKey; verify must fail closed to false.
  assert.equal(await verifyAnchorSignature(signed, new Uint8Array(14)), false);
});

// Known-answer vector: a FIXED PKCS#8 key + FIXED anchor yields a FIXED Ed25519
// signature. Ed25519 is deterministic, so any conforming re-implementation
// (Rust/Python) that JCS-canonicalizes {anchored_at, entry_count, tip_hash} and
// signs must reproduce this exact signature. Pins the wire format against drift.
test("anchor signing KAT: fixed key + anchor → fixed signature (cross-impl vector)", async () => {
  const PKCS8_B64 = "MC4CAQAwBQYDK2VwBCIEIIAl3//zb9AjG90dmjOu6A3z91FlXCoO+NBo0RudSnE6";
  const PUBKEY_B64URL = "-Ok69Hy3y89DkFxKsVOAKG2JY8txiallzGM83Ey-JX8";
  const anchor = { anchored_at: "2026-07-12T03:00:00Z", tip_hash: "0".repeat(64), entry_count: 128 };
  const publicKeyRaw = base64urlToBytes(PUBKEY_B64URL);
  const sign = await ed25519SignerFromPkcs8Base64(PKCS8_B64);
  const signed = await signAnchor(anchor, { sign, keyId: await anchorKeyId(publicKeyRaw) });
  assert.equal(signed.key_id, "44c6dcb3ce05772e");
  assert.equal(signed.signature, "ofrJbIXIfyBf2hyuRrWNUKZ6Wjc1PVgOXKbAsZdIoKavHTx_ZTgrN2yrAO10KXCwIyhBAz10L8JjJgR0FgqqDA");
  assert.equal(await verifyAnchorSignature(signed, publicKeyRaw), true);
});
