// Hashing + canonical-JSON primitives shared by the worker and audit.mjs.

// SHA-256 of raw bytes, returned as 64-char hex.
export async function sha256HexBytes(bytes) {
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

// SHA-256 hash of a UTF-8 string, returned as 64-char hex.
// Used to store agent_secret_hash without retaining the plaintext.
export async function sha256Hex(text) {
  return sha256HexBytes(new TextEncoder().encode(text));
}

// Raw bytes → unpadded base64url (RFC 4648 §5). Inverse of did-keys' base64urlToBytes.
// Used to encode Ed25519 signatures + keys into JSON-safe strings.
export function bytesToBase64url(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Standard base64 (padded, not url-safe) → raw bytes. Used for the PKCS#8 signing key.
export function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// Import an Ed25519 private key (PKCS#8 DER, base64-encoded) into a sign(bytes) fn.
// WebCrypto Ed25519 accepts a private key ONLY as "pkcs8" (or "jwk"), never "raw" —
// this is the format the Worker's AUDIT_ANCHOR_SIGNING_KEY secret holds.
export async function ed25519SignerFromPkcs8Base64(pkcs8Base64) {
  const key = await crypto.subtle.importKey("pkcs8", base64ToBytes(pkcs8Base64), { name: "Ed25519" }, false, ["sign"]);
  return async (bytes) => new Uint8Array(await crypto.subtle.sign("Ed25519", key, bytes));
}

// Canonical JSON per RFC 8785 (JCS). Matches the A2A draft-1 _jcs_exact()
// pattern in the conformance harness — no float coercion, exact integers.
// Used so Rust/Python/Go implementations can byte-match our signed payloads.
export function jcsCanonicalize(obj) {
  if (obj === null) return "null";
  if (typeof obj === "boolean") return obj ? "true" : "false";
  if (typeof obj === "number") {
    if (!Number.isFinite(obj)) throw new Error("non-finite number in JCS payload");
    if (!Number.isInteger(obj) && Math.abs(obj) > Number.MAX_SAFE_INTEGER) {
      throw new Error("large float canonicalization not implemented");
    }
    return JSON.stringify(obj);
  }
  if (typeof obj === "string") return JSON.stringify(obj);
  if (Array.isArray(obj)) {
    return "[" + obj.map(jcsCanonicalize).join(",") + "]";
  }
  if (typeof obj === "object") {
    const keys = Object.keys(obj).sort();
    return "{" + keys.map(k => JSON.stringify(k) + ":" + jcsCanonicalize(obj[k])).join(",") + "}";
  }
  throw new Error("unsupported JCS type: " + typeof obj);
}
