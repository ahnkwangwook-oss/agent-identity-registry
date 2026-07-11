// AIR Registry API — Cloudflare Worker + D1
// Agent Identity Registry Foundation

// OpenAPI 3.1 spec bundled as a text module. See ../openapi.yaml for the
// hand-maintained source. Wrangler's [[rules]] type="Text" config in
// wrangler.toml turns the .yaml import into a string at build time.
import OPENAPI_YAML from "../openapi.yaml";
import { base58Decode, base64urlToBytes, ed25519ToMultibase, documentContainsKey } from "./did-keys.mjs";
import { calculateInitialTrustScore, computeVerifiedStatus, recomputeTrustScore, recomputeDependentsOf, computeEvidenceLabel, buildEvidence, EVIDENCE_LABEL_DISCLAIMER } from "./trust.mjs";
import { sha256Hex, jcsCanonicalize, ed25519SignerFromPkcs8Base64 } from "./crypto-utils.mjs";
import { recordAuditEvent, verifyAuditChain, buildAnchor, publishAnchor, computeChainTip, signAnchor, anchorKeyId, verifyAnchorSignature } from "./audit.mjs";
import { validateUsername, isHandleInCooldown, isUsernameConflict, lookupHandle } from "./validation.mjs";

// Detects a D1 UNIQUE/constraint violation on the audit chain's prev_hash —
// two concurrent mutations racing to extend the same chain tip. Surfaced to
// the caller as a 409 "retry" rather than a 500. D1 errors carry the SQLite
// message text (e.g. "UNIQUE constraint failed: agent_audit_log.prev_hash").
function isAuditChainContention(err) {
  const msg = String((err && (err.message || err.cause?.message)) || err || "");
  return /constraint failed/i.test(msg) && /prev_hash|agent_audit_log|UNIQUE/i.test(msg);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    // HEAD requests must return identical headers to GET per HTTP spec.
    // Cloudflare Workers don't auto-alias these, so we treat HEAD as GET
    // for routing and strip the body before returning. Matters for tools
    // that probe endpoints with HEAD before downloading (curl -I,
    // monitoring, some openapi-generator versions).
    const isHead = request.method === "HEAD";
    const method = isHead ? "GET" : request.method;

    // CORS headers. Most endpoints are restricted to our own origin, but
    // the OpenAPI spec endpoint allows ANY origin — so browser-based
    // tooling (Swagger UI playgrounds, openapi-generator, Stoplight, etc.)
    // can fetch the spec without a CORS-proxy hop.
    const isPublicSpecEndpoint = path === "/api/v1/openapi.yaml";
    const corsHeaders = {
      "Access-Control-Allow-Origin": isPublicSpecEndpoint
        ? "*"
        : "https://agentidentityregistry.org",
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, X-Admin-Key, X-Agent-Secret",
    };

    if (method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    try {
      let response;

      // Route matching
      if (path === "/api/v1/agents" && method === "GET") {
        response = await listAgents(url, env.DB);
      } else if (path.match(/^\/api\/v1\/agents\/AIR-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}\/trust-score$/) && method === "GET") {
        const airId = path.split("/")[4];
        response = await getTrustScore(airId, env.DB);
      } else if (path.match(/^\/api\/v1\/agents\/AIR-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}\/did-document$/) && method === "GET") {
        const airId = path.split("/")[4];
        response = await getDidDocument(airId, env.DB);
      } else if (path.match(/^\/api\/v1\/agents\/AIR-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/) && method === "GET") {
        const airId = path.split("/")[4];
        response = await getAgent(airId, env.DB);
      } else if (path.match(/^\/api\/v1\/agents\/AIR-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/) && method === "PUT") {
        const airId = path.split("/")[4];
        response = await updateAgent(request, airId, env.DB);
      } else if (path.match(/^\/api\/v1\/agents\/AIR-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}$/) && method === "DELETE") {
        const airId = path.split("/")[4];
        response = await adminAuth(request, env) || await deleteAgent(airId, env.DB);
      } else if (path.match(/^\/api\/v1\/agents\/AIR-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}\/attestations$/) && method === "POST") {
        const airId = path.split("/")[4];
        response = await createAttestation(request, airId, env.DB);
      } else if (path.match(/^\/api\/v1\/agents\/AIR-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}\/attestations$/) && method === "GET") {
        const airId = path.split("/")[4];
        response = await listAttestations(airId, env.DB);
      } else if (path === "/api/v1/attestations/recent" && method === "GET") {
        response = await recentAttestations(url, env.DB);
      } else if (path.match(/^\/api\/v1\/agents\/AIR-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}\/attestations\/\d+$/) && method === "DELETE") {
        const parts = path.split("/");
        response = await revokeAttestation(request, parts[4], parts[6], env.DB);
      } else if (path.match(/^\/api\/v1\/agents\/AIR-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}\/badge\.svg$/) && method === "GET") {
        const airId = path.split("/")[4];
        response = await getBadgeSvg(airId, env.DB, url.searchParams.get("format"));
      } else if (path.match(/^\/api\/v1\/agents\/AIR-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}\/graph$/) && method === "GET") {
        const airId = path.split("/")[4];
        response = await getAgentGraph(airId, env.DB);
      } else if (path.match(/^\/api\/v1\/agents\/AIR-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}\/dependents$/) && method === "GET") {
        const airId = path.split("/")[4];
        response = await getDependents(airId, url, env.DB);
      } else if (path.match(/^\/api\/v1\/agents\/AIR-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}\/history$/) && method === "GET") {
        const airId = path.split("/")[4];
        response = await getAgentHistory(airId, url, env.DB);
      } else if (path === "/api/v1/audit/verify" && method === "GET") {
        response = await getAuditVerify(url, env);
      } else if (path === "/api/v1/audit/anchor" && method === "GET") {
        const anchor = await fetchLatestAnchor(env); // best-effort, may be null
        response = json({ anchor });
      } else if (path === "/api/v1/graph/stats" && method === "GET") {
        response = await getGraphStats(env.DB);
      } else if (path === "/api/v1/agents/register" && method === "POST") {
        response = await registerAgent(request, env.DB);
      } else if (path === "/api/v1/agents/check-name" && method === "GET") {
        response = await checkName(url, env.DB);
      } else if (path === "/api/v1/agents/check-username" && method === "GET") {
        response = await checkUsername(url, env.DB);
      } else if (path.match(/^\/api\/v1\/agents\/by-username\/[^/]+$/) && method === "GET") {
        const handle = decodeURIComponent(path.split("/")[5]);
        response = await getAgentByUsername(handle, env.DB);
      } else if (path === "/api/v1/admin/stats" && method === "GET") {
        response = await adminAuth(request, env) || await adminStats(env.DB);
      } else if (path === "/api/v1/admin/recent" && method === "GET") {
        response = await adminAuth(request, env) || await adminRecent(url, env.DB);
      } else if (path === "/api/v1/admin/cron/did-wba-resolve" && method === "POST") {
        // Manual trigger for the weekly did:wba re-resolution. Two real uses:
        //   (a) Backfilling existing agents right after the column migration,
        //       since the cron only runs Sundays — without this you'd wait days.
        //   (b) Verifying the cron handler actually works without waiting.
        response = await adminAuth(request, env) || await runDidWbaResolveCron(env.DB);
      } else if (path === "/api/v1/admin/cron/publish-anchor" && method === "POST") {
        // Manual trigger for the weekly external anchor publish — backfill the
        // first anchor or verify the GitHub adapter without waiting for Sunday.
        response = await adminAuth(request, env);
        if (!response) {
          try {
            const { anchor, result } = await buildAndPublishAnchor(env, new Date().toISOString());
            response = json({ published: anchor, result });
          } catch (e) {
            response = json({ error: (e && e.message) || String(e) }, 500);
          }
        }
      } else if (path === "/api/v1/health" && method === "GET") {
        response = json({ status: "ok", version: "0.1.0", registry: "AIR" });
      } else if (path === "/api/v1/openapi.yaml" && method === "GET") {
        // Hand-maintained OpenAPI 3.1 spec, served verbatim. 5-min edge cache.
        response = new Response(OPENAPI_YAML, {
          status: 200,
          headers: {
            "Content-Type": "application/yaml; charset=utf-8",
            "Cache-Control": "public, max-age=300",
          },
        });
      } else {
        response = json({ error: "Not found" }, 404);
      }

      // Attach CORS headers to every response
      const headers = new Headers(response.headers);
      for (const [k, v] of Object.entries(corsHeaders)) {
        headers.set(k, v);
      }
      // HEAD: identical headers to GET, no body.
      const body = isHead ? null : response.body;
      return new Response(body, { status: response.status, headers });

    } catch (err) {
      return json({ error: "Internal server error", message: err.message }, 500);
    }
  },

  // Workers Cron entrypoint — fires per the [triggers] crons schedule in
  // wrangler.toml. Currently used to re-check did:wba resolution weekly so
  // the registry's freshness data doesn't go stale post-registration.
  //
  // ctx.waitUntil keeps the work alive past this function's return — the
  // scheduled event handler can return immediately, but the promise inside
  // waitUntil continues executing until completion (or the scheduled-event
  // wall-clock limit, currently many minutes for paid plans).
  async scheduled(event, env, ctx) {
    ctx.waitUntil(
      reResolveAllDidWba(env.DB).catch((err) => {
        // Surface in `wrangler tail` logs without crashing the invocation.
        console.error("[did-wba-cron] FAILED:", err && err.stack || err);
      })
    );
    // Publish the weekly external audit anchor to the public audit-anchors repo
    // so chain integrity is verifiable without trusting AIR's own DB. Isolated
    // from the did-wba step: a GitHub failure must not affect re-resolution.
    ctx.waitUntil(
      (async () => {
        try {
          await buildAndPublishAnchor(env, new Date().toISOString());
        } catch (e) {
          console.error("[audit-anchor-cron] FAILED:", (e && e.stack) || e);
        }
      })()
    );
  },
};

// ============================================================
// RATE LIMITING
// ============================================================

const RATE_LIMIT_MAX = 5;        // max requests
const RATE_LIMIT_WINDOW = 3600;  // per hour (seconds)

async function checkRateLimit(request, db, endpoint) {
  const ip = request.headers.get("CF-Connecting-IP") || request.headers.get("X-Forwarded-For") || "unknown";
  const now = new Date();
  const windowStart = new Date(now.getTime() - RATE_LIMIT_WINDOW * 1000).toISOString();

  // Count recent requests from this IP
  const count = await db.prepare(
    "SELECT COUNT(*) as cnt FROM rate_limits WHERE ip = ? AND endpoint = ? AND created_at > ?"
  ).bind(ip, endpoint, windowStart).first();

  if (count.cnt >= RATE_LIMIT_MAX) {
    return json({
      error: "Rate limit exceeded",
      message: "Maximum " + RATE_LIMIT_MAX + " registrations per hour. Please try again later.",
      retry_after_seconds: RATE_LIMIT_WINDOW,
    }, 429);
  }

  // Log this request
  await db.prepare(
    "INSERT INTO rate_limits (ip, endpoint, created_at) VALUES (?, ?, ?)"
  ).bind(ip, endpoint, now.toISOString()).run();

  // Clean up old entries (older than 24 hours) — async, don't block
  db.prepare("DELETE FROM rate_limits WHERE created_at < ?")
    .bind(new Date(now.getTime() - 86400000).toISOString()).run();

  return null; // null means allowed
}

// ============================================================
// HELPERS
// ============================================================

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "Content-Type": "application/json", ...extraHeaders },
  });
}

// ---- External anchor: GitHub adapters (Phase B) --------------------------
// audit.mjs stays network-free; the real GitHub I/O lives here and is injected
// into publishAnchor via { putFile }. Repo AgentIdentityRegistry/audit-anchors
// is PUBLIC, so reads work without auth (token, if present, just lifts the
// rate limit). GitHub requires a User-Agent header on every request.
const ANCHOR_REPO = "AgentIdentityRegistry/audit-anchors";

// Authoritative pinned public key for anchor SIGNATURES (raw 32-byte Ed25519,
// base64url). This source constant (+ the OpenAPI copy) is the trust anchor
// verifiers use — NOT the KEY.json convenience copy in the writable anchors repo.
// MUST match the private key in the AUDIT_ANCHOR_SIGNING_KEY secret.
const ANCHOR_PUBLIC_KEY_B64URL = "SET_AT_PROVISIONING";
// Signing went live on this date; a third-party verifier MUST treat any UNSIGNED
// anchor dated on/after it as invalid (AIR's server never publishes one — see
// buildAndPublishAnchor's hard-require — but a repo-write attacker could).
const ANCHOR_SIGNING_EFFECTIVE = "2026-07-11";

// Returns a putFile({ path, content, message }) sink that commits to the public
// anchors repo. GETs first to recover any existing file's sha so re-publishing
// the same dated path updates (instead of 422-ing). Throws on a failed PUT so
// the caller's try/catch logs it.
function githubPutFile(env) {
  return async ({ path, content, message }) => {
    const apiUrl = `https://api.github.com/repos/${ANCHOR_REPO}/contents/${path}`;
    const headers = {
      "Authorization": `Bearer ${env.AUDIT_ANCHOR_TOKEN}`,
      "Accept": "application/vnd.github+json",
      "User-Agent": "air-registry",
      "X-GitHub-Api-Version": "2022-11-28",
    };
    // Recover existing sha (200) or treat as new file (404).
    let sha;
    const head = await fetch(apiUrl, { headers });
    if (head.ok) sha = (await head.json()).sha;
    const res = await fetch(apiUrl, {
      method: "PUT",
      headers,
      body: JSON.stringify({ message, content: btoa(content), ...(sha ? { sha } : {}) }),
    });
    if (!res.ok) {
      const error = (await res.text()).slice(0, 500);
      throw new Error(`github putFile ${res.status}: ${error}`);
    }
    return { ok: res.ok, status: res.status };
  };
}

// Build → SIGN → publish the weekly anchor. HARD-REQUIRE: if the signing key is
// unset, throw and publish NOTHING — there is deliberately no unsigned-anchor
// path (removes the silent-downgrade surface). Callers decide how to surface it:
// the cron logs + skips; the manual admin trigger returns the error.
async function buildAndPublishAnchor(env, now) {
  if (!env.AUDIT_ANCHOR_SIGNING_KEY) {
    throw new Error("AUDIT_ANCHOR_SIGNING_KEY unset — refusing to publish an unsigned anchor");
  }
  const sign = await ed25519SignerFromPkcs8Base64(env.AUDIT_ANCHOR_SIGNING_KEY);
  const keyId = await anchorKeyId(base64urlToBytes(ANCHOR_PUBLIC_KEY_B64URL));
  const anchor = await signAnchor(await buildAnchor(env.DB, now), { sign, keyId });
  const result = await publishAnchor(anchor, { putFile: githubPutFile(env) });
  return { anchor, result };
}

// Best-effort fetch of the most recent published anchor (or null). Never throws:
// read endpoints must not break when GitHub is unreachable or rate-limited.
// Dated YYYY-MM-DD.json filenames sort lexicographically, so the max name wins.
async function fetchLatestAnchor(env) {
  try {
    const headers = { "User-Agent": "air-registry" };
    if (env.AUDIT_ANCHOR_TOKEN) headers["Authorization"] = `Bearer ${env.AUDIT_ANCHOR_TOKEN}`;
    const listUrl = `https://api.github.com/repos/${ANCHOR_REPO}/contents/anchors`;
    const res = await fetch(listUrl, { headers });
    if (!res.ok) return null; // 404 = no anchors yet
    const entries = await res.json();
    if (!Array.isArray(entries) || entries.length === 0) return null;
    const latest = entries.reduce((a, b) => (b.name > a.name ? b : a));
    const raw = await fetch(latest.download_url, { headers: { "User-Agent": "air-registry" } });
    if (!raw.ok) return null;
    return JSON.parse(await raw.text());
  } catch {
    return null;
  }
}

// ============================================================
// AIR ID GENERATION (per spec: SHA-256 → base32 → CRC32)
// ============================================================

// Crockford's Base32 alphabet — 32 characters, excludes I, L, O, U to avoid
// look-alike confusion with 1, 0. Matches SPECIFICATION.md line 79.
// Previous version was only 29 chars, which produced "undefined" segments
// in ~32% of new AIR IDs whenever lookup index landed in [29, 31]. Fixed 2026-05-23.
const BASE32_CHARS = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

function base32Encode(bytes, length) {
  let result = "";
  let bits = 0;
  let value = 0;
  for (let i = 0; i < bytes.length && result.length < length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5 && result.length < length) {
      bits -= 5;
      result += BASE32_CHARS[(value >>> bits) & 0x1f];
    }
  }
  if (bits > 0 && result.length < length) {
    result += BASE32_CHARS[(value << (5 - bits)) & 0x1f];
  }
  return result;
}

function crc32(data) {
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i++) {
    crc ^= data[i];
    for (let j = 0; j < 8; j++) {
      crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

async function generateAirId(identityDoc) {
  // 1. Canonical JSON
  const canonical = JSON.stringify(identityDoc, Object.keys(identityDoc).sort());

  // 2. SHA-256 hash
  const encoder = new TextEncoder();
  const hashBuffer = await crypto.subtle.digest("SHA-256", encoder.encode(canonical));
  const hashBytes = new Uint8Array(hashBuffer);

  // 3. First 8 bytes → base32 → HEAD (4) + TAIL (4)
  const head = base32Encode(hashBytes.slice(0, 4), 4);
  const tail = base32Encode(hashBytes.slice(4, 8), 4);

  // 4. CRC32 of full hash → base32 → CHECKSUM (4)
  const crcValue = crc32(hashBytes);
  const crcBytes = new Uint8Array([
    (crcValue >>> 24) & 0xff,
    (crcValue >>> 16) & 0xff,
    (crcValue >>> 8) & 0xff,
    crcValue & 0xff,
  ]);
  const checksum = base32Encode(crcBytes, 4);

  // 5. Format
  return `AIR-${head}-${tail}-${checksum}`;
}

// ============================================================
// did:wba VALIDATION & RESOLUTION
// ============================================================
// Validates and resolves did:wba (Web-Based Authentication) DIDs per
// the W3C AI Agent Protocol CG spec. did:wba is a DNS-anchored DID
// method that doesn't require blockchain or central registry.
//
// Format:
//   did:wba:DOMAIN                  → https://DOMAIN/.well-known/agent.json
//   did:wba:DOMAIN:path:segments    → https://DOMAIN/path/segments/did.json
//
// Validation policy: STRICT (hard-reject on bad format).
// did:wba is opt-in — agents without a domain can use did:key instead.

const DID_WBA_PREFIX = "did:wba:";
const DID_WBA_TIMEOUT_MS = 3000;
// 8 KB. A DID doc with the max 20 service endpoints is ~3.7 KB; the old 1024 cap
// truncated real docs (any agent with an A2AInbox endpoint is ~1.2 KB) so JSON.parse
// threw and resolution silently failed. See air/trust-graph-coldstart-2026-06-02.
const DID_WBA_MAX_RESPONSE_BYTES = 8192;

function isDidWba(did) {
  return typeof did === "string" && did.startsWith(DID_WBA_PREFIX);
}

function validateDidWba(did) {
  if (!isDidWba(did)) {
    return { valid: false, error: "not a did:wba" };
  }
  const rest = did.slice(DID_WBA_PREFIX.length);
  if (rest.length === 0) {
    return { valid: false, error: "missing domain after did:wba:" };
  }

  // Split into [domain, ...pathSegments]
  const parts = rest.split(":");
  const domain = parts[0];
  const pathSegments = parts.slice(1);

  // Domain length per RFC 1035 (min 4 = a.bc; max 253 = full hostname)
  if (domain.length < 4 || domain.length > 253) {
    return { valid: false, error: "domain length must be 4-253 chars" };
  }
  // Domain charset: ASCII letters/digits/dots/hyphens, must include a dot
  if (!/^[a-z0-9.-]+$/i.test(domain)) {
    return { valid: false, error: "domain has invalid characters (ASCII letters/digits/dots/hyphens only)" };
  }
  if (!domain.includes(".")) {
    return { valid: false, error: "domain must include at least one dot (e.g. example.com)" };
  }
  // SSRF guard: reject IPv4 literals
  if (/^\d+\.\d+\.\d+\.\d+$/.test(domain)) {
    return { valid: false, error: "domain cannot be a raw IPv4 address" };
  }
  // SSRF guard: reject localhost variants
  if (domain.toLowerCase() === "localhost" || domain.toLowerCase().endsWith(".localhost")) {
    return { valid: false, error: "domain cannot be localhost" };
  }

  // Path segments must be safe identifiers (alphanumeric + hyphen + underscore)
  for (const seg of pathSegments) {
    if (seg.length === 0 || !/^[a-zA-Z0-9_-]+$/.test(seg)) {
      return { valid: false, error: "path segment '" + seg + "' has invalid characters" };
    }
  }

  return { valid: true, domain, pathSegments };
}

function didWbaResolutionUrl(parsed) {
  if (parsed.pathSegments.length === 0) {
    return `https://${parsed.domain}/.well-known/agent.json`;
  }
  return `https://${parsed.domain}/${parsed.pathSegments.join("/")}/did.json`;
}

async function resolveDidWba(did, db) {
  const parsed = validateDidWba(did);
  if (!parsed.valid) {
    return { resolved: false, error: parsed.error };
  }

  // AIR-minted DIDs (did:wba:agentidentityregistry.org:agents:{air_id}) are SELF-HOSTED:
  // resolving one means checking OUR OWN registry, not an HTTP round-trip. A Worker can't
  // reliably fetch its own route (the self-subrequest bypasses the Worker → 404), so the
  // generic HTTP path can never resolve them. The agent existing + active + having a
  // public_key IS the proof its DID document (AIR spec §3.3) would resolve.
  // See air/trust-graph-coldstart-2026-06-02.
  if (parsed.domain === "agentidentityregistry.org") {
    // Any did:wba on OUR domain MUST be the canonical agents:{air_id} shape, resolved
    // via direct DB check — never an HTTP self-fetch. Reject anything else at the source
    // so a future catch-all/SPA route on this domain can't become a key-substitution vector.
    if (parsed.pathSegments.length !== 2 || parsed.pathSegments[0] !== "agents") {
      return { resolved: false, url: "(local)", error: "non-canonical AIR-domain did:wba (expected agents:{air_id})" };
    }
    // (The shape guard above also keeps the !db / direct-DB path below unreachable
    //  for any attacker-crafted same-domain DID — only canonical AIR-minted DIDs reach it.)
    if (!db) {
      return { resolved: false, url: "(local)", error: "AIR-minted DID resolution needs a DB handle" };
    }
    const airId = parsed.pathSegments[1];
    const row = await db.prepare(
      "SELECT public_key, status FROM agents WHERE air_id = ?"
    ).bind(airId).first();
    if (!row || row.status !== "active") {
      return { resolved: false, url: "(local)", error: "AIR-minted DID: agent not found or inactive" };
    }
    if (!row.public_key) {
      return { resolved: false, url: "(local)", error: "AIR-minted DID: agent has no public_key" };
    }
    return { resolved: true, url: `(local: /api/v1/agents/${airId}/did-document)` };
  }

  const url = didWbaResolutionUrl(parsed);
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), DID_WBA_TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      method: "GET",
      headers: { "Accept": "application/json" },
      redirect: "manual", // CF Workers reject "error"; we detect redirects below
      signal: controller.signal,
    });
    clearTimeout(timeoutId);

    // No redirects allowed (security): a did:wba document must be served directly.
    // With redirect:"manual", a 3xx surfaces as a redirect status or an
    // opaqueredirect response (status 0); reject either.
    if (response.type === "opaqueredirect" || (response.status >= 300 && response.status < 400)) {
      return { resolved: false, url, error: "did:wba resolution must not redirect (status " + response.status + ")" };
    }
    if (!response.ok) {
      return { resolved: false, url, error: "HTTP " + response.status };
    }

    // Must be a JSON document. Enforces the did:wba content type AND guards against
    // reading an HTML error page (e.g. a 200 SPA fallback) as a DID doc — the class of
    // bug that hid the AIR-minted resolution break. See air/trust-graph-coldstart-2026-06-02.
    const contentType = (response.headers.get("content-type") || "").toLowerCase();
    if (!contentType.includes("application/json") && !contentType.includes("application/did+json")) {
      return { resolved: false, url, error: "DID document is not JSON (content-type: " + (contentType || "none") + ")" };
    }

    // Stream-read up to the byte cap (truncate, don't reject)
    const reader = response.body.getReader();
    const chunks = [];
    let received = 0;
    while (received < DID_WBA_MAX_RESPONSE_BYTES) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      received += value.length;
    }
    try { reader.cancel(); } catch {}

    // Concatenate up to the byte cap
    const merged = new Uint8Array(Math.min(received, DID_WBA_MAX_RESPONSE_BYTES));
    let offset = 0;
    for (const chunk of chunks) {
      const remaining = DID_WBA_MAX_RESPONSE_BYTES - offset;
      if (remaining <= 0) break;
      const slice = chunk.subarray(0, remaining);
      merged.set(slice, offset);
      offset += slice.length;
    }
    const text = new TextDecoder().decode(merged);

    // Parse the DID document and KEEP it — the caller binds the published key to
    // AIR's record (#4 resolved-key check). A non-JSON body still fails closed.
    let document;
    try {
      document = JSON.parse(text);
    } catch {
      return { resolved: false, url, error: "response is not valid JSON" };
    }
    return { resolved: true, url, document };
  } catch (e) {
    clearTimeout(timeoutId);
    const error = e.name === "AbortError" ? "timeout after " + DID_WBA_TIMEOUT_MS + "ms" : e.message || "network error";
    return { resolved: false, url, error };
  }
}

// ============================================================
// CRYPTO UTILITIES
// ============================================================
// Validation helpers for cryptographic material submitted by clients.
// Currently: Ed25519 public keys (base64url, 32 bytes after decode).
// Key ENCODING (base58/multibase) now lives in ./did-keys.mjs; this section holds
// key validation + Ed25519 signature verification.

// Generate a 32-char hex agent secret (16 random bytes = 128 bits of entropy).
// Plaintext is shown to the user once at registration and never stored or recoverable.
function generateAgentSecret() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

// Constant-time string equality (timing-safe). Returns true if and only if
// both strings have identical length and contents. Iterates the full length
// regardless of mismatch position, preventing timing-side-channel attacks
// during agent secret verification.
function constantTimeEquals(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

function validatePublicKey(key) {
  if (typeof key !== "string" || key.length === 0) {
    return { valid: false, error: "must be a non-empty string" };
  }
  // Ed25519 public keys are 32 bytes → 43 chars base64url (no pad) or 44 (with pad)
  if (key.length !== 43 && key.length !== 44) {
    return { valid: false, error: "must be 43 or 44 base64url chars (Ed25519 is 32 bytes)" };
  }
  // base64url charset: A-Z, a-z, 0-9, -, _, optional = padding
  if (!/^[A-Za-z0-9_-]+=*$/.test(key)) {
    return { valid: false, error: "contains invalid base64url characters" };
  }
  // Decode: base64url → base64 → atob → byte string
  try {
    let b64 = key.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4 !== 0) b64 += "=";
    const binary = atob(b64);
    if (binary.length !== 32) {
      return { valid: false, error: "decoded key must be exactly 32 bytes (got " + binary.length + ")" };
    }
    return { valid: true };
  } catch (e) {
    return { valid: false, error: "is not valid base64url" };
  }
}

// ============================================================
// ATTESTATION HELPERS (AIR Verified — Phase 4, migrations/0004)
// ============================================================
//
// Six locks an attestation must pass to count toward Verified:
//   Lock 1: Live did:wba resolution + Ed25519 signature check
//   Lock 2: WHOIS root distinct from subject + from other attesters
//   Lock 3: Attester tenure ≥30 days + attester own trust ≥50
//   Lock 4: Weighted by attester_trust × tenure_multiplier
//   Lock 5: Attester rate limit ≤10 issuances per 7-day rolling window
//   Lock 6: Public, signed, audit trail
//
// Verified formula:
//   For each non-revoked attestation, weight = attester_trust × tenure_mult
//   verified = (sum(weight) >= 300) AND (count(distinct whois_root) >= 3)
//
// See [[air/strategic-borrowings-from-opena2a-2026-05-28]] for design rationale.

// Verify an Ed25519 signature in multibase encoding.
//   publicKeyBase64url — 43-44 char base64url (Ed25519 32-byte raw key)
//   payloadBytes       — Uint8Array of the JCS-canonical bytes that were signed
//   signatureMultibase — "z" + base58btc-encoded 64-byte signature
// Returns true iff the signature is valid. All failure modes (bad encoding,
// wrong length, Web Crypto error) return false — never throw.
async function verifyEd25519Signature(publicKeyBase64url, payloadBytes, signatureMultibase) {
  if (typeof signatureMultibase !== "string" || !signatureMultibase.startsWith("z")) return false;
  let sigBytes;
  try { sigBytes = base58Decode(signatureMultibase.slice(1)); } catch { return false; }
  if (sigBytes.length !== 64) return false;

  let keyBytes;
  try { keyBytes = base64urlToBytes(publicKeyBase64url); } catch { return false; }
  if (keyBytes.length !== 32) return false;

  try {
    const cryptoKey = await crypto.subtle.importKey(
      "raw", keyBytes, { name: "Ed25519" }, false, ["verify"]
    );
    return await crypto.subtle.verify("Ed25519", cryptoKey, sigBytes, payloadBytes);
  } catch {
    return false;
  }
}

// Multi-label TLDs we recognize for proper eTLD+1 (WHOIS root) extraction.
// Hand-maintained subset covering ~95% of cases. A full Public Suffix List
// would add ~50KB for marginal additional coverage; this gate is one of 6
// locks so the residual 5% gap is acceptable.
const MULTI_LABEL_TLDS = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk", "net.uk",
  "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
  "co.nz", "net.nz", "org.nz", "ac.nz", "gen.nz", "geek.nz",
  "co.jp", "ne.jp", "or.jp", "ad.jp", "ac.jp", "go.jp", "gr.jp",
  "co.kr", "or.kr", "ne.kr", "re.kr", "go.kr", "ac.kr", "pe.kr",
  "com.br", "net.br", "org.br", "gov.br", "edu.br",
  "com.sg", "edu.sg", "gov.sg", "net.sg", "org.sg",
  "co.in", "net.in", "org.in", "gov.in", "edu.in", "ac.in",
  "co.za", "org.za", "gov.za", "net.za", "ac.za",
  "com.mx", "org.mx", "gob.mx", "edu.mx",
  "com.hk", "org.hk", "gov.hk", "edu.hk", "idv.hk", "net.hk",
  "com.tw", "org.tw", "gov.tw", "edu.tw", "idv.tw", "net.tw",
  "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
]);

// Extract the WHOIS root (eTLD+1) from a did:wba creator DID.
//   "did:wba:agent.foo.steinberger.io:agents:AIR-X" → "steinberger.io"
//   "did:wba:agent.example.co.uk:agents:AIR-X"      → "example.co.uk"
// Throws on non-did:wba or malformed input; callers must catch.
function extractWhoisRoot(did) {
  if (typeof did !== "string" || !did.startsWith("did:wba:")) {
    throw new Error("not a did:wba DID");
  }
  const rest = did.slice("did:wba:".length);
  const hostEnd = rest.indexOf(":");
  const host = (hostEnd === -1 ? rest : rest.slice(0, hostEnd)).toLowerCase();
  const cleanHost = host.split(":")[0]; // defensive port strip
  const labels = cleanHost.split(".");
  if (labels.length < 2) throw new Error("host has too few labels: " + cleanHost);

  if (labels.length >= 3) {
    const last2 = labels.slice(-2).join(".");
    if (MULTI_LABEL_TLDS.has(last2)) {
      return labels.slice(-3).join(".");
    }
  }
  return labels.slice(-2).join(".");
}

// Tenure multiplier per the AIR Verified design (Lock 4):
//   <30d    → 0   (not eligible — caller should reject before this is reached)
//   30-90d  → 0.5
//   90-365d → 1.0
//   >365d   → 1.5
function tenureMultiplier(ageDays) {
  if (ageDays < 30) return 0;
  if (ageDays < 90) return 0.5;
  if (ageDays < 365) return 1.0;
  return 1.5;
}

// Run all 6 eligibility locks for an attester. Returns either:
//   { eligible: true, attester_trust, age_days, tenure_multiplier,
//     public_key, creator_did, whois_root }
//   { eligible: false, reason: string }
//
// Lock 1 here verifies attester's own did:wba resolves. Caller is responsible
// for Lock 2 (WHOIS root vs subject + other attesters) since that needs the
// subject context.
async function getAttesterEligibility(attesterAirId, db) {
  const attester = await db.prepare(`
    SELECT air_id, creator_did, created_at, public_key, status
    FROM agents WHERE air_id = ?
  `).bind(attesterAirId).first();

  if (!attester) return { eligible: false, reason: "attester not found" };
  if (attester.status !== "active") return { eligible: false, reason: "attester is not active" };
  if (!attester.public_key) {
    return { eligible: false, reason: "attester has no public_key on file (Lock 1 prerequisite)" };
  }

  // Lock 1: must be did:wba so we can resolve it live.
  // External (non-did:wba) attesters are a future feature.
  if (!isDidWba(attester.creator_did)) {
    return { eligible: false, reason: "attester creator_did is not did:wba (external attesters not yet supported)" };
  }
  const wba = await resolveDidWba(attester.creator_did, db);
  if (!wba.resolved) {
    return { eligible: false, reason: `Lock 1: did:wba live resolution failed (${wba.error})` };
  }
  // Lock 1 key binding (#4): for an EXTERNAL did:wba, the freshly-resolved document
  // must advertise the key we verify signatures against. AIR-minted DIDs return no
  // `document` (self-consistent by construction) and skip this.
  if (wba.document && !documentContainsKey(wba.document, attester.public_key)) {
    return { eligible: false, reason: "Lock 1: published did.json does not advertise the registered public key" };
  }

  // Lock 3a: tenure ≥30 days
  const createdAt = new Date(attester.created_at);
  const ageDays = (Date.now() - createdAt.getTime()) / (1000 * 60 * 60 * 24);
  if (ageDays < 30) {
    return { eligible: false, reason: `Lock 3: attester tenure ${ageDays.toFixed(1)}d < required 30d` };
  }

  // Lock 3b: attester's own trust ≥50
  const trustRow = await db.prepare(
    "SELECT total_score FROM trust_scores WHERE air_id = ?"
  ).bind(attesterAirId).first();
  const attesterTrust = trustRow?.total_score ?? 0;
  if (attesterTrust < 50) {
    return { eligible: false, reason: `Lock 3: attester trust ${attesterTrust} < required 50` };
  }

  // Lock 5: rate limit ≤10 active issuances per rolling 7-day window
  const recentCount = await db.prepare(`
    SELECT COUNT(*) AS n FROM agent_attestations
    WHERE attester_air_id = ?
      AND datetime(signed_at) >= datetime('now', '-7 days')
      AND revoked_at IS NULL
  `).bind(attesterAirId).first();
  const issuedRecently = recentCount?.n ?? 0;
  if (issuedRecently >= 10) {
    return { eligible: false, reason: `Lock 5: ${issuedRecently} active issuances in last 7d (max 10)` };
  }

  // Lock 2 prep: extract WHOIS root. Caller compares against subject + others.
  let whoisRoot;
  try {
    whoisRoot = extractWhoisRoot(attester.creator_did);
  } catch (e) {
    return { eligible: false, reason: `Lock 2 prep: cannot extract WHOIS root (${e.message})` };
  }

  return {
    eligible: true,
    attester_trust: attesterTrust,
    age_days: ageDays,
    tenure_multiplier: tenureMultiplier(ageDays),
    public_key: attester.public_key,
    creator_did: attester.creator_did,
    whois_root: whoisRoot,
  };
}

// ============================================================
// ROUTE HANDLERS
// ============================================================

async function getAgent(airId, db) {
  const agent = await db.prepare(
    "SELECT a.*, t.total_score, t.grade, t.provenance, t.behavioral, t.transparency, t.security, t.peer_attestations, t.calculated_at FROM agents a LEFT JOIN trust_scores t ON a.air_id = t.air_id WHERE a.air_id = ?"
  ).bind(airId).first();

  if (!agent) {
    return json({ error: "Agent not found", air_id: airId }, 404);
  }

  // Computed Verified status from active attestations (Phase 4 / migration 0004).
  // The legacy `agent.verified` and `agent.verification_level` columns are kept
  // for backward compat but the authoritative value comes from the attestation
  // graph. See [[air/strategic-borrowings-from-opena2a-2026-05-28]].
  const verifiedStatus = await computeVerifiedStatus(airId, db);

  return json({
    "@context": "https://agentidentityregistry.org/v1",
    type: "AgentIdentity",
    air_id: agent.air_id,
    name: agent.name,
    username: agent.username || null,
    description: agent.description,
    creator: {
      did: agent.creator_did,
      name: agent.creator_name,
      type: agent.creator_type,
      public_key: agent.public_key, // null for agents registered without one
    },
    capabilities: JSON.parse(agent.capabilities || "[]"),
    security: {
      certifications: JSON.parse(agent.security_certifications || "[]"),
    },
    transparency: {
      open_source: !!agent.transparency_open_source,
      code_repository: agent.transparency_code_repo,
      documentation_url: agent.transparency_docs_url,
    },
    verified: verifiedStatus.verified,
    verification_level: agent.verification_level, // legacy, kept for compat
    verification_status: {
      verified: verifiedStatus.verified,
      score: verifiedStatus.verification_score,
      score_required: 300,
      attestation_count: verifiedStatus.attestation_count,
      distinct_whois_roots: verifiedStatus.distinct_whois_roots,
      distinct_whois_roots_required: 3,
    },
    // Persisted result of the most recent did:wba resolution check.
    // null = creator isn't a did:wba (the field is N/A). For did:wba creators,
    // true/false reflects whether the agent's did.json was fetchable at the
    // last check. Refreshed weekly by the scheduled cron.
    did_wba_resolved: agent.did_wba_resolved === null ? null : !!agent.did_wba_resolved,
    did_wba_last_checked_at: agent.did_wba_last_checked_at,
    is_demo: !!agent.is_demo,
    status: agent.status,
    created: agent.created_at,
    updated: agent.updated_at,
    trust_score: agent.total_score,
    trust_grade: agent.grade,
    components: {
      provenance: agent.provenance,
      behavioral: agent.behavioral,
      transparency: agent.transparency,
      security: agent.security,
      peer_attestations: agent.peer_attestations,
    },
    evidence: buildEvidence(verifiedStatus, {
      provenance: agent.provenance,
      transparency: agent.transparency,
      security: agent.security,
    }),
  });
}

// W3C DID Core-shaped DID document for an AIR-registered agent.
// Returns 404 if the agent has no public_key on file (no key = nothing to publish).
// The "id" is AIR's minted DID for this agent; if the agent registered with a
// different creator_did (e.g. did:key, did:wba on their own domain), that DID
// is included under "alsoKnownAs" — W3C-standard way to link equivalent DIDs.
// Public, no auth, cacheable for 5 minutes at the edge.
async function getDidDocument(airId, db) {
  const agent = await db.prepare(
    "SELECT air_id, creator_did, public_key, name, service_endpoints FROM agents WHERE air_id = ? AND status = 'active'"
  ).bind(airId).first();

  if (!agent) {
    return json({ error: "Agent not found", air_id: airId }, 404);
  }
  if (!agent.public_key) {
    return json({
      error: "Agent has no public key on file; DID document not available.",
      air_id: airId,
      hint: "Register with a public_key field (Ed25519, base64url) to enable DID document resolution.",
    }, 404);
  }

  const airDid = `did:wba:agentidentityregistry.org:agents:${airId}`;
  const publicKeyMultibase = ed25519ToMultibase(agent.public_key);
  const trustScoreUrl = `https://agentidentityregistry.org/api/v1/agents/${airId}/trust-score`;

  // alsoKnownAs only included if the agent's creator_did differs from the AIR-minted DID.
  const alsoKnownAs = agent.creator_did && agent.creator_did !== airDid ? [agent.creator_did] : undefined;

  // Hardcoded AIRTrustScore entry is preserved — every agent always advertises
  // its trust-score endpoint. Per-agent service_endpoints (Phase 3 Stage 3.0.1a)
  // are appended on top via parseServiceEndpoints below.
  const service = [
    {
      id: `${airDid}#trust-score`,
      type: "AIRTrustScore",
      serviceEndpoint: trustScoreUrl,
    },
    ...parseServiceEndpoints(agent.service_endpoints, airDid),
  ];

  const doc = {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/ed25519-2020/v1",
    ],
    id: airDid,
    alsoKnownAs,
    verificationMethod: [
      {
        id: `${airDid}#key-1`,
        type: "Ed25519VerificationKey2020",
        controller: airDid,
        publicKeyMultibase,
      },
    ],
    authentication: [`${airDid}#key-1`],
    assertionMethod: [`${airDid}#key-1`],
    service,
  };

  // Cache at the edge for 5 minutes (DID docs are slow-changing).
  // 60s client cache TTL per AIR spec §3.6 (DID document freshness).
  return json(doc, 200, { "Cache-Control": "public, max-age=60" });
}

// Parse the JSON string stored in agents.service_endpoints into validated
// W3C did-core service entries. Returns an empty array (never throws) when:
//   • the column is NULL / empty
//   • the JSON is malformed
//   • the top-level value isn't an array
// Each entry must have a string `type` and a string `serviceEndpoint`; entries
// failing that check are skipped silently rather than poisoning the whole list.
// `id` is auto-generated as `${airDid}#${type}` when the stored entry omits it,
// so callers get spec-compliant fragment IDs even from minimal PUT payloads.
function parseServiceEndpoints(raw, airDid) {
  if (!raw) return [];
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) return [];
  const out = [];
  for (const entry of parsed) {
    if (!entry || typeof entry !== "object") continue;
    if (typeof entry.type !== "string" || entry.type.length === 0) continue;
    if (typeof entry.serviceEndpoint !== "string" || entry.serviceEndpoint.length === 0) continue;
    const id = typeof entry.id === "string" && entry.id.length > 0
      ? entry.id
      : `${airDid}#${entry.type}`;
    out.push({ id, type: entry.type, serviceEndpoint: entry.serviceEndpoint });
  }
  return out;
}

// Validate a service_endpoints PUT payload. Returns { valid: true, normalized }
// on success (normalized is the array of validated entries, safe to JSON.stringify)
// or { valid: false, error } on the first failure. Strict: array of objects each
// with string `type` and string `serviceEndpoint` (URL form). Optional string `id`.
function validateServiceEndpoints(value) {
  if (!Array.isArray(value)) {
    return { valid: false, error: "service_endpoints must be an array" };
  }
  if (value.length > 20) {
    return { valid: false, error: "service_endpoints exceeds max length of 20 entries" };
  }
  const normalized = [];
  for (let i = 0; i < value.length; i++) {
    const entry = value[i];
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      return { valid: false, error: `service_endpoints[${i}] must be an object` };
    }
    if (typeof entry.type !== "string" || entry.type.trim().length === 0) {
      return { valid: false, error: `service_endpoints[${i}].type must be a non-empty string` };
    }
    if (typeof entry.serviceEndpoint !== "string" || entry.serviceEndpoint.trim().length === 0) {
      return { valid: false, error: `service_endpoints[${i}].serviceEndpoint must be a non-empty string` };
    }
    // URL form check — accept any scheme so callers can ship did:, https:, mailto:,
    // urn: etc. (W3C DID Core treats serviceEndpoint as a generic URI).
    try {
      new URL(entry.serviceEndpoint);
    } catch {
      return { valid: false, error: `service_endpoints[${i}].serviceEndpoint is not a valid URL` };
    }
    if (entry.id !== undefined && (typeof entry.id !== "string" || entry.id.length === 0)) {
      return { valid: false, error: `service_endpoints[${i}].id must be a non-empty string when present` };
    }
    const out = { type: entry.type.trim().slice(0, 100), serviceEndpoint: entry.serviceEndpoint.trim().slice(0, 500) };
    if (entry.id) out.id = entry.id.trim().slice(0, 200);
    normalized.push(out);
  }
  return { valid: true, normalized };
}

async function getTrustScore(airId, db) {
  const score = await db.prepare(
    "SELECT * FROM trust_scores WHERE air_id = ?"
  ).bind(airId).first();

  if (!score) {
    return json({ error: "Trust score not found", air_id: airId }, 404);
  }

  // Label needs Verified status; getTrustScore otherwise reads only trust_scores.
  // If this throws, let it propagate (→ 500) — never silently mislabel.
  const verifiedStatus = await computeVerifiedStatus(airId, db);

  return json({
    air_id: airId,
    total_score: score.total_score,
    grade: score.grade,
    components: {
      provenance: score.provenance,
      behavioral: score.behavioral,
      transparency: score.transparency,
      security: score.security,
      peer_attestations: score.peer_attestations,
    },
    calculated_at: score.calculated_at,
    evidence: buildEvidence(verifiedStatus, {
      provenance: score.provenance,
      transparency: score.transparency,
      security: score.security,
    }),
  });
}

async function listAgents(url, db) {
  const limit = Math.min(parseInt(url.searchParams.get("limit") || "20"), 100);
  const offset = parseInt(url.searchParams.get("offset") || "0");

  const { results } = await db.prepare(
    "SELECT a.air_id, a.name, a.description, a.verified, a.verification_level, a.is_demo, a.created_at, t.total_score, t.grade FROM agents a LEFT JOIN trust_scores t ON a.air_id = t.air_id WHERE a.status = 'active' ORDER BY t.total_score DESC LIMIT ? OFFSET ?"
  ).bind(limit, offset).all();

  const countRow = await db.prepare(
    "SELECT COUNT(*) as total FROM agents WHERE status = 'active'"
  ).first();

  return json({
    agents: results.map((r) => ({
      air_id: r.air_id,
      name: r.name,
      description: r.description,
      verified: !!r.verified,
      verification_level: r.verification_level,
      is_demo: !!r.is_demo,
      trust_score: r.total_score,
      trust_grade: r.grade,
      created: r.created_at,
    })),
    total: countRow.total,
    limit,
    offset,
  });
}

async function registerAgent(request, db) {
  // Rate limit check
  const rateLimited = await checkRateLimit(request, db, "register");
  if (rateLimited) return rateLimited;

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Invalid JSON body" }, 400);
  }

  // Validate required fields
  if (!body.name || typeof body.name !== "string" || body.name.trim().length === 0) {
    return json({ error: "Field 'name' is required" }, 400);
  }
  // Either creator_did OR public_key is required (Step 6).
  // - creator_did present: caller controls the DID elsewhere (did:key, did:wba, did:web, etc.)
  // - creator_did absent + public_key present: AIR mints a did:wba pointing at this registry
  // - both absent: 400 — we need at least one identity anchor
  const hasCreatorDid = body.creator_did && typeof body.creator_did === "string" && body.creator_did.trim().length > 0;
  const hasPublicKey = body.public_key && typeof body.public_key === "string" && body.public_key.trim().length > 0;
  if (!hasCreatorDid && !hasPublicKey) {
    return json({
      error: "Either 'creator_did' or 'public_key' is required. If you don't have a domain, omit creator_did and AIR will mint a did:wba for you (your public_key anchors the identity).",
    }, 400);
  }

  // Sanitize inputs
  const name = body.name.trim().slice(0, 200);
  const description = (body.description || "").trim().slice(0, 2000);
  // creatorDid is `let` (not const) so it can be reassigned later when AIR mints a did:wba
  // for keyless agents (when the caller omitted creator_did but provided public_key).
  let creatorDid = hasCreatorDid ? body.creator_did.trim().slice(0, 500) : "";
  const creatorName = (body.creator_name || "").trim().slice(0, 200);
  const creatorType = ["individual", "organization"].includes(body.creator_type) ? body.creator_type : "individual";
  const capabilities = JSON.stringify((body.capabilities || []).slice(0, 20));
  const securityCerts = JSON.stringify((body.security_certifications || []).slice(0, 10));
  const openSource = body.open_source ? 1 : 0;
  const codeRepo = (body.code_repository || "").trim().slice(0, 500);
  const docsUrl = (body.documentation_url || "").trim().slice(0, 500);

  // did:wba validation + resolution (Strict Mom policy)
  // - If creator_did is a did:wba, format MUST be valid (hard-reject on bad format)
  // - Resolution is best-effort: never blocks registration on resolution failure
  // - Non-did:wba creator_did (did:key, did:web, etc.) is unaffected
  let didWbaResolved; // undefined for non-did:wba registrations
  if (isDidWba(creatorDid)) {
    const validation = validateDidWba(creatorDid);
    if (!validation.valid) {
      return json({ error: "Invalid did:wba: " + validation.error }, 400);
    }
    const resolution = await resolveDidWba(creatorDid, db);
    didWbaResolved = resolution.resolved;
  }

  // Public key validation (optional field, required when creator is did:wba)
  // - If provided: must be valid Ed25519 (base64url, 32 bytes decoded)
  // - If creator is did:wba: public_key is REQUIRED (did:wba IDs don't embed
  //   keys; without one, signatures cannot be verified)
  // - did:key creators may omit this — their key is encoded in the DID itself
  const publicKey = body.public_key ? String(body.public_key).trim() : null;
  if (publicKey) {
    const keyValidation = validatePublicKey(publicKey);
    if (!keyValidation.valid) {
      return json({ error: "Invalid public_key: " + keyValidation.error }, 400);
    }
  }
  if (isDidWba(creatorDid) && !publicKey) {
    return json({
      error: "did:wba creator_did requires a public_key field (Ed25519, base64url-encoded). did:key creators can omit this.",
    }, 400);
  }

  // Check for duplicate names (warn, don't block)
  const nameMatch = await db.prepare(
    "SELECT COUNT(*) as count FROM agents WHERE LOWER(name) = LOWER(?) AND status = 'active'"
  ).bind(name).first();
  const duplicateNameCount = nameMatch.count;

  // Generate AIR ID
  // AIR ID generation. The identity hash anchors on creator_did when present, or on
  // public_key when creator_did is absent (we still need a uniqueness contributor
  // beyond name + timestamp to avoid collision on rapid registrations).
  const identityDoc = creatorDid
    ? { name, description, creator_did: creatorDid, timestamp: new Date().toISOString() }
    : { name, description, public_key: publicKey, timestamp: new Date().toISOString() };
  const airId = await generateAirId(identityDoc);

  // Step 6: AIR-issued did:wba for keyless agents.
  // If creator_did was not supplied, mint one now that we have the AIR ID.
  // The minted DID points back at this registry and resolves at /agents/{air_id}/did-document.
  // The agent's identity is anchored by their public_key, which the DID document publishes.
  const airMintedDid = !creatorDid;
  if (airMintedDid) {
    creatorDid = `did:wba:agentidentityregistry.org:agents:${airId}`;
  }

  // Check for collision (extremely unlikely)
  const existing = await db.prepare("SELECT air_id FROM agents WHERE air_id = ?").bind(airId).first();
  if (existing) {
    return json({ error: "ID collision, please retry" }, 409);
  }

  const now = new Date().toISOString();

  // Generate per-agent secret for future PUT auth.
  // Plaintext is returned in the 201 response below and never stored — only its SHA-256
  // hash is persisted. If the caller loses the secret, the only recovery path is admin
  // DELETE + re-register. This matches the "API key shown once" pattern from Stripe, OpenAI, etc.
  const agentSecret = generateAgentSecret();
  const agentSecretHash = await sha256Hex(agentSecret);

  // Insert agent
  // did_wba_resolved is persisted only when the creator IS a did:wba (otherwise
  // the field is meaningless — NULL). did_wba_last_checked_at mirrors it: NULL
  // unless we actually checked. The weekly cron refreshes both for did:wba rows.
  const didWbaResolvedCol = isDidWba(creatorDid) ? (didWbaResolved ? 1 : 0) : null;
  const didWbaCheckedAtCol = isDidWba(creatorDid) ? now : null;
  const insertAgentStmt = db.prepare(
    `INSERT INTO agents (air_id, name, description, creator_did, creator_name, creator_type, capabilities, security_certifications, transparency_open_source, transparency_code_repo, transparency_docs_url, verification_level, verified, status, created_at, updated_at, public_key, agent_secret_hash, did_wba_resolved, did_wba_last_checked_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'self-verified', 0, 'active', ?, ?, ?, ?, ?, ?)`
  ).bind(airId, name, description, creatorDid, creatorName, creatorType, capabilities, securityCerts, openSource, codeRepo, docsUrl, now, now, publicKey, agentSecretHash, didWbaResolvedCol, didWbaCheckedAtCol);

  // Calculate and insert trust score
  const agentRow = {
    creator_did: creatorDid,
    creator_name: creatorName,
    creator_type: creatorType,
    transparency_open_source: openSource,
    transparency_code_repo: codeRepo,
    transparency_docs_url: docsUrl,
    security_certifications: securityCerts,
  };
  const score = calculateInitialTrustScore(agentRow);

  const insertTrustStmt = db.prepare(
    `INSERT INTO trust_scores (air_id, total_score, grade, provenance, behavioral, transparency, security, peer_attestations, calculated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(airId, score.total_score, score.grade, score.provenance, score.behavioral, score.transparency, score.security, score.peer_attestations, now);

  // Record the "registered" audit event and commit it in ONE atomic batch with
  // the agent + trust-score inserts. audit-or-fail: if the audit insert can't be
  // written (UNIQUE(prev_hash) contention), the whole registration rolls back.
  const auditStmt = await recordAuditEvent(db, { airId, event: "registered", changedFields: null, actor: "registrant", now });
  try {
    await db.batch([insertAgentStmt, insertTrustStmt, auditStmt]);
  } catch (err) {
    if (isAuditChainContention(err)) {
      return json({ error: "audit chain contention, please retry", air_id: airId }, 409);
    }
    throw err;
  }

  const warnings = [];
  if (duplicateNameCount > 0) {
    warnings.push("An agent named '" + name + "' already exists (" + duplicateNameCount + " existing). Your agent has been assigned a unique AIR ID.");
  }

  return json({
    air_id: airId,
    name,
    creator_did: creatorDid, // echoed for clarity; may be AIR-minted (see air_minted_did flag)
    air_minted_did: airMintedDid || undefined, // true when AIR generated the did:wba; omitted otherwise
    status: "active",
    verification_level: "self-verified",
    trust_score: score.total_score,
    trust_grade: score.grade,
    created: now,
    public_key: publicKey || undefined, // omit from response when not provided
    did_wba_resolved: didWbaResolved, // undefined for non-did:wba creators; true/false otherwise
    agent_secret: agentSecret, // SAVE THIS — shown only at registration, required for PUT updates
    agent_secret_note: "Store agent_secret securely. It is required to update this agent's record (PUT /agents/" + airId + ") via the X-Agent-Secret header. This value is not retrievable later — if lost, the only recovery is admin DELETE + re-register.",
    warnings: warnings.length > 0 ? warnings : undefined,
    message: "Agent registered successfully. Submit verification documents to upgrade trust level.",
  }, 201);
}

// ============================================================
// UPDATE AGENT
// ============================================================

async function updateAgent(request, airId, db) {
  // Verify agent exists
  const existing = await db.prepare("SELECT * FROM agents WHERE air_id = ? AND status = 'active'").bind(airId).first();
  if (!existing) {
    return json({ error: "Agent not found", air_id: airId }, 404);
  }

  // Authentication: require X-Agent-Secret matching the stored hash.
  // Constant-time comparison prevents timing-side-channel attacks.
  const providedSecret = request.headers.get("X-Agent-Secret");
  if (!providedSecret) {
    return json({ error: "Missing X-Agent-Secret header. Updates require the secret returned at registration." }, 401);
  }
  if (!existing.agent_secret_hash) {
    // Legacy seed agents predate Step 4 — no stored secret to compare against.
    return json({ error: "Agent has no PUT auth secret on file (legacy agent). Contact admin." }, 401);
  }
  const providedHash = await sha256Hex(providedSecret);
  if (!constantTimeEquals(providedHash, existing.agent_secret_hash)) {
    return json({ error: "Invalid agent secret" }, 401);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Invalid JSON body" }, 400);
  }

  // Single timestamp for this update: used as updated_at, the cooldown-gate "now",
  // and any tombstone released_at so they're all consistent within one PUT.
  const now = new Date().toISOString();

  // Only allow updating specific fields
  const updates = [];
  const binds = [];
  // Public-facing names of the fields the caller actually changed — recorded in
  // the audit log so history shows WHAT changed (not the internal column names).
  const changedFields = [];
  // Extra statements (username tombstone INSERT/DELETE) threaded into the SAME
  // atomic batch as the agents UPDATE + audit insert. Built in the username branch.
  const usernameStmts = [];
  // The handle being claimed this PUT (normalized), or null. Used only to label a
  // UNIQUE-index 409 if another agent wins the FCFS race.
  let claimedUsername = null;

  if (body.description !== undefined) {
    updates.push("description = ?");
    binds.push(String(body.description).trim().slice(0, 2000));
    changedFields.push("description");
  }
  if (body.capabilities !== undefined && Array.isArray(body.capabilities)) {
    updates.push("capabilities = ?");
    binds.push(JSON.stringify(body.capabilities.slice(0, 20)));
    changedFields.push("capabilities");
  }
  if (body.security_certifications !== undefined && Array.isArray(body.security_certifications)) {
    updates.push("security_certifications = ?");
    binds.push(JSON.stringify(body.security_certifications.slice(0, 10)));
    changedFields.push("security_certifications");
  }
  if (body.open_source !== undefined) {
    updates.push("transparency_open_source = ?");
    binds.push(body.open_source ? 1 : 0);
    changedFields.push("open_source");
  }
  if (body.code_repository !== undefined) {
    updates.push("transparency_code_repo = ?");
    binds.push(String(body.code_repository).trim().slice(0, 500));
    changedFields.push("code_repository");
  }
  if (body.documentation_url !== undefined) {
    updates.push("transparency_docs_url = ?");
    binds.push(String(body.documentation_url).trim().slice(0, 500));
    changedFields.push("documentation_url");
  }
  // service_endpoints — W3C did-core service[] entries appended to the DID document.
  // Phase 3 Stage 3.0.1a. Strict validation: array of objects each with string `type`
  // and string `serviceEndpoint` (URL form). Optional string `id`. Empty array clears.
  if (body.service_endpoints !== undefined) {
    const result = validateServiceEndpoints(body.service_endpoints);
    if (!result.valid) {
      return json({ error: "Invalid service_endpoints: " + result.error }, 400);
    }
    updates.push("service_endpoints = ?");
    binds.push(result.normalized.length === 0 ? null : JSON.stringify(result.normalized));
    changedFields.push("service_endpoints");
  }
  // username (@handle) — Milestone G. The published, unique, claimable handle.
  // Layered uniqueness: this branch read-gates on the cooldown tombstone for UX,
  // while the uq_agents_username UNIQUE index is the race-proof FCFS backstop
  // (caught in the batch catch below). Tombstone INSERT/DELETE statements are
  // queued into usernameStmts so they commit atomically with the UPDATE.
  if (body.username !== undefined) {
    if (body.username === null || body.username === "") {
      // Clearing the handle. Skip validation/cooldown; release any held handle.
      updates.push("username = ?");
      binds.push(null);
      changedFields.push("username");
      if (existing.username) {
        usernameStmts.push(
          db.prepare(
            "INSERT OR REPLACE INTO username_tombstones (username_normalized, released_by_air_id, released_at, username_display) VALUES (?, ?, ?, ?)"
          ).bind(existing.username, airId, now, existing.username)
        );
      }
    } else {
      const v = validateUsername(body.username);
      if (!v.valid) {
        return json({ error: "Invalid username: " + v.error }, 400);
      }
      if (v.normalized === existing.username) {
        // Unchanged — no-op. Do not push an update or tombstone.
      } else {
        // Cooldown read-gate: a handle released by a DIFFERENT agent within the
        // window is not yet claimable. The agent's own air id is the claimant.
        const tomb = await db.prepare(
          "SELECT released_by_air_id, released_at FROM username_tombstones WHERE username_normalized = ?"
        ).bind(v.normalized).first();
        if (isHandleInCooldown(tomb, airId, Date.parse(now))) {
          return json({ error: "Username is in a cooldown period and not yet claimable", username: v.normalized }, 409);
        }
        updates.push("username = ?");
        binds.push(v.normalized);
        changedFields.push("username");
        claimedUsername = v.normalized;
        // Releasing the old handle (if any) as part of claiming a different one.
        if (existing.username && existing.username !== v.normalized) {
          usernameStmts.push(
            db.prepare(
              "INSERT OR REPLACE INTO username_tombstones (username_normalized, released_by_air_id, released_at, username_display) VALUES (?, ?, ?, ?)"
            ).bind(existing.username, airId, now, existing.username)
          );
        }
        // The freshly-claimed handle is active again — clear any own/expired tombstone for it.
        usernameStmts.push(
          db.prepare("DELETE FROM username_tombstones WHERE username_normalized = ?").bind(v.normalized)
        );
      }
    }
  }

  if (updates.length === 0) {
    return json({ error: "No valid fields to update. Updatable fields: description, capabilities, security_certifications, open_source, code_repository, documentation_url, service_endpoints, username" }, 400);
  }

  updates.push("updated_at = ?");
  binds.push(now);
  binds.push(airId);

  const updateStmt = db.prepare(
    "UPDATE agents SET " + updates.join(", ") + " WHERE air_id = ?"
  ).bind(...binds);

  // Record the "updated" audit event and commit it in ONE atomic batch with the
  // UPDATE. audit-or-fail: if the audit insert can't be written (UNIQUE(prev_hash)
  // contention), the field update rolls back too.
  const auditStmt = await recordAuditEvent(db, { airId, event: "updated", changedFields, actor: "owner", now });
  try {
    // Atomic: UPDATE + username tombstone INSERT/DELETE(s) + audit insert commit
    // together or not at all. Tombstones sit between the UPDATE and the audit tip
    // insert (which the contention guard targets).
    await db.batch([updateStmt, ...usernameStmts, auditStmt]);
  } catch (err) {
    if (isUsernameConflict(err)) {
      // FCFS backstop: another active agent already holds this handle (UNIQUE index).
      return json({ error: "Username already taken", username: claimedUsername }, 409);
    }
    if (isAuditChainContention(err)) {
      return json({ error: "audit chain contention, please retry", air_id: airId }, 409);
    }
    throw err;
  }

  // Recalculate trust score with updated data. Routes through recomputeTrustScore
  // so an agent edit preserves earned trust instead of wiping peer back to 300 (#3).
  try {
    await recomputeTrustScore(airId, db);
  } catch (e) {
    console.error("recomputeTrustScore (updateAgent) failed:", e);
  }

  // Echo the freshly-recomputed score so the response keeps its trust_score/trust_grade fields.
  const refreshed = await db.prepare(
    "SELECT total_score, grade FROM trust_scores WHERE air_id = ?"
  ).bind(airId).first();

  return json({
    air_id: airId,
    updated_fields: updates.length - 1, // exclude updated_at
    trust_score: refreshed?.total_score ?? null,
    trust_grade: refreshed?.grade ?? null,
    updated: now,
    message: "Agent updated successfully.",
  });
}

// ============================================================
// DELETE AGENT (admin only)
// ============================================================

async function deleteAgent(airId, db) {
  const existing = await db.prepare("SELECT air_id, name, username FROM agents WHERE air_id = ? AND status = 'active'").bind(airId).first();
  if (!existing) {
    return json({ error: "Agent not found", air_id: airId }, 404);
  }

  // Soft delete — set status to 'deleted' rather than removing the row. Also clear
  // username: the partial UNIQUE index (uq_agents_username WHERE username IS NOT NULL)
  // is NOT status-scoped, so a deleted row that kept its handle would occupy the index
  // forever (handle permanently unclaimable) while check-username reports it available.
  // Mirrors the owner-clear release path in updateAgent.
  const now = new Date().toISOString();
  const deleteStmt = db.prepare(
    "UPDATE agents SET status = 'deleted', username = NULL, updated_at = ? WHERE air_id = ?"
  ).bind(now, airId);

  // If the agent held a handle, tombstone it (same 30-day cooldown as a manual release).
  const usernameStmts = [];
  if (existing.username) {
    usernameStmts.push(
      db.prepare(
        "INSERT OR REPLACE INTO username_tombstones (username_normalized, released_by_air_id, released_at, username_display) VALUES (?, ?, ?, ?)"
      ).bind(existing.username, airId, now, existing.username)
    );
  }

  // Record the "deleted" audit event and commit it in ONE atomic batch with the
  // soft-delete UPDATE. audit-or-fail: if the audit insert can't be written
  // (UNIQUE(prev_hash) contention), the soft-delete rolls back too. The audit-tip
  // insert stays LAST so the contention guard targets it.
  const auditStmt = await recordAuditEvent(db, { airId, event: "deleted", changedFields: null, actor: "admin", now });
  try {
    await db.batch([deleteStmt, ...usernameStmts, auditStmt]);
  } catch (err) {
    if (isAuditChainContention(err)) {
      return json({ error: "audit chain contention, please retry", air_id: airId }, 409);
    }
    throw err;
  }

  // Dead-vouch filter (#3): this agent's vouches no longer count — rescore everyone
  // it vouched for so their trust + Verified drop immediately.
  try {
    await recomputeDependentsOf(airId, db);
  } catch (e) {
    console.error("recomputeDependentsOf (deleteAgent) failed:", e);
  }

  return json({
    air_id: airId,
    name: existing.name,
    status: "deleted",
    deleted_at: now,
    message: "Agent deleted (soft delete). Data retained for audit purposes.",
  });
}

// ============================================================
// AGENT-RECORD AUDIT LOG — public read endpoints (registry #5)
// ============================================================
//
// GET /api/v1/agents/{air_id}/history — paginated, tamper-evident change log
// for one agent. Returns the hash-linked entries (prev_hash + entry_hash) so a
// third party can independently re-verify the chain.

async function getAgentHistory(airId, url, db) {
  const limit = Math.min(parseInt(url.searchParams.get("limit") || "50"), 100);
  const offset = parseInt(url.searchParams.get("offset") || "0");
  const { results } = await db.prepare(
    "SELECT id, event, changed_fields, actor, created_at, prev_hash, entry_hash FROM agent_audit_log WHERE air_id = ? ORDER BY id ASC LIMIT ? OFFSET ?"
  ).bind(airId, limit, offset).all();
  const countRow = await db.prepare("SELECT COUNT(*) AS n FROM agent_audit_log WHERE air_id = ?").bind(airId).first();
  return json({
    air_id: airId,
    history: (results || []).map((r) => ({
      id: r.id, event: r.event,
      changed_fields: r.changed_fields ? JSON.parse(r.changed_fields) : null,
      actor: r.actor, created_at: r.created_at, prev_hash: r.prev_hash, entry_hash: r.entry_hash,
    })),
    total: countRow?.n ?? 0,
    limit, offset,
    note: "Agent-record history tracked since 2026-06-09 (audit-log launch).",
  });
}

// GET /api/v1/audit/verify?from=&to= — bounded integrity check of the global
// audit chain. Recomputes each entry's hash and confirms the prev_hash linkage.
// `from`/`to` keep the walk cheap on large logs.

async function getAuditVerify(url, env) {
  const fromId = parseInt(url.searchParams.get("from") || "0");
  const toParam = url.searchParams.get("to");
  const toId = toParam ? parseInt(toParam) : null;
  const result = await verifyAuditChain(env.DB, { fromId, toId });
  // Cross-check the live tip against the latest external anchor. Best-effort:
  // last_anchor is null when no anchor is published or GitHub is unreachable,
  // so the integrity verdict never depends on a third party being available.
  const tip = await computeChainTip(env.DB);
  const anchor = await fetchLatestAnchor(env); // best-effort, may be null
  let pinnedPub = null;
  try { pinnedPub = base64urlToBytes(ANCHOR_PUBLIC_KEY_B64URL); } catch { /* key not provisioned yet */ }
  const last_anchor = anchor ? {
    anchored_at: anchor.anchored_at,
    tip_hash: anchor.tip_hash,
    entry_count: anchor.entry_count,
    matches: tip.tip_hash === anchor.tip_hash && tip.count >= anchor.entry_count,
    // Authenticity of the anchor artifact against the PINNED key (null if we
    // can't yet — no key provisioned). A verifier must also reject an UNSIGNED
    // anchor dated >= ANCHOR_SIGNING_EFFECTIVE and enforce monotonic entry_count
    // across the series (rollback is caught by git history, not the signature).
    signature_valid: pinnedPub ? await verifyAnchorSignature(anchor, pinnedPub) : null,
  } : null;
  return json({ ...result, live_tip_hash: tip.tip_hash, live_count: tip.count, signing_effective: ANCHOR_SIGNING_EFFECTIVE, last_anchor });
}

// ============================================================
// NAME CHECK
// ============================================================

async function checkName(url, db) {
  const name = (url.searchParams.get("name") || "").trim();
  if (!name) return json({ error: "Query parameter 'name' is required" }, 400);

  const match = await db.prepare(
    "SELECT air_id, name FROM agents WHERE LOWER(name) = LOWER(?) AND status = 'active' LIMIT 5"
  ).bind(name).all();

  return json({
    name: name,
    exists: match.results.length > 0,
    count: match.results.length,
    existing_agents: match.results.map(function(r) { return { air_id: r.air_id, name: r.name }; }),
  });
}

// ============================================================
// USERNAME (@handle) CHECK + RESOLVER (Milestone G)
// ============================================================

// GET /api/v1/agents/check-username?username=...
// Pre-claim availability probe. A handle is available only when no active agent
// holds it AND no unexpired tombstone blocks it. Invalid handles return 200 with
// valid:false (so the UI can show the reason), matching checkName's soft style.
async function checkUsername(url, db) {
  const raw = url.searchParams.get("username") || "";
  const v = validateUsername(raw);
  if (!v.valid) {
    return json({ username: raw, valid: false, available: false, error: v.error }, 200);
  }
  const normalized = v.normalized;
  const held = await db.prepare(
    "SELECT air_id FROM agents WHERE LOWER(username) = ? AND status = 'active' LIMIT 1"
  ).bind(normalized).first();
  const tomb = await db.prepare(
    "SELECT released_by_air_id, released_at FROM username_tombstones WHERE username_normalized = ?"
  ).bind(normalized).first();
  // null claimant = pure availability probe: any unexpired tombstone blocks.
  const inCooldown = isHandleInCooldown(tomb, null, Date.now());
  return json({
    username: normalized,
    valid: true,
    available: !held && !inCooldown,
    reason: held ? "taken" : (inCooldown ? "cooldown" : "available"),
  }, 200);
}

// GET /api/v1/agents/by-username/{handle}
// Resolves a published @handle to its full agent record. Delegates to getAgent
// so the shape is identical to GET /agents/{air_id}.
async function getAgentByUsername(handle, db) {
  // Resolver: normalize with the charset check ONLY. Reservation is a claim-time
  // policy — a handle claimed before a word became reserved must still resolve.
  const normalized = lookupHandle(handle);
  if (normalized === null) {
    return json({ error: "Invalid username" }, 400);
  }
  const row = await db.prepare(
    "SELECT air_id FROM agents WHERE LOWER(username) = ? AND status = 'active' LIMIT 1"
  ).bind(normalized).first();
  if (!row) {
    return json({ error: "No agent with that username" }, 404);
  }
  return getAgent(row.air_id, db);
}

// ============================================================
// ATTESTATION ENDPOINTS (AIR Verified — Phase 4, migrations/0004)
// ============================================================
//
// POST /api/v1/agents/{air_id}/attestations
// Body: { attester_air_id, attestation_type, statement?, signed_at, signature_multibase }
// Header: X-Agent-Secret (the attester's secret — proves they own the attester record)
//
// The signed_payload that the attester signed is the JCS-canonical bytes of:
//   { attester_air_id, attestation_type, signed_at, statement, subject_air_id }
// (keys sorted alphabetically per JCS — see jcsCanonicalize)
//
// Returns 201 with the inserted attestation + the subject's updated verified status.
// Returns 400 on invalid input / signature failure (Lock 1).
// Returns 401 on missing/wrong attester secret.
// Returns 403 if attester fails eligibility (Locks 1, 3, 5).
// Returns 409 if Lock 2 (WHOIS-root distinctness) fails.

const VALID_ATTESTATION_TYPES = new Set([
  "identity_verification",  // I confirm this agent's claimed identity is real
  "operator_confirmation",  // I confirm this agent is operated by its claimed creator
  "dependency",             // I depend on this agent in production
  "safety_review",          // I have reviewed and trust this agent's safety
]);

// Attestation signed_at freshness window (replay defense; see migration 0005 +
// [[air/trust-graph-coldstart-2026-06-02]]). signed_at is part of the signed
// payload, so bounding it limits how stale/early a first-time submission may be;
// UNIQUE(signature_multibase) is the hard backstop against exact replay.
const ATTESTATION_MAX_AGE_MS = 60 * 60 * 1000; // 1h — signed_at must be recent
const ATTESTATION_FUTURE_SKEW_MS = 5 * 60 * 1000; // tolerate 5m of clock skew ahead

async function createAttestation(request, subjectAirId, db) {
  // ---- 1. Parse + validate body shape -------------------------------------
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "invalid JSON body" }, 400);
  }
  const {
    attester_air_id,
    attestation_type,
    signed_at,
    signature_multibase,
    statement = "",
  } = body || {};
  for (const [k, v] of [
    ["attester_air_id", attester_air_id],
    ["attestation_type", attestation_type],
    ["signed_at", signed_at],
    ["signature_multibase", signature_multibase],
  ]) {
    if (typeof v !== "string" || v.length === 0) {
      return json({ error: `missing or invalid '${k}'` }, 400);
    }
  }
  if (typeof statement !== "string") {
    return json({ error: "'statement' must be a string if provided" }, 400);
  }
  if (!VALID_ATTESTATION_TYPES.has(attestation_type)) {
    return json({
      error: "invalid attestation_type",
      message: `must be one of: ${[...VALID_ATTESTATION_TYPES].join(", ")}`,
    }, 400);
  }

  // Replay defense: signed_at must be a valid, recent ISO-8601 timestamp.
  // It is part of the signed payload; UNIQUE(signature_multibase) (migration 0005)
  // blocks exact re-insertion, and this bounds how stale/early a first submission
  // may be. Placed early so it is reachable without an eligible attester.
  const signedAtMs = Date.parse(signed_at);
  if (Number.isNaN(signedAtMs)) {
    return json({ error: "'signed_at' must be an ISO-8601 timestamp" }, 400);
  }
  const nowMs = Date.now();
  if (signedAtMs > nowMs + ATTESTATION_FUTURE_SKEW_MS) {
    return json({ error: "'signed_at' is in the future", hint: "check the signer's clock (max +5m skew)" }, 400);
  }
  if (signedAtMs < nowMs - ATTESTATION_MAX_AGE_MS) {
    return json({ error: "'signed_at' is too old; re-sign with a current timestamp", max_age_seconds: ATTESTATION_MAX_AGE_MS / 1000 }, 400);
  }

  // ---- 2. Self-attestation guard + subject existence ---------------------
  if (subjectAirId === attester_air_id) {
    return json({ error: "self-attestation is not allowed" }, 400);
  }
  const subject = await db.prepare(
    "SELECT air_id, creator_did, status FROM agents WHERE air_id = ?"
  ).bind(subjectAirId).first();
  if (!subject) {
    return json({ error: "subject agent not found", air_id: subjectAirId }, 404);
  }
  if (subject.status !== "active") {
    return json({ error: "subject agent is not active" }, 409);
  }

  // ---- 3. Authenticate attester via X-Agent-Secret -----------------------
  // Proves they control the AIR record they claim to be attesting from.
  // Separate from Lock 1 (which checks they ALSO control the underlying did:wba).
  const secret = request.headers.get("X-Agent-Secret");
  if (!secret) {
    return json({ error: "X-Agent-Secret header required for attestation" }, 401);
  }
  const attesterAuth = await db.prepare(
    "SELECT agent_secret_hash FROM agents WHERE air_id = ?"
  ).bind(attester_air_id).first();
  if (!attesterAuth?.agent_secret_hash) {
    return json({ error: "attester has no secret on file" }, 401);
  }
  const providedHash = await sha256Hex(secret);
  if (!constantTimeEquals(providedHash, attesterAuth.agent_secret_hash)) {
    return json({ error: "invalid attester secret" }, 401);
  }

  // Duplicate guard: at most one ACTIVE attestation per (subject, attester).
  // Re-attesting after revocation is allowed (revoked rows are excluded). The
  // partial UNIQUE index from migration 0005 is the hard backstop; this returns
  // a clean 409 and avoids the network-heavy eligibility check below.
  const existingActive = await db.prepare(
    "SELECT id FROM agent_attestations WHERE subject_air_id = ? AND attester_air_id = ? AND revoked_at IS NULL"
  ).bind(subjectAirId, attester_air_id).first();
  if (existingActive) {
    return json({
      error: "an active attestation from this attester to this subject already exists",
      attestation_id: existingActive.id,
      hint: "revoke the existing attestation before issuing a new one",
    }, 409);
  }

  // ---- 4. Run eligibility locks (Locks 1 + 3 + 5 + Lock 2 prep) ---------
  const elig = await getAttesterEligibility(attester_air_id, db);
  if (!elig.eligible) {
    return json({ error: "attester not eligible", reason: elig.reason }, 403);
  }

  // ---- 5. Lock 2: WHOIS-root distinctness --------------------------------
  // 5a. Subject's WHOIS root (only checkable if subject is did:wba).
  if (isDidWba(subject.creator_did)) {
    try {
      const subjectRoot = extractWhoisRoot(subject.creator_did);
      if (subjectRoot === elig.whois_root) {
        return json({
          error: "Lock 2: attester and subject share the same WHOIS root",
          whois_root: subjectRoot,
        }, 409);
      }
    } catch {
      return json({
        error: "Lock 2: subject WHOIS root could not be extracted",
      }, 500);
    }
  }
  // 5b. Each existing active attester must be on a different WHOIS root.
  const existingRoots = await db.prepare(`
    SELECT DISTINCT attester_whois_root FROM agent_attestations
    WHERE subject_air_id = ? AND revoked_at IS NULL
  `).bind(subjectAirId).all();
  for (const row of (existingRoots?.results ?? [])) {
    if (row.attester_whois_root === elig.whois_root) {
      return json({
        error: "Lock 2: another active attestation on this subject already uses your WHOIS root",
        whois_root: elig.whois_root,
      }, 409);
    }
  }

  // ---- 6. Verify Ed25519 signature over JCS-canonical payload ----------
  const canonicalPayload = jcsCanonicalize({
    attester_air_id,
    attestation_type,
    signed_at,
    statement,
    subject_air_id: subjectAirId,
  });
  const payloadBytes = new TextEncoder().encode(canonicalPayload);
  const sigOk = await verifyEd25519Signature(
    elig.public_key, payloadBytes, signature_multibase
  );
  if (!sigOk) {
    return json({
      error: "Lock 1: Ed25519 signature verification failed",
      hint: "Sign the JCS-canonical bytes of {attester_air_id, attestation_type, signed_at, statement, subject_air_id} with your Ed25519 private key, then multibase-encode (z + base58btc).",
    }, 400);
  }

  // ---- 7. Insert attestation ------------------------------------------
  const nowIso = new Date().toISOString();
  let insertResult;
  try {
    insertResult = await db.prepare(`
      INSERT INTO agent_attestations
        (subject_air_id, attester_air_id, attester_whois_root, attestation_type,
         statement, signed_payload, signature_multibase, signed_at,
         attester_trust_at_issue, tenure_multiplier_at_issue, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      subjectAirId,
      attester_air_id,
      elig.whois_root,
      attestation_type,
      statement,
      canonicalPayload,
      signature_multibase,
      signed_at,
      elig.attester_trust,
      elig.tenure_multiplier,
      nowIso,
    ).run();
  } catch (e) {
    const dbErr = String(e.message ?? e);
    // The UNIQUE indexes from migration 0005 (signature, active subject+attester)
    // are the hard backstop against a race that slips past the checks above.
    if (/UNIQUE constraint failed/i.test(dbErr)) {
      return json({ error: "duplicate attestation (this signature, or an active attestation for this subject+attester, already exists)" }, 409);
    }
    return json({ error: "database error", message: dbErr }, 500);
  }

  // Earned-trust feedback (#3): the new vouch may raise the subject's trust.
  // Best-effort — the attestation is already committed; staleness self-heals.
  try {
    await recomputeTrustScore(subjectAirId, db);
  } catch (e) {
    console.error("recomputeTrustScore (createAttestation) failed:", e);
  }

  // ---- 8. Updated verified status (so caller knows the threshold delta) -
  const verifiedStatus = await computeVerifiedStatus(subjectAirId, db);

  return json({
    attestation_id: insertResult.meta?.last_row_id,
    subject_air_id: subjectAirId,
    attester_air_id,
    attestation_type,
    statement,
    signed_at,
    attester_whois_root: elig.whois_root,
    attester_trust_at_issue: elig.attester_trust,
    tenure_multiplier_at_issue: elig.tenure_multiplier,
    weight: elig.attester_trust * elig.tenure_multiplier,
    verified_status: verifiedStatus,
  }, 201);
}

// GET /api/v1/agents/{air_id}/attestations
// PUBLIC — returns full attestation list (including revoked, marked as such)
// so anyone can audit the trust graph. Audit IS part of Lock 6.
async function listAttestations(subjectAirId, db) {
  const subject = await db.prepare(
    "SELECT air_id FROM agents WHERE air_id = ?"
  ).bind(subjectAirId).first();
  if (!subject) {
    return json({ error: "agent not found", air_id: subjectAirId }, 404);
  }

  const result = await db.prepare(`
    SELECT id, attester_air_id, attester_whois_root, attestation_type,
           statement, signed_payload, signature_multibase, signed_at,
           attester_trust_at_issue, tenure_multiplier_at_issue,
           revoked_at, created_at
    FROM agent_attestations
    WHERE subject_air_id = ?
    ORDER BY signed_at DESC
  `).bind(subjectAirId).all();

  const attestations = (result?.results ?? []).map(row => ({
    id: row.id,
    attester_air_id: row.attester_air_id,
    attester_whois_root: row.attester_whois_root,
    attestation_type: row.attestation_type,
    statement: row.statement,
    signed_payload: row.signed_payload,
    signature_multibase: row.signature_multibase,
    signed_at: row.signed_at,
    attester_trust_at_issue: row.attester_trust_at_issue,
    tenure_multiplier_at_issue: row.tenure_multiplier_at_issue,
    weight: row.attester_trust_at_issue * row.tenure_multiplier_at_issue,
    revoked_at: row.revoked_at,
    is_active: row.revoked_at === null,
    created_at: row.created_at,
  }));

  const verifiedStatus = await computeVerifiedStatus(subjectAirId, db);

  return json({
    subject_air_id: subjectAirId,
    attestations,
    total: attestations.length,
    active: attestations.filter(a => a.is_active).length,
    verified_status: verifiedStatus,
  });
}

// GET /api/v1/attestations/recent?limit=N
// PUBLIC firehose of recent active attestations. Used for:
//   - Building a dashboard / "live activity" view
//   - Spotting Sybil rings (3 fresh attesters all on the same fresh subject = smell)
//   - Backfilling local mirrors of the trust graph
// Default limit 50, max 200.
async function recentAttestations(url, db) {
  const limitRaw = parseInt(url.searchParams.get("limit") || "50", 10);
  const limit = Math.max(1, Math.min(isNaN(limitRaw) ? 50 : limitRaw, 200));

  const result = await db.prepare(`
    SELECT id, subject_air_id, attester_air_id, attester_whois_root,
           attestation_type, statement, signed_at,
           attester_trust_at_issue, tenure_multiplier_at_issue, created_at
    FROM agent_attestations
    WHERE revoked_at IS NULL
    ORDER BY signed_at DESC
    LIMIT ?
  `).bind(limit).all();

  const items = (result?.results ?? []).map(row => ({
    id: row.id,
    subject_air_id: row.subject_air_id,
    attester_air_id: row.attester_air_id,
    attester_whois_root: row.attester_whois_root,
    attestation_type: row.attestation_type,
    statement: row.statement,
    signed_at: row.signed_at,
    weight: row.attester_trust_at_issue * row.tenure_multiplier_at_issue,
    created_at: row.created_at,
  }));

  return json({
    attestations: items,
    total: items.length,
    limit,
  });
}

// DELETE /api/v1/agents/{subject_air_id}/attestations/{attestation_id}
// Soft-deletes an attestation. Only the original attester can revoke.
// Auth via X-Agent-Secret of the attester (not the subject).
async function revokeAttestation(request, subjectAirId, attestationIdRaw, db) {
  const attestationId = parseInt(attestationIdRaw, 10);
  if (isNaN(attestationId) || attestationId < 1) {
    return json({ error: "invalid attestation_id" }, 400);
  }

  const att = await db.prepare(`
    SELECT id, subject_air_id, attester_air_id, revoked_at
    FROM agent_attestations WHERE id = ?
  `).bind(attestationId).first();
  if (!att) {
    return json({ error: "attestation not found", attestation_id: attestationId }, 404);
  }
  if (att.subject_air_id !== subjectAirId) {
    return json({
      error: "attestation does not belong to this subject",
      attestation_id: attestationId,
      claimed_subject: subjectAirId,
      actual_subject: att.subject_air_id,
    }, 400);
  }
  if (att.revoked_at) {
    return json({ error: "attestation already revoked", revoked_at: att.revoked_at }, 409);
  }

  const secret = request.headers.get("X-Agent-Secret");
  if (!secret) {
    return json({ error: "X-Agent-Secret header required (must be original attester's secret)" }, 401);
  }
  const attesterAuth = await db.prepare(
    "SELECT agent_secret_hash FROM agents WHERE air_id = ?"
  ).bind(att.attester_air_id).first();
  if (!attesterAuth?.agent_secret_hash) {
    return json({ error: "attester has no secret on file" }, 401);
  }
  const providedHash = await sha256Hex(secret);
  if (!constantTimeEquals(providedHash, attesterAuth.agent_secret_hash)) {
    return json({ error: "invalid attester secret (only the original attester can revoke)" }, 401);
  }

  const nowIso = new Date().toISOString();
  await db.prepare(`UPDATE agent_attestations SET revoked_at = ? WHERE id = ?`)
    .bind(nowIso, attestationId).run();

  // Earned-trust feedback (#3): removing a vouch may lower the subject's trust.
  try {
    await recomputeTrustScore(subjectAirId, db);
  } catch (e) {
    console.error("recomputeTrustScore (revokeAttestation) failed:", e);
  }

  const verifiedStatus = await computeVerifiedStatus(subjectAirId, db);
  return json({
    revoked: true,
    attestation_id: attestationId,
    subject_air_id: subjectAirId,
    revoked_at: nowIso,
    verified_status: verifiedStatus,
  });
}

// GET /api/v1/agents/{air_id}/badge.svg
// SVG badge showing the agent's evidence label (default):
//   - Verified  -> green "Verified ✓"
//   - Attested  -> blue "Attested"
//   - Self-declared / Registered -> gray (the label word)
//   - agent not found -> gray "not found"
// ?format=score returns the legacy numeric badge ("AIR Trust | <score>", blue;
//   gray "no score" if none). The <title> carries the neutrality disclaimer.
// 60s cache (so badges reflect label changes quickly).
async function getBadgeSvg(airId, db, format) {
  const agent = await db.prepare(`
    SELECT a.air_id, a.status, t.total_score, t.provenance, t.transparency, t.security
    FROM agents a LEFT JOIN trust_scores t ON a.air_id = t.air_id
    WHERE a.air_id = ?
  `).bind(airId).first();

  let leftLabel, rightLabel, rightColor;
  if (!agent) {
    leftLabel = "AIR";
    rightLabel = "not found";
    rightColor = "#9f9f9f";
  } else if (format === "score") {
    // Legacy numeric badge (opt-in via ?format=score): always shows the raw
    // score number, even for Verified agents. The default (no param) shows the
    // evidence-label word. ?format=score is a new param, so no existing embedder
    // relied on the old Verified->green default here.
    leftLabel = "AIR Trust";
    rightLabel = agent.total_score != null ? String(agent.total_score) : "no score";
    rightColor = agent.total_score != null ? "#007ec6" : "#9f9f9f";
  } else {
    const status = await computeVerifiedStatus(airId, db);
    const label = computeEvidenceLabel(status, {
      provenance: agent.provenance,
      transparency: agent.transparency,
      security: agent.security,
    });
    leftLabel = "AIR";
    if (label === "Verified") {
      rightLabel = "Verified ✓";
      rightColor = "#4c1";
    } else if (label === "Attested") {
      rightLabel = "Attested";
      rightColor = "#007ec6";
    } else {
      rightLabel = label; // "Self-declared" | "Registered"
      rightColor = "#9f9f9f";
    }
  }

  // Width budget — ~7px per character at 11px font in Verdana.
  const leftWidth = Math.max(45, leftLabel.length * 8 + 10);
  const rightWidth = Math.max(50, rightLabel.length * 7 + 12);
  const totalWidth = leftWidth + rightWidth;
  const leftMid = leftWidth / 2;
  const rightMid = leftWidth + rightWidth / 2;

  const escape = (s) =>
    s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="20" role="img" aria-label="${escape(leftLabel)}: ${escape(rightLabel)}">
  <title>${escape(leftLabel)}: ${escape(rightLabel)} — ${escape(EVIDENCE_LABEL_DISCLAIMER)}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r"><rect width="${totalWidth}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="${leftWidth}" height="20" fill="#555"/>
    <rect x="${leftWidth}" width="${rightWidth}" height="20" fill="${rightColor}"/>
    <rect width="${totalWidth}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text aria-hidden="true" x="${leftMid * 10}" y="150" transform="scale(.1)" fill="#000" fill-opacity=".3">${escape(leftLabel)}</text>
    <text x="${leftMid * 10}" y="140" transform="scale(.1)" fill="#fff">${escape(leftLabel)}</text>
    <text aria-hidden="true" x="${rightMid * 10}" y="150" transform="scale(.1)" fill="#000" fill-opacity=".3">${escape(rightLabel)}</text>
    <text x="${rightMid * 10}" y="140" transform="scale(.1)" fill="#fff">${escape(rightLabel)}</text>
  </g>
</svg>`;

  return new Response(svg, {
    status: 200,
    headers: {
      "Content-Type": "image/svg+xml; charset=utf-8",
      "Cache-Control": "public, max-age=60",
      "Access-Control-Allow-Origin": "*",
    },
  });
}

// ============================================================
// TRUST GRAPH (Phase 4+) — read views over agent_attestations
// ============================================================
//
// The attestation table is a directed graph: each active row is an edge
// attester -> subject ("vouches for"). `dependency`-type edges additionally
// mean "attester depends on subject in production", which powers blast-radius.
// All graph endpoints are PUBLIC and count active (non-revoked) edges only.

// GET /api/v1/agents/{air_id}/graph
// 1-hop ego graph: who vouches for this agent (inbound) + who it vouches for
// (outbound).
async function getAgentGraph(airId, db) {
  const agent = await db.prepare("SELECT air_id FROM agents WHERE air_id = ?").bind(airId).first();
  if (!agent) return json({ error: "agent not found", air_id: airId }, 404);

  const inbound = await db.prepare(`
    SELECT attester_air_id, attestation_type, attester_whois_root, signed_at,
           attester_trust_at_issue * tenure_multiplier_at_issue AS weight
    FROM agent_attestations
    WHERE subject_air_id = ? AND revoked_at IS NULL
    ORDER BY signed_at DESC
  `).bind(airId).all();

  const outbound = await db.prepare(`
    SELECT subject_air_id, attestation_type, signed_at,
           attester_trust_at_issue * tenure_multiplier_at_issue AS weight
    FROM agent_attestations
    WHERE attester_air_id = ? AND revoked_at IS NULL
    ORDER BY signed_at DESC
  `).bind(airId).all();

  const inb = (inbound?.results ?? []).map(r => ({
    attester_air_id: r.attester_air_id,
    attestation_type: r.attestation_type,
    attester_whois_root: r.attester_whois_root,
    weight: r.weight,
    signed_at: r.signed_at,
  }));
  const outb = (outbound?.results ?? []).map(r => ({
    subject_air_id: r.subject_air_id,
    attestation_type: r.attestation_type,
    weight: r.weight,
    signed_at: r.signed_at,
  }));

  return json({
    air_id: airId,
    inbound: inb,
    outbound: outb,
    inbound_count: inb.length,
    outbound_count: outb.length,
  });
}

// GET /api/v1/agents/{air_id}/dependents?depth=N&limit=M
// Blast radius: the transitive set of agents that depend (directly or via a
// chain) on this agent, following `dependency` edges in reverse. depth default
// 6 (max 10), limit default 500 (max 1000). `truncated` flags when the node
// cap clipped the result — never silently truncate.
async function getDependents(airId, url, db) {
  const agent = await db.prepare("SELECT air_id FROM agents WHERE air_id = ?").bind(airId).first();
  if (!agent) return json({ error: "agent not found", air_id: airId }, 404);

  const depthRaw = parseInt(url.searchParams.get("depth") || "6", 10);
  const depth = Math.max(1, Math.min(isNaN(depthRaw) ? 6 : depthRaw, 10));
  const limitRaw = parseInt(url.searchParams.get("limit") || "500", 10);
  const limit = Math.max(1, Math.min(isNaN(limitRaw) ? 500 : limitRaw, 1000));

  // UNION (not UNION ALL) dedups cycles; the depth guard bounds recursion.
  // Fetch limit+1 rows so we can detect (and report) truncation.
  const result = await db.prepare(`
    WITH RECURSIVE dependents(air_id, depth) AS (
      SELECT attester_air_id, 1 FROM agent_attestations
        WHERE subject_air_id = ? AND attestation_type = 'dependency' AND revoked_at IS NULL
      UNION
      SELECT a.attester_air_id, d.depth + 1
        FROM agent_attestations a JOIN dependents d ON a.subject_air_id = d.air_id
        WHERE a.attestation_type = 'dependency' AND a.revoked_at IS NULL AND d.depth < ?
    )
    SELECT air_id, MIN(depth) AS depth FROM dependents
      WHERE air_id != ?
      GROUP BY air_id ORDER BY depth, air_id LIMIT ?
  `).bind(airId, depth, airId, limit + 1).all();

  const rows = result?.results ?? [];
  const truncated = rows.length > limit;
  const dependents = rows.slice(0, limit).map(r => ({ air_id: r.air_id, depth: r.depth }));

  return json({
    air_id: airId,
    dependents,
    total: dependents.length,
    max_depth: depth,
    truncated,
  });
}

// GET /api/v1/graph/stats
// Global trust-graph summary: node + edge counts, edges by type, plus the
// most-attested agents and most-active attesters.
async function getGraphStats(db) {
  const edges = await db.prepare(
    "SELECT COUNT(*) AS n FROM agent_attestations WHERE revoked_at IS NULL"
  ).first();
  const nodes = await db.prepare(`
    SELECT COUNT(DISTINCT subject_air_id) AS subjects,
           COUNT(DISTINCT attester_air_id) AS attesters
    FROM agent_attestations WHERE revoked_at IS NULL
  `).first();
  const distinctTotal = await db.prepare(`
    SELECT COUNT(*) AS n FROM (
      SELECT subject_air_id AS id FROM agent_attestations WHERE revoked_at IS NULL
      UNION
      SELECT attester_air_id AS id FROM agent_attestations WHERE revoked_at IS NULL
    )
  `).first();
  const byType = await db.prepare(`
    SELECT attestation_type AS t, COUNT(*) AS n FROM agent_attestations
    WHERE revoked_at IS NULL GROUP BY attestation_type
  `).all();
  const topAttested = await db.prepare(`
    SELECT subject_air_id AS air_id, COUNT(*) AS count FROM agent_attestations
    WHERE revoked_at IS NULL GROUP BY subject_air_id ORDER BY count DESC, air_id LIMIT 5
  `).all();
  const topAttesters = await db.prepare(`
    SELECT attester_air_id AS air_id, COUNT(*) AS count FROM agent_attestations
    WHERE revoked_at IS NULL GROUP BY attester_air_id ORDER BY count DESC, air_id LIMIT 5
  `).all();

  const byTypeObj = {};
  for (const r of (byType?.results ?? [])) byTypeObj[r.t] = r.n;

  return json({
    nodes: {
      subjects: nodes?.subjects ?? 0,
      attesters: nodes?.attesters ?? 0,
      total_distinct: distinctTotal?.n ?? 0,
    },
    edges: {
      active: edges?.n ?? 0,
      by_type: byTypeObj,
    },
    top_attested: (topAttested?.results ?? []).map(r => ({ air_id: r.air_id, count: r.count })),
    top_attesters: (topAttesters?.results ?? []).map(r => ({ air_id: r.air_id, count: r.count })),
  });
}

// ADMIN ENDPOINTS (API key protected)
// ============================================================

async function adminAuth(request, env) {
  const key = new URL(request.url).searchParams.get("key") ||
    request.headers.get("X-Admin-Key");
  if (!env.ADMIN_KEY || key !== env.ADMIN_KEY) {
    return json({ error: "Unauthorized" }, 401);
  }
  return null; // null means auth passed
}

async function adminStats(db) {
  const total = await db.prepare("SELECT COUNT(*) as count FROM agents WHERE status = 'active'").first();
  const verified = await db.prepare("SELECT COUNT(*) as count FROM agents WHERE verified = 1").first();
  const unverified = await db.prepare("SELECT COUNT(*) as count FROM agents WHERE verified = 0").first();
  const demoCount = await db.prepare("SELECT COUNT(*) as count FROM agents WHERE is_demo = 1").first();
  const realCount = await db.prepare("SELECT COUNT(*) as count FROM agents WHERE is_demo = 0 AND status = 'active'").first();

  const gradeDistribution = await db.prepare(
    "SELECT t.grade, COUNT(*) as count FROM trust_scores t JOIN agents a ON t.air_id = a.air_id WHERE a.status = 'active' GROUP BY t.grade ORDER BY t.total_score DESC"
  ).all();

  const recentCount = await db.prepare(
    "SELECT COUNT(*) as count FROM agents WHERE created_at > datetime('now', '-7 days')"
  ).first();

  const avgScore = await db.prepare(
    "SELECT ROUND(AVG(t.total_score)) as avg_score FROM trust_scores t JOIN agents a ON t.air_id = a.air_id WHERE a.status = 'active'"
  ).first();

  return json({
    total_agents: total.count,
    real_agents: realCount.count,
    demo_agents: demoCount.count,
    verified: verified.count,
    unverified: unverified.count,
    registered_last_7_days: recentCount.count,
    average_trust_score: avgScore.avg_score,
    grade_distribution: (gradeDistribution.results || []).reduce((acc, r) => {
      acc[r.grade] = r.count;
      return acc;
    }, {}),
  });
}

async function adminRecent(url, db) {
  const limit = Math.min(parseInt(url.searchParams.get("limit") || "20"), 100);

  const { results } = await db.prepare(
    `SELECT a.air_id, a.name, a.creator_did, a.creator_name, a.creator_type,
            a.verification_level, a.verified, a.is_demo, a.created_at,
            t.total_score, t.grade
     FROM agents a
     LEFT JOIN trust_scores t ON a.air_id = t.air_id
     WHERE a.status = 'active'
     ORDER BY a.created_at DESC
     LIMIT ?`
  ).bind(limit).all();

  return json({
    recent_registrations: results.map((r) => ({
      air_id: r.air_id,
      name: r.name,
      creator_did: r.creator_did,
      creator_name: r.creator_name || "(none)",
      creator_type: r.creator_type,
      verified: !!r.verified,
      is_demo: !!r.is_demo,
      verification_level: r.verification_level,
      trust_score: r.total_score,
      trust_grade: r.grade,
      registered: r.created_at,
    })),
    count: results.length,
  });
}

// ============================================================
// WEEKLY did:wba RE-RESOLUTION
// ============================================================
// Runs from two places:
//   * `scheduled()` — fires every Sunday 03:00 UTC per wrangler.toml's
//     [triggers] crons. No request, no caller, no laptop required.
//   * `POST /api/v1/admin/cron/did-wba-resolve` (admin auth) — manual
//     trigger for backfills + testing.
//
// Walks every active agent whose creator_did is a did:wba, re-resolves
// the agent's did.json over HTTP, and updates `did_wba_resolved` +
// `did_wba_last_checked_at` in the DB. Best-effort: failures on one
// agent never sink the batch.
//
// Concurrency: small batches via Promise.allSettled. Avoids fanning out
// hundreds of fetches simultaneously while keeping wall-clock reasonable.

const DID_WBA_CRON_BATCH = 5;

async function reResolveAllDidWba(db) {
  const startedAt = Date.now();

  const { results: agents } = await db.prepare(
    `SELECT air_id, creator_did, public_key
     FROM agents
     WHERE status = 'active' AND creator_did LIKE 'did:wba:%'`
  ).all();

  const summary = {
    total: agents.length,
    resolved: 0,
    unresolved: 0,
    write_errors: 0,
  };
  // Up to 5 distinct resolution-failure reasons, surfaced in the run summary so
  // operators can diagnose without wrangler tail (would have caught the 2026-06-02
  // did:wba self-fetch bug immediately).
  const errorSamples = new Set();

  for (let i = 0; i < agents.length; i += DID_WBA_CRON_BATCH) {
    const batch = agents.slice(i, i + DID_WBA_CRON_BATCH);
    // allSettled because resolveDidWba returns {resolved: false, ...} on
    // failure — it shouldn't throw, but defensive: a rejected promise here
    // would otherwise crash the whole cron run.
    const results = await Promise.allSettled(
      batch.map((a) => resolveDidWba(a.creator_did, db))
    );

    const now = new Date().toISOString();
    for (let j = 0; j < batch.length; j++) {
      const agent = batch[j];
      const settled = results[j];
      let resolvedBool =
        settled.status === "fulfilled" ? !!settled.value.resolved : false;
      let reason;
      if (!resolvedBool) {
        reason = settled.status === "fulfilled"
          ? (settled.value.error || "unknown")
          : "threw: " + ((settled.reason && settled.reason.message) || settled.reason);
      }
      // #4 key-binding drift: a resolved EXTERNAL doc that does not advertise the
      // agent's registered key is flagged (distinct from an unreachable host).
      if (resolvedBool && settled.status === "fulfilled" && settled.value.document &&
          !documentContainsKey(settled.value.document, agent.public_key)) {
        resolvedBool = false;
        reason = "did:wba key drift (published did.json does not advertise the registered key)";
      }
      if (resolvedBool) {
        summary.resolved++;
      } else {
        summary.unresolved++;
        if (errorSamples.size < 5) errorSamples.add(reason);
      }

      try {
        await db.prepare(
          `UPDATE agents
           SET did_wba_resolved = ?, did_wba_last_checked_at = ?
           WHERE air_id = ?`
        ).bind(resolvedBool ? 1 : 0, now, agent.air_id).run();
      } catch (err) {
        // Don't let one bad row sink the run; surface in summary for the
        // operator (visible via `wrangler tail` or the admin endpoint).
        summary.write_errors++;
        console.error(
          `[did-wba-cron] DB write failed for ${agent.air_id}:`,
          err && err.message || err
        );
      }
    }
  }

  summary.duration_ms = Date.now() - startedAt;
  summary.completed_at = new Date().toISOString();
  summary.sample_errors = [...errorSamples];
  console.log(
    `[did-wba-cron] ${summary.total} agents in ${summary.duration_ms}ms ` +
    `— resolved=${summary.resolved} unresolved=${summary.unresolved} ` +
    `write_errors=${summary.write_errors}`
  );
  return summary;
}

// Admin-endpoint wrapper around the cron — returns the run summary as JSON
// so operators can verify the trigger fired correctly.
async function runDidWbaResolveCron(db) {
  const summary = await reResolveAllDidWba(db);
  return json({
    triggered: "manual",
    ...summary,
  });
}
