# AIR Trust Architecture Whitepaper — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. NOTE: this is a **content deliverable**, not code — "verification" per task = fact-checking every figure against the cited source file + a final mandatory independent review. There are no unit tests.

**Goal:** Publish a citable v1 whitepaper covering AIR's full trust architecture (score + cryptographic Verified + trust graph + tamper-evident audit + evidence labels), as one markdown source rendered to a `/whitepaper` web page + a downloadable PDF.

**Architecture:** One canonical markdown file (`docs/whitepaper/air-trust-architecture-v1.md`) → `make-pdf` skill → PDF; and → a self-contained `whitepaper/index.html` reusing the site's page shell (head/CSS/nav/footer copied from `about/index.html`) with the content as semantic HTML + a "Download PDF" button. Every claim anchored to `trust.mjs` / `openapi.yaml` / `TRUST-SCORE.md` / `SPECIFICATION.md` / the audit-log spec. Author → independent review before deploy.

**Tech Stack:** Markdown, the `make-pdf` gstack skill, hand-authored HTML (site design system), `scripts/deploy-site.sh` (Cloudflare Pages), `sitemap.xml`.

**Spec:** `docs/superpowers/specs/2026-06-15-trust-architecture-whitepaper-design.md`

---

## File Structure

- **`docs/whitepaper/air-trust-architecture-v1.md`** (CREATE) — the canonical whitepaper source (all sections). Single source of truth.
- **`whitepaper/index.html`** (CREATE) — the styled web page: site shell + the whitepaper rendered as semantic HTML + "Download PDF" link.
- **`whitepaper/air-trust-architecture-v1.pdf`** (CREATE, generated) — the downloadable PDF (lives in the deployed dir).
- **`scripts/deploy-site.sh`** (MODIFY) — add `whitepaper` to DIRS.
- **`sitemap.xml`** (MODIFY) — add `/whitepaper/`.
- **The 9 marketing pages** (`index.html`, `about/`, `developers/`, `governance/`, `blog/`, `note/`, `register/`, `lookup/`, `contact/` `index.html`) (MODIFY) — add a "Whitepaper" link to the shared footer-nav block (NOT the crowded top nav) for site-wide discoverability, plus a prominent inline link from `about/`, `developers/`, `governance/`.

## Anchored facts (the writer MUST use these exact values; verify each against its source before writing)

- Score weights: **provenance 0.25, behavioral 0.25, transparency 0.20, security 0.15, peer_attestations 0.15** — `api/src/trust.mjs` `calculateInitialTrustScore`.
- Grades: AAA≥950, AA≥850, A≥700, BBB≥600, BB≥500, B≥400, C<400 — `trust.mjs` `computeGrade`.
- Ceiling: **645 (grade BBB)** max today; A/AA/AAA reserved; behavioral is a flat **500** — `docs/TRUST-SCORE.md:49`, `SPECIFICATION.md` "Current ceiling".
- Peer curve: `300 + round(18·√weightSum)`, cap **1000** — `trust.mjs` `peerAttestationsSubscore`.
- Verified = `verification_score ≥ 300 AND ≥3 distinct WHOIS roots` — `trust.mjs` `computeVerifiedStatus`.
- The **6 locks** (did:wba+Ed25519, WHOIS-root diversity, tenure≥30d + trust≥50, weighting, rate limit ≤10/7d, public signed trail) — `air/strategic-borrowings-from-opena2a-2026-05-28` (GBrain) + `SPECIFICATION.md`.
- Evidence labels: **Verified / Attested / Self-declared / Registered** (factual) — `trust.mjs` `computeEvidenceLabel`.
- Audit log: externally-anchored hash chain; weekly `(tip_hash, entry_count)` → public `AgentIdentityRegistry/audit-anchors`; "tamper-evident against the operator **back to the last weekly anchor**, not real-time-trustless between anchors" — `docs/superpowers/specs/2026-06-09-agent-audit-log-design.md`, `docs/TRUST-SCORE.md` §Audit Log.
- Endpoints: `api/openapi.yaml` (servers base `https://agentidentityregistry.org/api/v1`).

---

# PHASE A — Write the whitepaper (markdown)

> Each task: re-read the cited source(s), draft the section(s) into the md, then run the fact-check grep to confirm every number matches. Commit per task.

### Task 1: Scaffold + front matter + Abstract/Exec Summary + §1 Problem + §2 Principles

**Files:** Create `docs/whitepaper/air-trust-architecture-v1.md`.

- [ ] **Step 1: Read sources** — `air/strategic-borrowings-from-opena2a-2026-05-28` (GBrain), `docs/SPECIFICATION.md` intro, `about/index.html` (voice/positioning).
- [ ] **Step 2: Write** the file header (title *"AIR: A Neutral Trust & Verification Architecture for AI Agents"*, version v1.0, date 2026-06-15, one-line abstract), then:
  - **Abstract / Executive Summary** (~1 page, plain language): the problem, AIR's approach (neutral registry + cryptographic verification + auditable scoring), what's novel (cross-org Verified, externally-anchored audit), honest current state (live infra, cold-start).
  - **§1 The Problem**: agent-to-agent trust is unsolved; identity ≠ trust; why *neutral* (a single vendor's "verified" isn't credibly neutral).
  - **§2 Design Principles**: neutrality (facts, not verdicts), transparency (publish the math), verifiability (don't trust us — verify), honesty (admit gaps).
- [ ] **Step 3: Fact-check** — this section has few hard numbers; confirm no scoring figures are stated yet (those belong to §3). `grep -nE '6[0-9][0-9]|0\.[0-9]|Verified' docs/whitepaper/air-trust-architecture-v1.md` — ensure any number present is traceable.
- [ ] **Step 4: Commit** — `git add docs/whitepaper/air-trust-architecture-v1.md && git commit -m "docs(whitepaper): abstract + problem + principles"`

### Task 2: §3 The Trust Score

**Files:** Modify `docs/whitepaper/air-trust-architecture-v1.md`.

- [ ] **Step 1: Read** `api/src/trust.mjs` (`calculateInitialTrustScore`, `computeGrade`, `peerAttestationsSubscore`, `computeEvidenceLabel`) + `docs/TRUST-SCORE.md`.
- [ ] **Step 2: Write §3** covering: the 5 weighted components (exact weights above), the 7 grades, the **645 ceiling + why** (behavioral flat 500; provenance/transparency/security partly self-declared), the diminishing-returns peer curve, and the **evidence labels** (Verified/Attested/Self-declared/Registered — factual, describe evidence not worth). Include one worked example consistent with `TRUST-SCORE.md`'s example.
- [ ] **Step 3: Fact-check** — verify each number against source:
  `grep -nE '0\.25|0\.20|0\.15|645|950|850|700|600|500|400' docs/whitepaper/air-trust-architecture-v1.md` and cross-check vs `grep -nE '0\.25|0\.20|0\.15|>= ?[0-9]{3}' api/src/trust.mjs`. Every weight/threshold/ceiling must match. NO claim that any agent can exceed 645 today.
- [ ] **Step 4: Commit** — `git commit -am "docs(whitepaper): the trust score"`

### Task 3: §4 Cryptographic Verification + §5 Trust Graph

**Files:** Modify the md.

- [ ] **Step 1: Read** `trust.mjs` `computeVerifiedStatus`, `api/src/did-keys.mjs`, `SPECIFICATION.md` (attestation/Verified), `api/openapi.yaml` (`/graph`, `/dependents`, `/graph/stats`), the 6-lock design in the GBrain strategic page.
- [ ] **Step 2: Write §4** (the moat): the attestation model + AIR Verified = `verification_score ≥ 300 AND ≥3 distinct WHOIS roots`; the **6 locks** (list each precisely); live did:wba resolution + Ed25519 check; frozen `attester_trust_at_issue × tenure_multiplier`; rate limit ≤10/7d; public signed trail. Argue why single-vendor "verified" can't be neutral. **§5 Trust Graph**: ego graph / dependents (blast-radius) / stats; trust as relational; topology surfaces self-attestation rings.
- [ ] **Step 3: Fact-check** — `grep -nE '≥ ?3|>= ?300|30[ -]?day|tenure|Ed25519|WHOIS' docs/whitepaper/...md`; confirm the "≥3 distinct WHOIS roots" + "verification_score ≥ 300" match `computeVerifiedStatus` in `trust.mjs`, and the graph endpoints exist in `openapi.yaml` (`grep -c '/graph\|/dependents' api/openapi.yaml`).
- [ ] **Step 4: Commit** — `git commit -am "docs(whitepaper): cryptographic verification + trust graph"`

### Task 4: §6 Auditability + §7 Threat Model + §8 Limitations

**Files:** Modify the md.

- [ ] **Step 1: Read** `docs/superpowers/specs/2026-06-09-agent-audit-log-design.md`, `api/src/audit.mjs`, `docs/TRUST-SCORE.md` §Audit Log.
- [ ] **Step 2: Write §6** (auditability): the externally-anchored hash chain; the operator-trust problem; the weekly `(tip_hash, entry_count)` anchor to the public `audit-anchors` repo; `/audit/verify` cross-check. State the honest bound verbatim: **tamper-evident against the operator back to the last weekly anchor; not real-time-trustless between anchors**. **§7 Threat Model**: defends against self-attestation, Sybil-via-shared-root (→ ≥3 independent roots), operator tampering (→ external anchor), replay/key-compromise (→ signed_at freshness, UNIQUE signature); explicitly does NOT prevent determined multi-org collusion, does NOT yet measure runtime behavior, does NOT guarantee between-anchor integrity. **§8 Current State & Limitations**: live in production BUT cold-start (zero live attestations), 645 ceiling, behavioral is a placeholder, inputs partly self-declared.
- [ ] **Step 3: Fact-check** — `grep -niE 'immutable|cannot be tampered|fully trustless|100%' docs/whitepaper/...md` MUST return nothing (over-claim guard). Confirm "back to the last weekly anchor" phrasing is present. Confirm §8 states cold-start + 645 + flat-behavioral.
- [ ] **Step 4: Commit** — `git commit -am "docs(whitepaper): auditability + threat model + limitations"`

### Task 5: §9 Governance & Roadmap + §10 How to Verify/Build + References/Appendix

**Files:** Modify the md.

- [ ] **Step 1: Read** `ROADMAP.md`, `air/roadmap` (GBrain), `api/openapi.yaml` servers/paths, the SDK package names (`agent-identity-registry` on npm/PyPI, `air-mcp-server`).
- [ ] **Step 2: Write §9** (governance: neutrality commitments — AIR Verified = ≥3 roots, no genesis founder's-pass; the 501(c)(3) path; W3C/DIF/CAWG engagement; how the model evolves). **§10 How to verify / build on it**: the live API base, `openapi.yaml`, Python/TS SDKs (exact names), `/audit/verify`, and `docs/TRUST-SCORE.md` for full rubrics. **References + Appendix**: exact formulas (appendix), prior art (W3C DID Core, VC Data Model, did:wba draft, C2PA/CAWG), glossary. Use REAL package names only.
- [ ] **Step 3: Fact-check** — `grep -nE 'agent-identity-registry|air-mcp-server|did:wba|/api/v1' docs/whitepaper/...md`; confirm package names match reality (no fabricated `air-sdk` etc. — a known past hallucination). Confirm the openapi server base is exactly `https://agentidentityregistry.org/api/v1`.
- [ ] **Step 4: Commit** — `git commit -am "docs(whitepaper): governance, developer guide, references"`

---

# PHASE B — Produce outputs

### Task 6: Generate the PDF

**Files:** Create `whitepaper/air-trust-architecture-v1.pdf`.

- [ ] **Step 1:** Invoke the **make-pdf skill** on `docs/whitepaper/air-trust-architecture-v1.md`, output to `whitepaper/air-trust-architecture-v1.pdf` (create the `whitepaper/` dir). (If make-pdf needs a title/author, use the whitepaper title + "Agent Identity Registry".)
- [ ] **Step 2: Verify** the PDF exists + is non-trivial: `ls -la whitepaper/air-trust-architecture-v1.pdf` (expect > 50KB) and open/spot-check page 1 renders the title + abstract.
- [ ] **Step 3: Commit** — `git add whitepaper/air-trust-architecture-v1.pdf && git commit -m "docs(whitepaper): publication PDF"`

### Task 7: Build the `/whitepaper` web page

**Files:** Create `whitepaper/index.html`.

- [ ] **Step 1:** Copy the shell of `about/index.html` — the `<head>` (meta/OG/CSS `<style>` block), the `.nav` block, and the footer — into `whitepaper/index.html`. Update: `<title>` → "AIR Trust Architecture Whitepaper | AIR", `<meta name="description">`, OG tags, and `<link rel="canonical" href="https://agentidentityregistry.org/whitepaper/">`.
- [ ] **Step 2:** Render the whitepaper markdown body to semantic HTML (h2/h3/p/ul/table/code/blockquote) and place it inside a `<main>` styled like the other content pages (reuse existing content classes, e.g. the section/container classes `about/index.html` uses). Prefer a repeatable conversion (`pandoc docs/whitepaper/air-trust-architecture-v1.md -o /tmp/wp-body.html` if pandoc is available, else `npx marked`) then hand-wrap in the shell; if neither is available, transcribe the md content into the shell faithfully. Add a prominent **"⬇ Download PDF"** button linking `/whitepaper/air-trust-architecture-v1.pdf` near the top.
- [ ] **Step 3: Verify** — `python3 -c "import html.parser,sys; html.parser.HTMLParser().feed(open('whitepaper/index.html').read()); print('parses')"`; open in a browser/preview to confirm the page matches the site look, nav works, the PDF link is present, and content matches the md (no dropped sections). Confirm the honest audit wording ("back to the last weekly anchor") survived the conversion (`grep -c 'last weekly anchor' whitepaper/index.html`).
- [ ] **Step 4: Commit** — `git add whitepaper/index.html && git commit -m "docs(whitepaper): /whitepaper web page"`

---

# PHASE C — Wire it into the site

### Task 8: Nav links + sitemap + deploy DIRS

**Files:** Modify the 9 marketing `index.html` files, `sitemap.xml`, `scripts/deploy-site.sh`.

- [ ] **Step 1: deploy DIRS** — in `scripts/deploy-site.sh`, change the DIRS line to include `whitepaper`:
  `DIRS=(assets about admin blog contact developers governance lookup note register specs whitepaper)`
- [ ] **Step 2: sitemap** — add to `sitemap.xml` (priority 0.8, changefreq monthly, lastmod 2026-06-15):
  ```xml
  <url>
    <loc>https://agentidentityregistry.org/whitepaper/</loc>
    <lastmod>2026-06-15</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.8</priority>
  </url>
  ```
- [ ] **Step 3: footer nav (all 9 pages)** — add a "Whitepaper" link to the footer resources list on each of the 9 marketing pages (match the existing footer-link markup on each). Do this consistently across: `index.html`, `about/index.html`, `developers/index.html`, `governance/index.html`, `blog/index.html`, `note/index.html`, `register/index.html`, `lookup/index.html`, `contact/index.html`. (Footer, not the top nav — avoids crowding the primary nav.)
- [ ] **Step 4: prominent inline links** — add a contextual link to the whitepaper from the body of `about/index.html` (near "What We've Built"), `developers/index.html` (trust/score area), and `governance/index.html`.
- [ ] **Step 5: Verify** — `grep -rc 'href="/whitepaper' --include=index.html . | grep -v ':0'` shows all 9 pages link it; `grep -c whitepaper scripts/deploy-site.sh sitemap.xml` both ≥1.
- [ ] **Step 6: Commit** — `git commit -am "site: link whitepaper from nav + sitemap + deploy dirs"`

---

# PHASE D — Review, deploy, ship

### Task 9: Independent accuracy + neutrality review (MANDATORY — do NOT self-approve)

- [ ] **Step 1:** Dispatch a fresh reviewer (Opus) on the whitepaper md + the HTML page. It MUST verify, against `api/src/trust.mjs` + `api/openapi.yaml` + `docs/TRUST-SCORE.md`: (a) every number (weights, 645 ceiling, grade thresholds, ≥3 roots, ≥300, peer curve) is correct; (b) NO over-claim — no "immutable"/"cannot be tampered"/"fully trustless"; the audit bound says "back to the last weekly anchor"; (c) neutrality — evidence labels/scores framed as facts, never endorsements; (d) NO fabricated endpoints/packages (real names: `agent-identity-registry`, `air-mcp-server`); (e) §7 threat-model + §8 limitations are present and honest (cold-start, 645, flat behavioral). Return findings + SHIP / FIX-FIRST.
- [ ] **Step 2:** Fix any findings; re-verify the specific fact-check greps for changed numbers. (Re-review if the reviewer found a Critical.)

### Task 10: Deploy + verify live + PR (PETER-GATED)

- [ ] **Step 1 (CONFIRM WITH PETER):** `./scripts/deploy-site.sh` (publishes `/whitepaper/` page + PDF).
- [ ] **Step 2: Smoke (cache-busted):**
  ```bash
  cb=$(date +%s)
  curl -s -o /dev/null -w "page  %{http_code}\n" "https://agentidentityregistry.org/whitepaper/?cb=$cb"
  curl -s -o /dev/null -w "pdf   %{http_code} %{size_download}b\n" "https://agentidentityregistry.org/whitepaper/air-trust-architecture-v1.pdf?cb=$cb"
  curl -s "https://agentidentityregistry.org/sitemap.xml?cb=$cb" | grep -c whitepaper
  curl -s "https://agentidentityregistry.org/about/?cb=$cb" | grep -c 'href="/whitepaper'
  ```
  Expect: page 200, pdf 200 + non-trivial size, sitemap ≥1, about links it.
- [ ] **Step 3: PR + merge** — `git push -u origin feat/trust-whitepaper`; `gh pr create --base main ...`; merge after Peter's OK.

---

## Self-Review (against the spec)

**Spec coverage:** audience-layering (exec summary + body + dev section) → T1/T2–5/T5 · full-architecture scope (score T2, Verified T3, graph T3, audit T4, labels T2) → ✅ · threat model + limitations (mandatory) → T4 · web page + PDF from one md source → T6/T7 · nav/sitemap/deploy wiring → T8 · anchored-accuracy + honest-claims → per-task fact-checks + T9 · author→review → T9 · scope guardrails (no blog spin-off, no new features) → respected.

**Placeholder scan:** none — each content task lists the section's must-cover points + the exact anchored facts + a concrete fact-check grep; production tasks give exact commands/paths. The one flexible step is the md→HTML conversion (T7): named tools (pandoc/marked) with a faithful-transcription fallback — not a vague placeholder.

**Consistency:** file paths (`docs/whitepaper/air-trust-architecture-v1.md`, `whitepaper/index.html`, `whitepaper/air-trust-architecture-v1.pdf`) identical across tasks; the anchored-facts block is the single source the content tasks cite; the honest audit wording ("back to the last weekly anchor") is enforced in T4, T7, and T9.
