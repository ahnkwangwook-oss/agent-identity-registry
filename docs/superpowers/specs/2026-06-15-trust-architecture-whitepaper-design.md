# Design — AIR Trust Architecture Whitepaper (v1)

**Date:** 2026-06-15
**Status:** Approved design, pending spec review → implementation plan
**Branch:** `feat/trust-whitepaper`

## Goal

Produce a standalone, **citable** whitepaper that formalizes and positions AIR's *full trust architecture* — not just the 0–1000 score, but the cryptographic verification, cross-org trust graph, tamper-evident audit log, and evidence labels. Its job is to unblock the stalled **partnership + funding** track (W3C AI Agent Protocol CG, Eric Scouten/CAWG, grant applications — NSF/OTF) and lend credibility to attester outreach before the ~2026-07-02 cold-start.

**Not** a from-scratch methodology: `docs/TRUST-SCORE.md` (576 lines) already documents the score rubrics, dispute process, and audit log for developers. The whitepaper *repackages + formalizes* that (plus the verification/graph/audit moat) into a formal artifact for external audiences, adding the framing dev-docs lack: problem statement, design rationale, threat model, honest limitations, governance.

## Audience (all three, served by layering)

One layered document; readers self-select depth:
- **Executive summary** (~1 page, plain-language, press-quotable) — general public / press.
- **Formal body** (rigorous, cited) — standards bodies + grant reviewers + serious partners (the primary readers).
- **"How to verify / build on it" + appendices** — developers (pointers to the live API/spec/SDKs).

## Format + home

- **Canonical source:** one markdown file — `docs/whitepaper/air-trust-architecture-v1.md`. Single source of truth; both outputs derive from it.
- **Output A — web page:** a styled HTML page at `/whitepaper/` matching the site design system, with a "Download PDF" button. Added to site nav + `sitemap.xml`. (New dir `whitepaper` added to `deploy-site.sh` DIRS.)
- **Output B — PDF:** publication-quality PDF generated from the markdown via the `make-pdf` skill (or an equivalent md→PDF path), served for download (e.g. `/whitepaper/air-trust-architecture-v1.pdf`).
- **Duplication policy:** the markdown is authoritative; the HTML page is a rendered derivative (regenerated on updates, not hand-diverged). The plan will pin the exact md→HTML approach (convert-and-style vs. author-HTML-from-md) — favor a repeatable conversion so the two never drift.

## Outline (sections + what each anchors to)

Every number/claim MUST be anchored to a source of truth (see "Accuracy"). Sections:

- **Abstract / Executive Summary** — the problem, AIR's approach (neutral registry + cryptographic verification + auditable scoring), what's novel (cross-org Verified, externally-anchored audit), honest current state (live infra, cold-start). Plain language.
- **1. The Problem** — agent-to-agent trust is unsolved; identity ≠ trust; why a *neutral* layer is needed vs. single-vendor. (Framing; anchor to competitive context in `air/strategic-borrowings-from-opena2a-2026-05-28`.)
- **2. Design Principles** — neutrality (facts, not verdicts), transparency (publish the math), verifiability (don't trust us — verify), honesty (admit what we don't have). The governance stance.
- **3. The Trust Score** — 5-component weighted model (provenance 0.25, behavioral 0.25, transparency 0.20, security 0.15, peer_attestations 0.15), 7 grades, the honest **645 ceiling** + why (behavioral flat 500; provenance/transparency/security partly self-declared); the diminishing-returns peer curve; **evidence labels** (Verified/Attested/Self-declared/Registered — factual, not verdicts). Anchor: `api/src/trust.mjs` (`calculateInitialTrustScore`, `computeGrade`, `peerAttestationsSubscore`, `computeEvidenceLabel`) + `docs/TRUST-SCORE.md`.
- **4. Cryptographic Verification (the moat)** — the attestation model + **AIR Verified**: the 6 locks, ≥3 *independent* WHOIS roots from ≥3 attesters, live did:wba resolution + Ed25519 signature check, frozen `attester_trust_at_issue × tenure_multiplier`, rate limits, public signed audit trail. Why single-vendor "verified" can't be neutral. Anchor: `docs/SPECIFICATION.md`, `api/src/trust.mjs` (`computeVerifiedStatus`), `api/src/did-keys.mjs`, `air/strategic-borrowings-from-opena2a-2026-05-28` (the 6-lock design).
- **5. The Trust Graph** — cross-org attestation topology (ego graph / dependents-blast-radius / stats); trust as relational; why topology surfaces self-attestation rings. Anchor: `api/openapi.yaml` (`/graph`, `/dependents`, `/graph/stats`).
- **6. Tamper-Evident Auditability** — the externally-anchored hash chain; the operator-trust problem + the external anchor (weekly `(tip_hash, entry_count)` → public `audit-anchors` repo) + verify-against-anchor. State the honest bound: tamper-evident against the operator **back to the last weekly anchor**, not real-time-trustless between anchors. Anchor: `docs/superpowers/specs/2026-06-09-agent-audit-log-design.md`, `api/src/audit.mjs`, `docs/TRUST-SCORE.md` §Audit Log.
- **7. Threat Model** — defends against: self-attestation, Sybil via shared WHOIS root (→ the ≥3-independent-roots rule), operator tampering (→ external anchor), key compromise/replay (→ signed_at freshness, UNIQUE signature). Explicitly does NOT: prevent a determined multi-org collusion, measure real runtime behavior yet, guarantee between-anchor integrity. Honest.
- **8. Current State & Limitations** — live in production, but **cold-start (zero live attestations)**, the 645 ceiling, behavioral is a flat placeholder (not yet measured), inputs partly self-declared. The neutral body admitting what it doesn't have. (This IS the brand.)
- **9. Governance & Roadmap** — neutrality commitments (AIR Verified = ≥3 roots; no genesis founder's-pass), the 501(c)(3) path, standards engagement (W3C/DIF/CAWG), how the model evolves. Anchor: `ROADMAP.md`, `air/roadmap`.
- **10. How to Verify / Build On It** — pointers: live API base, `openapi.yaml`, the Python/TS SDKs, `/audit/verify`, `docs/TRUST-SCORE.md` for full rubrics.
- **References + Appendix** — exact formulas (appendix), prior art (W3C DID/VC, did:wba draft, C2PA/CAWG), glossary, links to spec/API/repos.

Target length: **~12–18 PDF pages.** Sections 7 + 8 are mandatory (honest limits + threat model = the credibility that dev-docs and marketing both lack).

## Accuracy + review (non-negotiable — public content)

- **Anchor every figure/claim** to `api/src/trust.mjs`, `api/openapi.yaml`, `docs/TRUST-SCORE.md`, `docs/SPECIFICATION.md`, or the audit-log spec. No invented numbers. The docs-rot rule applies: the code is the source of truth.
- **Honest claims only:** the audit log is "tamper-evident against the operator *back to the last weekly anchor*" (never "immutable"); evidence labels/scores describe evidence, never endorse ("facts, not verdicts"); the cold-start / self-declared / 645-ceiling limits are stated plainly.
- **Author → independent reviewer pass** before publish (the project's non-negotiable rule; subagent hallucination on public content is systematic). Reviewer verifies numbers vs. code, no over-claims, neutrality maintained.

## Rollout

- Add `whitepaper` to `scripts/deploy-site.sh` DIRS; add `/whitepaper/` to `sitemap.xml`; add "Whitepaper" to the global nav on the marketing pages.
- Deploy the site (static) for the page + PDF; no worker/API change.
- Branch → PR → merge (standard).

## Scope guardrails (YAGNI)

In: the one v1 whitepaper (md source), the `/whitepaper` page, the PDF, nav/sitemap wiring, the review.
Out: the short blog/press spin-off (derive from the exec summary *later*); any NEW trust feature (this documents what's shipped); translations; a versioned multi-paper series (v1 only).
