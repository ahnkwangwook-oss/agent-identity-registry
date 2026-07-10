# AIR: A Neutral Trust & Verification Architecture for AI Agents

**A whitepaper from the Agent Identity Registry Foundation**

**Version 1.0 — 2026-07-11**

> AIR is a neutral, nonprofit registry that gives AI agents a cryptographic identity, a transparent and auditable trust score, and cross-organization verification that no single vendor can credibly offer alone. This paper documents the full architecture — the score, the cryptographic Verified badge, the trust graph, the externally-anchored audit log, and the evidence labels — and states plainly what the system does *not* yet do.

---

## Abstract

AI agents are becoming autonomous participants in commerce, infrastructure, and everyday software. When one agent transacts with, delegates to, or depends on another, a basic question has no good answer today: **who is this agent, and should I trust it?**

Existing approaches conflate two different problems. *Identity* — proving an agent is the same entity across interactions — is increasingly solved by cryptographic methods such as W3C Decentralized Identifiers. *Trust* — whether that identity has earned any standing — is not. Where trust signals exist at all, they are proprietary to a single platform, opaque in how they are computed, and issued by an organization that also competes in the ecosystem it is grading.

The **Agent Identity Registry (AIR)** is neutral infrastructure for that second problem. It is operated by a nonprofit foundation, not a commercial platform, and it is built on four commitments: publish the math, describe evidence rather than render verdicts, let anyone re-verify every claim independently, and state honestly what the system cannot yet do.

AIR combines five mechanisms into one architecture:

1. **A transparent trust score** — a published, weighted composite of five components on a 0–1000 scale, with every weight and threshold documented and queryable.
2. **Cryptographic verification (the moat)** — an "AIR Verified" status that requires cryptographically-signed endorsements from independent attesters anchored to **three or more distinct WHOIS roots**, gated by six enforced checks.
3. **A cross-organization trust graph** — trust modeled as a relational topology (who vouches for whom, who depends on whom), which surfaces self-attestation rings that a flat score would hide.
4. **A tamper-evident audit log** — an append-only, hash-linked record of every change to an agent's record, whose chain tip is anchored weekly to a public external repository so that even the registry operator cannot silently rewrite history.
5. **Factual evidence labels** — a plain-language classification (Verified / Attested / Self-declared / Registered) that describes *what independent evidence exists*, never an endorsement.

Two properties are genuinely novel. First, **cross-organizational Verified**: because AIR-minted identities all share a single WHOIS root, AIR itself cannot manufacture a Verified agent — the requirement for three independent roots is self-binding, which is precisely what a single-vendor badge can never be. Second, **externally-anchored auditability**: publishing the audit chain's tip to an outside, append-only repository makes the log tamper-evident *against the operator*, back to the last weekly anchor.

We are equally clear about the present limits. The infrastructure is live in production, but the trust network is in its cold-start phase; the score is deliberately capped at grade **BBB (645/1000)** today because the behavioral component is a fixed placeholder until signed action-history telemetry ships; and several inputs remain partly self-declared. These are stated not as caveats buried in an appendix but as a design principle: a neutral registry earns credibility by admitting what it does not have.

Everything below is verifiable. The scoring code, the API contract, the specification, and the audit anchors are all public. The correct response to this paper is not to trust it — it is to check it.

---

## 1. The Problem

### 1.1 Agents now act, not just answer

A growing share of software is agentic: systems that take actions on a user's behalf — calling APIs, moving data, initiating transactions, and delegating sub-tasks to other agents. As soon as one agent relies on another, it inherits that other agent's behavior and risk. The interaction is no longer a query and a response; it is a dependency.

Dependencies require a basis for trust. Between humans and institutions, that basis is built from identity documents, reputations, credentials, and audit trails accumulated over time. For AI agents, almost none of that infrastructure exists in a neutral, portable form.

### 1.2 Identity is not trust

It is tempting to treat identity as sufficient. It is not. Knowing an agent's cryptographic identifier tells you that it is the *same* agent as before — it says nothing about whether that agent is competent, honest, well-secured, or endorsed by anyone. A stable identity is a prerequisite for trust, not a substitute for it.

Concretely, two questions must be answered separately:

- **Identity:** *Is this the entity it claims to be, consistently, across interactions?* Cryptographic identity — a content-addressed identifier bound to a public key and a W3C DID document — answers this well.
- **Trust:** *Given that identity, what independent evidence exists that this agent should be relied upon?* This requires evidence that comes from *outside* the agent itself: endorsements from independent parties, transparent scoring, and an auditable history.

AIR treats identity as the foundation and trust as the structure built on top of it. The two are related but never conflated: an agent can have an impeccable cryptographic identity and no trust standing at all.

### 1.3 Why the trust layer must be neutral

Where agent "trust" or "verification" signals exist today, they are almost always issued by a single commercial platform about agents on that platform. This creates three problems that no amount of engineering can fix from inside a single vendor:

- **Incentive conflict.** A platform that both hosts agents and certifies them is grading its own ecosystem. Its "verified" badge is, structurally, a marketing asset — it cannot be a neutral fact, because the issuer has a commercial stake in the outcome.
- **Non-portability.** A signal that lives inside one platform does not travel. An agent's standing resets to zero the moment it interacts across a platform boundary — exactly where trust matters most.
- **Opacity.** Proprietary scores are rarely published in full. If you cannot see how a number is computed, you cannot audit it, contest it, or reproduce it.

The trust layer for a cross-vendor agent web therefore has to be **neutral, portable, and transparent** — properties that are structural, not cosmetic. A neutral registry is not simply a nicer version of a vendor badge; it is a different category of thing, because it is the one party in the ecosystem with no agent of its own to promote.

### 1.4 The gap this paper addresses

The result is a missing layer. Agents have increasingly good identity and no shared, neutral, auditable notion of trust. Platforms build proprietary silos that do not interoperate; users and other agents have no neutral source of truth; and the "verified" signals that do exist cannot credibly claim neutrality. The rest of this paper describes the architecture AIR uses to fill that gap, and is candid about where the architecture is still incomplete.

---

## 2. Design Principles

Four principles govern every design decision in AIR. They are not aspirational values; each maps to a concrete, checkable mechanism described later in this paper.

### 2.1 Neutrality — facts, not verdicts

AIR describes evidence; it does not render judgments. Every agent carries a factual **evidence label** — *Verified*, *Attested*, *Self-declared*, or *Registered* — that states *what independent evidence exists*, never whether the agent is "good." The numeric score and its components are the transparent detail behind that label. AIR issues no endorsements, picks no winners, and grants no agent — including any operated by the foundation itself — a privileged standing.

This neutrality is enforced structurally, not promised. Because AIR-minted identities all share the single `agentidentityregistry.org` WHOIS root, and because Verified status requires endorsements across **three distinct roots**, AIR cannot mint itself a Verified agent. The registry is bound by the same rules it publishes.

### 2.2 Transparency — publish the math

Every scoring weight, grade threshold, verification requirement, and audit-hash recipe in this paper is documented in public source and queryable through a public API. There are no hidden multipliers and no undisclosed heuristics. A reader who disagrees with a number can point to the exact line of code that produces it. Transparency is what makes the score contestable, and contestability is what makes it trustworthy.

### 2.3 Verifiability — don't trust us, verify

Wherever possible, AIR is designed so that its claims can be reproduced by a third party with no access to the registry's internals:

- An agent's content-addressed identifier can be **recomputed** from its identity document.
- Each attestation signature can be **re-checked** against the attester's independently-resolved public key.
- Every entry in the audit log can be **re-derived** and its hash linkage confirmed, and the chain's tip cross-checked against a public external anchor.

The design goal is that trust in AIR reduces to trust in mathematics and in public records — not in the good intentions of the operator.

### 2.4 Honesty — admit what we don't have

A neutral registry earns standing by being candid about its own limits. AIR publishes its actual status, not an aspirational one. The score is capped at grade BBB today because behavioral telemetry is not yet measured; the network is in cold-start; some inputs are self-declared; and the audit log is tamper-evident only back to the last weekly anchor, not in real time between anchors. These limitations are documented in §7 (Threat Model) and §8 (Current State & Limitations) as first-class content, because a system that hides its weaknesses cannot credibly certify anyone else's strengths.
