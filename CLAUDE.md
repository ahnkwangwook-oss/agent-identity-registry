# AIR — Agent Identity Registry

> Moved out of `~/.claude/CLAUDE.md` on 2026-09-07. It was loading into every session on the
> machine; it only matters here. Global keeps no AIR rules.

Applies to all AIR work: agentidentityregistry.org, air-site, the SDK, the MCP server, and
BossClaw/SuperClaw when in scope.

1. **Read the session-start protocol FIRST** — `mcp__gbrain__get_page` slug=`air/session-start-protocol`.
   That page is the authoritative entry point and always points at the latest handoff plus the
   canonical lessons. Do NOT hardcode handoff dates here — they go stale.
2. **Do the Step 0 Git audit before any other work** — `git status -sb && git log @{u}.. --oneline`
   in every active repo (`~/air-site`, `~/air-site/sdk/python`, `~/air-site/mcp-server`, and
   `~/SuperClaw` if BossClaw is in scope). Reconcile anything local-only first.
3. **Save only to GBrain** — all new AIR knowledge goes to `mcp__gbrain__put_page` with the
   `air/` prefix. Do NOT save to `wiki/air/*` or local-only files, except
   `~/.claude/projects/*/memory/` for fast-access mirrors of permanent rules.
4. **Append new lessons** to `air/lessons-learned-canonical` when earned. That page is the
   durable cross-session ruleset.
5. **Write a handoff at session end** — `air/session-handoff-YYYY-MM-DD` (add a `-suffix` for
   parallel sessions). Update the session-start-protocol page to point at the new handoff.
   Re-run the Step 0 audit before declaring done.

Universal rules (communication style, engineering standards, git discipline) live in
`~/.claude/CLAUDE.md` and still apply.
