# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| v0.1.x (latest) | Yes |
| older | No |

## Reporting a Vulnerability

**Do not open public issues for security vulnerabilities.**

Report privately via [GitHub private vulnerability reporting](../../security/advisories/new)
(or email the maintainer listed in package.json). Include:

- Cerberus version
- Steps to reproduce
- Impact (what an attacker can do: e.g. mint tokens outside policy, tamper with audit log, bypass the broker)

We aim to acknowledge within 48 hours.

## Security Design Notes

- **Fail-closed**: any internal failure (policy unloadable, D1 unreachable,
  binding error) denies the request with 503. The broker never mints on error.
- **Tamper-evident audit**: every decision entry is SHA-256 hash-chained to the
  previous entry (`prev_hash`). Verify with `npm run lifecycle` (chain checks)
  or `verifyChain()` in `src/audit.ts`.
- **Least privilege**: minted tokens are repo-scoped `read`/`write` with short
  TTLs (default ≤ 900s; elevation grants ≤ 300s). Agents never see the
  Artifacts binding — only the broker Worker holds it.
- **Default deny**: no matching rule → deny. New deployments should start in
  `"mode": "observe"` to preview would-deny decisions in the audit log.
  Note: observe mode still returns 403 (assessment, not pass-through).
- **Secrets**: never commit tokens. `POLICY_JSON` goes in `wrangler secret` /
  `.dev.vars` (gitignored). Gitleaks runs in CI to catch accidents.

## Known Limitations (v0.1)

- Prompt injection in agent task content is out of scope: Cerberus governs
  *access*, not *intent*. Path-level checks do not inspect file contents.
- The broker must be the exclusive token minter; if agents can reach the
  Artifacts binding directly, policy is bypassable. Deploy accordingly.
- Containment is fail-closed by design: one unexplained push revokes all
  outstanding write tokens on the repo. A per-repo 5-minute cooldown
  bounds weaponization, but a mistaken push still disrupts legitimate
  agents until they re-mint. The tradeoff is deliberate and logged.
- Single-approver elevation: no quorum yet. A compromised approver key
  compromises the elevation path. Agent keys support expiry (`expiresAt`)
  — set it.
  → **Fixed 2026-10-12**: `elevationQuorum` in policy (default 1). At 2+,
  tickets need that many distinct approvers; the requester can never
  approve their own ticket and one agent can't approve twice. No single
  key grants elevated access alone.
- Audit transparency aids attacker timing: `/v1/events` is public read.
  Accepted as a design tradeoff.
- Push→token attribution is a platform gap: if a stolen token wins the
  race ahead of the legitimate push, the attacker's push may be explained
  first. Only Cloudflare can close this (push event → token ID linkage).
