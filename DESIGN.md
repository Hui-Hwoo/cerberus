# Cerberus — design

## Problem

Cloudflare Artifacts is the storage/brick layer: a versioned filesystem that
speaks Git, with a Workers binding to create/fork repos and mint repo-scoped
Git tokens. Its token model is exactly two knobs:

- scope: `"read" | "write"` (per repository)
- ttl: seconds

There is **no** path-level permission, **no** branch protection, **no** notion of
"which agent may do what", and **no** audit of who used which token for what.
The official best-practices doc tells you to "mint the narrowest token you can,
for the shortest time you can" — but provides no engine to decide what "narrow
enough" means per agent, per task. Every entrant building multi-agent Git
platforms (12 surveyed) re-implements ad-hoc trust; none builds the policy layer.

## Solution

Cerberus is a Worker that **owns the Artifacts binding exclusively** and acts
as the sole token minter. Agents never touch `env.ARTIFACTS`. Every Git
operation follows:

```
1. agent → POST /v1/token {agentId, roles, taskId, action, repo, branch, paths}
2. policy engine evaluates ordered rules (glob on repos/branches/paths)
   - explicit deny wins; otherwise first matching allow; else default deny
3a. ALLOW → broker mints repo.createToken(scope, shortTtl), returns {token, expiresAt}
3b. ALLOW+requireApproval → returns elevation ticket, agent requests approval
3c. DENY → returns reason; decision logged
4. every decision appended to audit log (D1)
5. revocation: broker can revokeToken(tokenOrId) — kill switch on violation
6. post-hoc: Worker subscribes to repo push events, cross-checks pushes against
   broker-issued tokens (defense in depth)
```

## Policy model

```jsonc
{
  "version": 1,
  "defaultEffect": "deny",
  "rules": [
    {
      "id": "docs-write",
      "effect": "allow",
      "roles": ["docs-writer"],
      "actions": ["read", "push", "create-branch"],
      "repos": ["*"],
      "branches": ["docs/*", "feat/*"],   // never main
      "paths": ["docs/**", "README.md"],
      "maxTtlSeconds": 900
    },
    {
      "id": "protect-main",
      "effect": "deny",
      "actions": ["push"],
      "branches": ["main"]               // branch protection, no exceptions w/o approval
    }
  ]
}
```

- Matching: agent/role must intersect; action must be listed; repo/branch globs
  must match. Path semantics differ by effect: for `allow` rules EVERY touched
  path must be covered by `paths` globs; for `deny` rules ANY touched path
  hitting `paths` globs triggers the rule (so smuggling `src/auth/jwt.ts`
  inside an otherwise-legit push is still denied).
- Precedence: any matching `deny` beats any `allow`; else first matching `allow`;
  else `defaultEffect` (`deny`).
- `requireApproval: true` on a rule turns an allow into an elevation ticket —
  a human approves via `POST /v1/elevate/:id/approve`, broker mints a
  narrow, very-short-TTL token.

## Threat model

| Threat | Mitigation |
|---|---|
| Agent touches files outside its scope | Policy denies at request time; token never minted |
| Agent pushes to `main` directly | `protect-main`-style deny rule; branch not in any allow glob |
| Compromised/leaked token | Short TTL (≤15 min default); `revokeToken` kill switch; `listTokens` inventory |
| Agent bypasses Cerberus, mints own token | Binding lives only in Cerberus Worker; agents get tokens via HTTPS, never see `ARTIFACTS` |
| Malicious instructions in issues/PRs (prompt injection) | Out of scope for v1 — Cerberus governs *access*, not *intent*. Documented limitation |
| Post-hoc tampering | Push-event subscription cross-checks; audit log is append-only |
| Audit log tampering | **Hash-chained audit**: every decision entry commits via SHA-256 to the previous entry's hash (`prev_hash`); `verifyChain()` detects any modification/deletion |
| Broker internal failure (policy unloadable, D1 down) | **Fail-closed**: any internal error returns 503 with `allowed:false`; no token is ever minted on error |
| Policy misconfiguration breaking agents | **Observe mode** (`"mode":"observe"`): deny decisions are logged/labeled as would-deny without minting, so teams can validate policy against real traffic before enforcing |

## What we rely on from Artifacts (verified 2026-10-09)

`artifacts.create/get/list/import/delete`; repo handle `createToken(scope?, ttl?)`,
`revokeToken(tokenOrId)`, `listTokens()`, `fork(name, opts?)`, `log()`,
`readFile/readCommit/readTree/readBlob`; repo handles are `Disposable`
(`using` declaration). Tokens are repo-level read/write only — the gap we fill.

## Deliberate non-goals (5-day scope)

- Full CI/merge pipeline (others do this); Cerberus is the gate *before* it
- Semantic conflict detection; cost accounting; memory systems
- Multi-namespace federation; fine-grained repo admin roles

## Security practices borrowed from InnerWarden

InnerWarden (Rust autonomous security agent) informed three design choices:

1. **Hash-chained audit log** — its `decisions.rs` chains every decision entry
   via SHA-256 `prev_hash` with immediate flush; we ported the chain (without
   the flush, D1 is durable per write).
2. **Fail-closed gatekeeper** — InnerWarden's skills fail *open* (a crashed
   security agent is worse than a missed response); a token broker must do the
   opposite, so every internal failure path returns deny.
3. **Safe defaults + observe mode** — InnerWarden installs with `dry_run=true`;
   our `mode:"observe"` is the same idea for policy rollout.
