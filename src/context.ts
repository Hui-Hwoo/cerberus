// Request-scoped context: policy, audit log, auth, containment gate.
// Imported by routes; index.ts wires it into the Worker entrypoint.

import { D1AuditLog, MemoryAuditLog, type AuditLog } from "./audit.js";
import { authenticate, type AgentKey } from "./auth.js";
import type { Env, Policy } from "./types.js";
import { json, sha256Hex } from "./util.js";

/** Parse POLICY_JSON. Throws when unconfigured — fail-closed upstream. */
export function getPolicy(env: Env): Policy {
	if (!env.POLICY_JSON) {
		throw new Error(
			"POLICY_JSON is not set. Copy policy.example.json into the POLICY_JSON " +
				"secret (wrangler secret put POLICY_JSON) or .dev.vars for local dev.",
		);
	}
	return JSON.parse(env.POLICY_JSON) as Policy;
}

/**
 * Short hash of the active policy. Stamped on every decision so an
 * auditor can tell which policy version produced it. A silent policy
 * change is otherwise invisible in the audit trail.
 */
export async function getPolicyHash(env: Env): Promise<string> {
	return (await sha256Hex(env.POLICY_JSON ?? "")).slice(0, 16);
}

let fallbackAudit: AuditLog | null = null;

/** D1 in production, one process-wide in-memory log for local dev/tests. */
export function getAudit(env: Env): AuditLog {
	if (env.AUDIT_DB) return new D1AuditLog(env.AUDIT_DB);
	if (!fallbackAudit) fallbackAudit = new MemoryAuditLog();
	return fallbackAudit;
}

/**
 * Test-only: drop the shared in-memory audit log so the next getAudit()
 * starts fresh. Gives each test suite an isolated audit trail.
 */
export function resetFallbackAudit(): void {
	fallbackAudit = null;
}

/**
 * Authenticate a route. Identity ALWAYS comes from the key —
 * never from the request body. Returns the key or an error Response.
 */
export function requireKey(
	req: Request,
	env: Env,
	opts?: { approve?: boolean; admin?: boolean },
): AgentKey | Response {
	let key: AgentKey | null;
	try {
		key = authenticate(req, env);
	} catch {
		// Key store misconfigured: fail closed, never fail open.
		return json({ error: "auth misconfigured — fail-closed" }, 503);
	}
	if (!key)
		return json({ error: "unauthorized: missing or invalid bearer key" }, 401);
	if (key.expiresAt) {
		const exp = Date.parse(key.expiresAt);
		if (Number.isNaN(exp))
			return json(
				{ error: "auth misconfigured: bad expiresAt — fail-closed" },
				503,
			);
		if (exp <= Date.now())
			return json({ error: "unauthorized: bearer key expired" }, 401);
	}
	if (opts?.approve && !key.canApprove)
		return json({ error: "forbidden: key cannot approve elevations" }, 403);
	if (opts?.admin && !key.isAdmin)
		return json({ error: "forbidden: admin only" }, 403);
	return key;
}

/**
 * Containment cooldown per repo. Without it, a single malicious (or just
 * mistaken) push every few seconds could keep revoking every agent's
 * tokens indefinitely — turning the safety system into a DoS weapon.
 * With it, the disruption is bounded to one mass-revocation per window;
 * agents re-mint in seconds via their keys.
 * Tradeoff (accepted, logged): a real attack's follow-up pushes inside
 * the window are not individually contained.
 */
const CONTAINMENT_COOLDOWN_MS = 5 * 60 * 1000;
const lastContainment = new Map<string, number>();

/**
 * Containment gate: returns true when revocation should fire, false when
 * suppressed by the per-repo cooldown.
 */
export function shouldContain(repo: string, nowMs = Date.now()): boolean {
	const last = lastContainment.get(repo) ?? 0;
	if (nowMs - last < CONTAINMENT_COOLDOWN_MS) return false;
	lastContainment.set(repo, nowMs);
	return true;
}
