// Agent authentication: pre-shared keys bound to identity.
//
// The key determines agentId + roles. The request body is NEVER trusted for
// identity — self-asserted roles are the same as no authentication at all.
// Keys are provisioned out-of-band (wrangler secret put AGENT_KEYS_JSON)
// and never appear in the repo; see keys.example.json for the shape.

import type { Env } from "./types.js";

export interface AgentKey {
	/** The credential id (the map key in the keys file). Never logged. */
	id: string;
	agentId: string;
	roles: string[];
	canApprove?: boolean;
	isAdmin?: boolean;
	/**
	 * Optional ISO 8601 expiry, e.g. "2026-11-01T00:00:00Z".
	 * Absent = never expires (legacy keys). Expired keys are rejected
	 * with 401; an unparseable value fails closed with 503.
	 */
	expiresAt?: string;
}

interface KeysFile {
	keys: Record<string, Omit<AgentKey, "id">>;
}

export function loadAgentKeys(env: Env): Map<string, AgentKey> {
	if (!env.AGENT_KEYS_JSON) {
		throw new Error(
			"AGENT_KEYS_JSON is not set. Provision with: " +
				"wrangler secret put AGENT_KEYS_JSON < keys.json",
		);
	}
	const parsed = JSON.parse(env.AGENT_KEYS_JSON) as KeysFile;
	const map = new Map<string, AgentKey>(
		Object.entries(parsed.keys ?? {}).map(([id, k]) => [
			id,
			{ id, ...k },
		]),
	);
	if (map.size === 0) throw new Error("AGENT_KEYS_JSON contains no keys.");
	return map;
}

/**
 * Authenticate a request via `Authorization: Bearer <key>`.
 * Returns the bound identity, or null when the key is missing/invalid.
 * Throws when the key store itself is misconfigured (fail-closed).
 */
export function authenticate(req: Request, env: Env): AgentKey | null {
	const h = req.headers.get("authorization") ?? "";
	const m = h.match(/^Bearer\s+(.+)$/i);
	if (!m) return null;
	return loadAgentKeys(env).get(m[1].trim()) ?? null;
}
