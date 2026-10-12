// Token broker — the ONLY place that mints Artifacts tokens.
// Agents never see the ARTIFACTS binding; they get short-lived tokens via HTTPS.
//
// Binding signatures verified against
// https://developers.cloudflare.com/artifacts/api/workers-binding/ (2026-10-09):
//   repo.createToken(scope?: "read"|"write", ttl?: number)
//     → Promise<{ plaintext, scope, expiresAt }>
//   repo.revokeToken(tokenOrId: string) → Promise<boolean>
//   repo handles are Disposable — released with `using`.

import { evaluate } from "./policy.js";
import type {
	AccessRequest,
	ArtifactsBinding,
	Env,
	Policy,
	TokenGrant,
} from "./types.js";

export async function requestToken(
	binding: ArtifactsBinding,
	policy: Policy,
	req: AccessRequest,
): Promise<TokenGrant> {
	const decision = evaluate(policy, req);
	if (!decision.allowed) return { decision };
	if (decision.requireApproval) {
		// Elevation ticket is created by the route layer (needs audit DB).
		return { decision };
	}
	using repo = await binding.get(req.repo);
	const minted = await repo.createToken(
		decision.tokenScope ?? "read",
		decision.ttlSeconds ?? 900,
	);
	return {
		decision,
		token: minted.plaintext,
		expiresAt: minted.expiresAt,
	};
}

/** Direct mint used by elevation approval (policy already authorized the shape). */
export async function mintToken(
	binding: ArtifactsBinding,
	repoName: string,
	scope: "read" | "write",
	ttlSeconds: number,
): Promise<{ plaintext: string; expiresAt: string }> {
	using repo = await binding.get(repoName);
	const minted = await repo.createToken(scope, ttlSeconds);
	return { plaintext: minted.plaintext, expiresAt: minted.expiresAt };
}

/** Kill switch: revoke a previously minted token (e.g. on policy violation). */
export async function revokeToken(
	binding: ArtifactsBinding,
	repoName: string,
	tokenOrId: string,
): Promise<boolean> {
	using repo = await binding.get(repoName);
	return repo.revokeToken(tokenOrId);
}

/** Inventory check: list outstanding tokens on a repo. */
export async function listOutstandingTokens(
	binding: ArtifactsBinding,
	repoName: string,
): Promise<number> {
	using repo = await binding.get(repoName);
	const res = await repo.listTokens();
	return res.total;
}

export interface ContainmentResult {
	revoked: number;
	total: number;
}

/**
 * Containment: revoke outstanding write tokens on a repo after an
 * UNEXPLAINED push is detected. The push already landed — we cannot undo
 * it — but we disarm whoever holds write tokens so the breach is limited
 * to a single push.
 *
 * Token entry shape is defensive: when a scope field is present we revoke
 * write tokens only; when the shape is unknown we fail closed and revoke
 * everything rather than risk missing the attacker's token. Best-effort
 * per token: one revoke failing never stops the rest.
 */
export async function revokeAllWriteTokens(
	binding: ArtifactsBinding,
	repoName: string,
): Promise<ContainmentResult> {
	using repo = await binding.get(repoName);
	const res = await repo.listTokens();
	// listTokens() is loosely typed; validate each entry defensively.
	const entries: unknown[] = Array.isArray(res.tokens) ? res.tokens : [];
	let revoked = 0;
	for (const t of entries) {
		const obj =
			typeof t === "object" && t !== null
				? (t as Record<string, unknown>)
				: {};
		const scope = typeof obj.scope === "string" ? obj.scope : undefined;
		if (scope !== undefined && scope !== "write") continue;
		const id =
			typeof t === "string"
				? t
				: typeof obj.id === "string"
					? obj.id
					: typeof obj.tokenId === "string"
						? obj.tokenId
						: undefined;
		if (!id) continue;
		try {
			if (await repo.revokeToken(id)) revoked++;
		} catch {
			// best-effort: keep disarming the rest
		}
	}
	return { revoked, total: entries.length };
}

export type { Env };
