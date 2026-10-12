// Shared types for Cerberus.

export type Action = "read" | "push" | "create-branch" | "fork" | "create-repo";
export type Effect = "allow" | "deny";
export type TokenScope = "read" | "write";

/**
 * Advisory severity for a decision — filtering/display only, never changes
 * the allow/deny outcome. (Borrowed from InnerWarden's
 * crates/core/src/event.rs::Severity.)
 */
export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface PolicyRule {
	id: string;
	effect: Effect;
	/** Agent ids this rule applies to. Omit or ["*"] = any agent. */
	agents?: string[];
	/** Roles this rule applies to. Omit or ["*"] = any role. */
	roles?: string[];
	actions: Action[];
	/** Repo name globs. Omit = any repo. */
	repos?: string[];
	/** Branch globs. Checked for push/create-branch. Omit = any branch. */
	branches?: string[];
	/**
	 * Path globs. When the request lists paths, EVERY touched path must match
	 * at least one glob. Omit = any path.
	 */
	paths?: string[];
	/** Cap on minted token TTL (seconds). Defaults to 900. */
	maxTtlSeconds?: number;
	/** Allow, but only via human approval (elevation ticket). */
	requireApproval?: boolean;
}

export interface Policy {
	version: 1;
	defaultEffect: Effect;
	rules: PolicyRule[];
	/**
	 * "enforce" (default): deny decisions block token minting.
	 * "observe": deny decisions are still blocked, but logged and reported as
	 * would-deny — lets teams validate a policy against real agent traffic
	 * before enforcing. Borrowed from InnerWarden's dry_run safe default:
	 * new deployments start non-disruptive.
	 */
	mode?: "enforce" | "observe";
	/**
	 * Distinct approvers required to grant an elevation ticket.
	 * Default 1. Set to 2+ for quorum: no single approver (and never the
	 * requester) can unilaterally grant elevated access.
	 */
	elevationQuorum?: number;
}

export interface AccessRequest {
	agentId: string;
	roles: string[];
	taskId: string;
	action: Action;
	repo: string;
	branch?: string;
	/** Repository-relative paths the agent intends to touch. */
	paths?: string[];
}

export interface Decision {
	allowed: boolean;
	reason: string;
	ruleId?: string;
	tokenScope?: TokenScope;
	ttlSeconds?: number;
	requireApproval?: boolean;
	/** Advisory severity (info/low/medium/high/critical). Set by severityFor(). */
	severity?: Severity;
	/**
	 * SHA-256 (first 16 hex chars) of the POLICY_JSON this decision was
	 * evaluated against. Lets an auditor tell which policy version
	 * produced a decision — without it, a silent policy change could
	 * make old decisions unverifiable.
	 */
	policyHash?: string;
}

export interface TokenGrant {
	decision: Decision;
	/** Git token plaintext — only present when allowed && !requireApproval. */
	token?: string;
	expiresAt?: string;
	/** Elevation ticket id — only present when allowed && requireApproval. */
	elevationId?: string;
}

/** Minimal Artifacts binding surface we use (verified against official docs 2026-10-09). */
export interface ArtifactsBinding {
	get(name: string): Promise<ArtifactsRepoHandle>;
	create(
		name: string,
		opts?: {
			description?: string;
			readOnly?: boolean;
			setDefaultBranch?: string;
		},
	): Promise<{
		name: string;
		remote: string;
		defaultBranch: string;
		token: string;
	}>;
}

export interface ArtifactsRepoHandle extends Disposable {
	createToken(
		scope?: TokenScope,
		ttl?: number,
	): Promise<{ plaintext: string; scope: TokenScope; expiresAt: string }>;
	revokeToken(tokenOrId: string): Promise<boolean>;
	listTokens(): Promise<{ total: number; tokens: unknown[] }>;
	readCommit(hash: string): Promise<{ treeHash: string } | null>;
	readTree(
		hash: string,
	): Promise<Array<{ name: string; type: string; hash: string }> | null>;
	log(opts?: {
		ref?: string;
		limit?: number;
		offset?: number;
	}): Promise<Array<{ hash: string }>>;
	info(): Promise<{ defaultBranch: string }>;
}

export interface Env {
	ARTIFACTS: ArtifactsBinding;
	AUDIT_DB: D1Database;
	/** JSON-serialized Policy. Loaded from a secret / KV in production. */
	POLICY_JSON: string;
	/** JSON-serialized agent key registry: { keys: { "<secret>": { agentId, roles, canApprove?, isAdmin? } } } */
	AGENT_KEYS_JSON: string;
	/** Optional webhook URL for elevation-ticket approver alerts (best-effort, fail-open). */
	NOTIFY_WEBHOOK_URL?: string;
	/** Optional HMAC secret for signing webhook payloads (x-cerberus-signature). */
	NOTIFY_WEBHOOK_SECRET?: string;
}
