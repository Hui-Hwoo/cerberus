// Audit log + elevation tickets. D1 in production; in-memory for local dev,
// the demo harness, and the lifecycle test.
//
// Tamper-evidence (borrowed from InnerWarden's decision log): every decision
// entry commits to the previous entry via SHA-256 (prev_hash), forming a
// hash chain. Any modification or deletion breaks verification.

import type { AccessRequest, Decision, TokenScope } from "./types.js";

export type Enforcement = "enforce" | "observe";

export interface AuditRecord {
	id: string;
	ts: number;
	req: AccessRequest;
	decision: Decision;
	tokenId?: string;
	enforcement: Enforcement;
	prevHash?: string;
	hash: string;
}

export type ElevationStatus = "pending" | "approved" | "rejected";

export interface ElevationApproval {
	agentId: string;
	ts: number;
}

export interface ElevationTicket {
	id: string;
	decisionId: string;
	ts: number;
	justification: string;
	status: ElevationStatus;
	decidedTs?: number;
	repo: string;
	tokenScope: TokenScope;
	ttlSeconds: number;
	tokenId?: string;
	/** Distinct approvers required (snapshotted from policy at creation). */
	requiredApprovals: number;
	/** Approvals collected so far. */
	approvals: ElevationApproval[];
}

export interface AuditLog {
	append(
		rec: Omit<AuditRecord, "id" | "ts" | "hash" | "prevHash">,
	): Promise<AuditRecord>;
	getDecision(id: string): Promise<AuditRecord | null>;
	recent(limit: number): Promise<AuditRecord[]>;
	stats(): Promise<{ total: number; allowed: number; denied: number }>;
	/**
	 * Denials by one agent since a timestamp (for probing detection).
	 * Excludes advisory probing_suspected flag records themselves so the
	 * flag can't inflate its own trigger count.
	 */
	countDenials(agentId: string, sinceTs: number): Promise<number>;
	createElevation(
		t: Omit<ElevationTicket, "id" | "ts" | "status">,
	): Promise<ElevationTicket>;
	getElevation(id: string): Promise<ElevationTicket | null>;
	listElevations(status?: ElevationStatus): Promise<ElevationTicket[]>;
	/**
	 * Transition a ticket to a final status. Conditional: only applies
	 * when the ticket is still pending. Returns true when this call won
	 * the transition — exactly one concurrent approver/rejecter wins,
	 * so there is never a double mint.
	 */
	setElevationStatus(
		id: string,
		status: ElevationStatus,
		decidedTs: number,
		tokenId?: string,
	): Promise<boolean>;
	/**
	 * Atomically record one approver's approval on a pending ticket.
	 * The append is conditional: it is a no-op when the ticket is no
	 * longer pending or the agent already approved (concurrent duplicate
	 * approvals must not double-count toward quorum).
	 * Returns the post-update ticket and whether the approval was added.
	 */
	addElevationApproval(
		id: string,
		approval: ElevationApproval,
	): Promise<{ ticket: ElevationTicket | null; added: boolean }>;
	logRepoEvent(
		e: Omit<RepoEvent, "id" | "ts">,
	): Promise<RepoEvent>;
	recentRepoEvents(limit: number): Promise<RepoEvent[]>;
}

/** A raw Artifacts repo event observed via Queue event subscription. */
export interface RepoEvent {
	id: string;
	ts: number;
	/** e.g. cf.artifacts.repo.pushed / cf.artifacts.repo.token.created */
	type: string;
	repo: string;
	namespace: string;
	ref?: string;
	/** explained: push matches a recent allow-decision; unexplained: no match;
	 *  observed: informational (token created/revoked, clone, fetch). */
	verdict: "explained" | "unexplained" | "observed";
	/** Decision id that explains this event, when verdict=explained. */
	explainedBy?: string;
	/** JSON detail (commit sha, token scope, …). */
	detail: string;
}

async function sha256Hex(input: string): Promise<string> {
	const digest = await crypto.subtle.digest(
		"SHA-256",
		new TextEncoder().encode(input),
	);
	return [...new Uint8Array(digest)]
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

/** Canonical serialization: fixed field order so hashes are reproducible. */
function canonical(rec: {
	req: AccessRequest;
	decision: Decision;
	enforcement: Enforcement;
	prevHash?: string;
}): string {
	return JSON.stringify({
		agent_id: rec.req.agentId,
		task_id: rec.req.taskId,
		action: rec.req.action,
		repo: rec.req.repo,
		branch: rec.req.branch ?? null,
		paths: rec.req.paths ?? [],
		allowed: rec.decision.allowed,
		reason: rec.decision.reason,
		rule_id: rec.decision.ruleId ?? null,
		token_scope: rec.decision.tokenScope ?? null,
		ttl_seconds: rec.decision.ttlSeconds ?? null,
		// ?? undefined (not null): JSON.stringify omits undefined values, so
		// records written before severity existed hash EXACTLY as before —
		// old chain segments keep verifying after the upgrade.
		severity: rec.decision.severity ?? undefined,
		enforcement: rec.enforcement,
		prev_hash: rec.prevHash ?? null,
	});
}

async function chainAppend(
	rec: Omit<AuditRecord, "id" | "ts" | "hash" | "prevHash">,
	prevHash: string | undefined,
	makeId: () => string,
): Promise<AuditRecord> {
	const hash = await sha256Hex(
		canonical({ ...rec, prevHash }),
	);
	return { ...rec, id: makeId(), ts: Date.now(), prevHash, hash };
}

/**
 * Per-isolate append serialization. Workers isolates are single-threaded
 * but awaits interleave: without this, two concurrent appends read the
 * same lastHash and fork the chain. Cross-isolate races are resolved by
 * the UNIQUE(prev_hash) constraint + retry in D1AuditLog.
 */
let appendChain: Promise<unknown> = Promise.resolve();
function serialized<T>(task: () => Promise<T>): Promise<T> {
	const run = appendChain.then(task);
	appendChain = run.catch(() => undefined);
	return run;
}

function isUniqueViolation(err: unknown): boolean {
	const msg = err instanceof Error ? err.message : String(err);
	return /UNIQUE constraint failed/i.test(msg);
}

function sleep(ms: number): Promise<void> {
	return new Promise((r) => setTimeout(r, ms));
}

/**
 * Verify a hash chain. Pass records oldest-first.
 * Returns the index of the first broken link, or ok:true.
 */
export async function verifyChain(
	records: AuditRecord[],
): Promise<{ ok: boolean; badIndex: number }> {
	let prev: string | undefined;
	for (let i = 0; i < records.length; i++) {
		const r = records[i];
		if ((r.prevHash ?? undefined) !== prev) return { ok: false, badIndex: i };
		const recomputed = await sha256Hex(
			canonical({
				req: r.req,
				decision: r.decision,
				enforcement: r.enforcement,
				prevHash: r.prevHash,
			}),
		);
		if (recomputed !== r.hash) return { ok: false, badIndex: i };
		prev = r.hash;
	}
	return { ok: true, badIndex: -1 };
}

function rowToRecord(r: Record<string, unknown>): AuditRecord {
	return {
		id: String(r.id),
		ts: Number(r.ts),
		req: {
			agentId: String(r.agent_id),
			roles: [],
			taskId: String(r.task_id),
			action: r.action as AuditRecord["req"]["action"],
			repo: String(r.repo),
			branch: r.branch ? String(r.branch) : undefined,
			paths: JSON.parse(String(r.paths ?? "[]")) as string[],
		},
		decision: {
			allowed: Number(r.allowed) === 1,
			reason: String(r.reason),
			ruleId: r.rule_id ? String(r.rule_id) : undefined,
			tokenScope: r.token_scope
				? (String(r.token_scope) as TokenScope)
				: undefined,
			ttlSeconds: r.ttl_seconds ? Number(r.ttl_seconds) : undefined,
			requireApproval: Number(r.require_approval) === 1,
			severity: r.severity
				? (String(r.severity) as AuditRecord["decision"]["severity"])
				: undefined,
		},
		tokenId: r.token_id ? String(r.token_id) : undefined,
		enforcement: (r.enforcement ? String(r.enforcement) : "enforce") as Enforcement,
		prevHash: r.prev_hash ? String(r.prev_hash) : undefined,
		hash: String(r.hash),
	};
}

function rowToTicket(r: Record<string, unknown>): ElevationTicket {
	let approvals: ElevationApproval[] = [];
	try {
		const parsed: unknown = JSON.parse(String(r.approvals ?? "[]"));
		if (Array.isArray(parsed)) approvals = parsed as ElevationApproval[];
	} catch {
		approvals = [];
	}
	return {
		id: String(r.id),
		decisionId: String(r.decision_id),
		ts: Number(r.ts),
		justification: String(r.justification),
		status: String(r.status) as ElevationStatus,
		decidedTs: r.decided_ts ? Number(r.decided_ts) : undefined,
		repo: String(r.repo),
		tokenScope: String(r.token_scope) as TokenScope,
		ttlSeconds: Number(r.ttl_seconds),
		tokenId: r.token_id ? String(r.token_id) : undefined,
		requiredApprovals: r.required_approvals
			? Number(r.required_approvals)
			: 1,
		approvals,
	};
}

export class MemoryAuditLog implements AuditLog {
	private records: AuditRecord[] = [];
	private tickets = new Map<string, ElevationTicket>();
	private lastHash: string | undefined;
	private n = 0;
	private m = 0;

	async append(
		rec: Omit<AuditRecord, "id" | "ts" | "hash" | "prevHash">,
	): Promise<AuditRecord> {
		return serialized(async () => {
			const full = await chainAppend(rec, this.lastHash, () => `dec-${++this.n}`);
			this.lastHash = full.hash;
			this.records.push(full);
			return full;
		});
	}

	async getDecision(id: string): Promise<AuditRecord | null> {
		return this.records.find((r) => r.id === id) ?? null;
	}

	async recent(limit: number): Promise<AuditRecord[]> {
		return this.records.slice(-limit).reverse();
	}

	async stats(): Promise<{ total: number; allowed: number; denied: number }> {
		const allowed = this.records.filter((r) => r.decision.allowed).length;
		return {
			total: this.records.length,
			allowed,
			denied: this.records.length - allowed,
		};
	}

	async countDenials(agentId: string, sinceTs: number): Promise<number> {
		return this.records.filter(
			(r) =>
				r.req.agentId === agentId &&
				r.ts >= sinceTs &&
				!r.decision.allowed &&
				!r.decision.reason.startsWith("probing_suspected:"),
		).length;
	}

	async createElevation(
		t: Omit<ElevationTicket, "id" | "ts" | "status">,
	): Promise<ElevationTicket> {
		const full: ElevationTicket = {
			...t,
			id: `elev-${++this.m}`,
			ts: Date.now(),
			status: "pending",
		};
		this.tickets.set(full.id, full);
		return full;
	}

	async getElevation(id: string): Promise<ElevationTicket | null> {
		return this.tickets.get(id) ?? null;
	}

	async listElevations(status?: ElevationStatus): Promise<ElevationTicket[]> {
		const all = [...this.tickets.values()].sort((a, b) => b.ts - a.ts);
		return status ? all.filter((t) => t.status === status) : all;
	}

	async setElevationStatus(
		id: string,
		status: ElevationStatus,
		decidedTs: number,
		tokenId?: string,
	): Promise<boolean> {
		const t = this.tickets.get(id);
		if (!t || t.status !== "pending") return false;
		t.status = status;
		t.decidedTs = decidedTs;
		if (tokenId) t.tokenId = tokenId;
		return true;
	}

	async addElevationApproval(
		id: string,
		approval: ElevationApproval,
	): Promise<{ ticket: ElevationTicket | null; added: boolean }> {
		const t = this.tickets.get(id);
		if (!t || t.status !== "pending") return { ticket: t ?? null, added: false };
		if ((t.approvals ?? []).some((a) => a.agentId === approval.agentId)) {
			return { ticket: t, added: false };
		}
		t.approvals = [...(t.approvals ?? []), approval];
		return { ticket: t, added: true };
	}

	private events: RepoEvent[] = [];
	private e = 0;

	async logRepoEvent(e: Omit<RepoEvent, "id" | "ts">): Promise<RepoEvent> {
		const full: RepoEvent = { ...e, id: `evt-${++this.e}`, ts: Date.now() };
		this.events.push(full);
		return full;
	}

	async recentRepoEvents(limit: number): Promise<RepoEvent[]> {
		return this.events.slice(-limit).reverse();
	}
}

export class D1AuditLog implements AuditLog {
	constructor(private db: D1Database) {}

	private async lastHash(): Promise<string | undefined> {
		// rowid = insertion order. NEVER use ORDER BY ts here: under burst,
		// many rows share the same millisecond ts, and D1 returns an
		// arbitrary tied row — not necessarily the chain tip. Reading a
		// stale tip causes UNIQUE(prev_hash) collisions that retries can
		// never resolve, because every retry may draw the same wrong row.
		const row = await this.db
			.prepare(`SELECT hash FROM decisions ORDER BY rowid DESC LIMIT 1`)
			.first<{ hash: string }>();
		return row?.hash;
	}

	async append(
		rec: Omit<AuditRecord, "id" | "ts" | "hash" | "prevHash">,
	): Promise<AuditRecord> {
		return serialized(() => this.appendInner(rec));
	}

	/**
	 * Read-compute-write with optimistic concurrency + bounded retry.
	 * UNIQUE(prev_hash) keeps the chain linear when isolates race on the
	 * tip. D1 is single-threaded: under burst its queue fills and it
	 * returns "overloaded" — writes are NOT auto-retried by D1 (only
	 * reads are), so we retry here with FULL-JITTER backoff (never
	 * synchronized thundering-herd retries), up to ~8s total.
	 * After 8 attempts we throw → the route fail-closes (503, no token).
	 */
	private async appendInner(
		rec: Omit<AuditRecord, "id" | "ts" | "hash" | "prevHash">,
	): Promise<AuditRecord> {
		let lastErr: unknown;
		for (let attempt = 0; attempt < 8; attempt++) {
			// Full jitter: sleep(random * cap), cap doubles per attempt.
			// Desynchronizes retries across isolates under burst.
			await sleep(Math.random() * Math.min(4000, 100 * 2 ** attempt));
			const full = await chainAppend(rec, await this.lastHash(), () =>
				crypto.randomUUID(),
			);
			try {
				await this.db
					.prepare(
						`INSERT INTO decisions
						 (id, ts, agent_id, task_id, action, repo, branch, paths, allowed, reason, rule_id, token_scope, ttl_seconds, token_id, require_approval, enforcement, severity, prev_hash, hash)
						 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
					)
					.bind(
						full.id,
						full.ts,
						full.req.agentId,
						full.req.taskId,
						full.req.action,
						full.req.repo,
						full.req.branch ?? null,
						JSON.stringify(full.req.paths ?? []),
						full.decision.allowed ? 1 : 0,
						full.decision.reason,
						full.decision.ruleId ?? null,
						full.decision.tokenScope ?? null,
						full.decision.ttlSeconds ?? null,
						full.tokenId ?? null,
						full.decision.requireApproval ? 1 : 0,
						full.enforcement,
						full.decision.severity ?? null,
						full.prevHash ?? null,
						full.hash,
					)
					.run();
				return full;
			} catch (err) {
				lastErr = err;
				if (!isUniqueViolation(err)) {
					console.error(
						`cerberus audit append attempt ${attempt + 1} failed:`,
						err,
					);
				}
			}
		}
		throw lastErr;
	}

	async getDecision(id: string): Promise<AuditRecord | null> {
		const row = await this.db
			.prepare(`SELECT * FROM decisions WHERE id = ?`)
			.bind(id)
			.first<Record<string, unknown>>();
		return row ? rowToRecord(row) : null;
	}

	async recent(limit: number): Promise<AuditRecord[]> {
		const rows = await this.db
			.prepare(`SELECT * FROM decisions ORDER BY ts DESC LIMIT ?`)
			.bind(limit)
			.all<Record<string, unknown>>();
		return (rows.results ?? []).map(rowToRecord);
	}

	async stats(): Promise<{ total: number; allowed: number; denied: number }> {
		const row = await this.db
			.prepare(`SELECT COUNT(*) AS total, SUM(allowed) AS allowed FROM decisions`)
			.first<{ total: number; allowed: number }>();
		const total = row?.total ?? 0;
		const allowed = row?.allowed ?? 0;
		return { total, allowed, denied: total - allowed };
	}

	async countDenials(agentId: string, sinceTs: number): Promise<number> {
		const row = await this.db
			.prepare(
				`SELECT COUNT(*) AS n FROM decisions
				 WHERE agent_id = ? AND ts >= ? AND allowed = 0
				 AND reason NOT LIKE 'probing_suspected:%'`,
			)
			.bind(agentId, sinceTs)
			.first<{ n: number }>();
		return row?.n ?? 0;
	}

	async createElevation(
		t: Omit<ElevationTicket, "id" | "ts" | "status">,
	): Promise<ElevationTicket> {
		const full: ElevationTicket = {
			...t,
			id: crypto.randomUUID(),
			ts: Date.now(),
			status: "pending",
		};
		await this.db
			.prepare(
				`INSERT INTO elevations
				 (id, decision_id, ts, justification, status, repo, token_scope, ttl_seconds,
				  required_approvals, approvals)
				 VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?)`,
			)
			.bind(
				full.id,
				full.decisionId,
				full.ts,
				full.justification,
				full.repo,
				full.tokenScope,
				full.ttlSeconds,
				full.requiredApprovals ?? 1,
				JSON.stringify(full.approvals ?? []),
			)
			.run();
		return full;
	}

	async getElevation(id: string): Promise<ElevationTicket | null> {
		const row = await this.db
			.prepare(`SELECT * FROM elevations WHERE id = ?`)
			.bind(id)
			.first<Record<string, unknown>>();
		return row ? rowToTicket(row) : null;
	}

	async listElevations(status?: ElevationStatus): Promise<ElevationTicket[]> {
		const rows = status
			? await this.db
					.prepare(`SELECT * FROM elevations WHERE status = ? ORDER BY ts DESC`)
					.bind(status)
					.all<Record<string, unknown>>()
			: await this.db
					.prepare(`SELECT * FROM elevations ORDER BY ts DESC`)
					.all<Record<string, unknown>>();
		return (rows.results ?? []).map(rowToTicket);
	}

	async setElevationStatus(
		id: string,
		status: ElevationStatus,
		decidedTs: number,
		tokenId?: string,
	): Promise<boolean> {
		const res = await this.db
			.prepare(
				`UPDATE elevations SET status = ?, decided_ts = ?, token_id = ?
				 WHERE id = ? AND status = 'pending'`,
			)
			.bind(status, decidedTs, tokenId ?? null, id)
			.run();
		return (res.meta?.rows_written ?? 0) > 0;
	}

	async addElevationApproval(
		id: string,
		approval: ElevationApproval,
	): Promise<{ ticket: ElevationTicket | null; added: boolean }> {
		// Atomic append-if-not-duplicate: concurrent approvals from the
		// same agent must not double-count toward quorum.
		const res = await this.db
			.prepare(
				`UPDATE elevations
				 SET approvals = json_insert(approvals, '$[#]', json(?))
				 WHERE id = ? AND status = 'pending'
				 AND NOT EXISTS (
					SELECT 1 FROM json_each(approvals)
					WHERE json_extract(json_each.value, '$.agentId') = ?
				 )`,
			)
			.bind(JSON.stringify(approval), id, approval.agentId)
			.run();
		const added = (res.meta?.rows_written ?? 0) > 0;
		return { ticket: await this.getElevation(id), added };
	}

	async logRepoEvent(e: Omit<RepoEvent, "id" | "ts">): Promise<RepoEvent> {
		const full: RepoEvent = { ...e, id: crypto.randomUUID(), ts: Date.now() };
		await this.db
			.prepare(
				`INSERT INTO repo_events
				 (id, ts, type, repo, namespace, ref, verdict, explained_by, detail)
				 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			)
			.bind(
				full.id,
				full.ts,
				full.type,
				full.repo,
				full.namespace,
				full.ref ?? null,
				full.verdict,
				full.explainedBy ?? null,
				full.detail,
			)
			.run();
		return full;
	}

	async recentRepoEvents(limit: number): Promise<RepoEvent[]> {
		const rows = await this.db
			.prepare(`SELECT * FROM repo_events ORDER BY ts DESC LIMIT ?`)
			.bind(limit)
			.all<Record<string, unknown>>();
		return (rows.results ?? []).map((r) => ({
			id: String(r.id),
			ts: Number(r.ts),
			type: String(r.type),
			repo: String(r.repo),
			namespace: String(r.namespace),
			ref: r.ref ? String(r.ref) : undefined,
			verdict: String(r.verdict) as RepoEvent["verdict"],
			explainedBy: r.explained_by ? String(r.explained_by) : undefined,
			detail: String(r.detail),
		}));
	}
}
