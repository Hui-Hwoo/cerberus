// Post-hoc reconciliation: Artifacts repo events (delivered via a Queue event
// subscription) are cross-checked against the broker's decision log.
// A push that has no matching allow-decision is flagged UNEXPLAINED —
// meaning something landed that the policy never approved.

import type { AuditLog, RepoEvent } from "./audit.js";
import { globToRegExp } from "./policy.js";

export interface AllowDecisionRef {
	id: string;
	repo: string;
	branch?: string;
	ts: number;
	/** Declared paths from the mint request; used for content verification. */
	paths?: string[];
}

/** refs/heads/docs/faq -> docs/faq */
export function branchFromRef(ref: string): string {
	return ref.replace(/^refs\/heads\//, "");
}

/**
 * Pure: find an allow-decision that explains a push.
 * Returns the decision id, or null when nothing matches (UNEXPLAINED).
 *
 * Single-use: a decision explains at most ONE push. Without this, an
 * attacker who bypasses the gate could piggyback on a recent legitimate
 * allow-decision for the same branch and have their push marked
 * "explained" — laundering the bypass and suppressing containment.
 */
export function verdictForPush(
	allowDecisions: AllowDecisionRef[],
	consumedDecisionIds: Set<string>,
	repo: string,
	branch: string,
	nowMs: number,
	windowMs = 30 * 60 * 1000,
): string | null {
	const hit = allowDecisions.find(
		(d) =>
			!consumedDecisionIds.has(d.id) &&
			d.repo === repo &&
			d.branch === branch &&
			nowMs - d.ts <= windowMs,
	);
	return hit ? hit.id : null;
}

export interface ArtifactsQueueEvent {
	type?: string;
	source?: { type?: string; namespace?: string; repoName?: string };
	payload?: Record<string, unknown>;
}

/**
 * Minimal commit/tree reader surface for content verification.
 * Field shapes follow @cloudflare/workers-types Artifacts definitions.
 */
export interface CommitTreeReader {
	readCommit(hash: string): Promise<{ treeHash: string } | null>;
	readTree(
		hash: string,
	): Promise<Array<{ name: string; type: string; hash: string }> | null>;
	/** Default branch name, e.g. "main". */
	getDefaultBranch(): Promise<string | null>;
	/** Current tip commit of a branch, or null when unresolvable. */
	getBranchTip(branch: string): Promise<string | null>;
}

/** A pushed commit as delivered in the event payload. */
export interface PushedCommit {
	id: string;
	parents: string[];
}

/** Everything the content check needs about a push. */
export interface PushInfo {
	repo: string;
	branch: string;
	before: string;
	after: string;
	commits: PushedCommit[];
}

function isTreeDir(type: string): boolean {
	return type === "tree";
}

/**
 * List all file paths in a tree (recursive), mapped to blob hashes.
 * Returns null when the walk cannot be completed (cap hit, API failure,
 * unexpected shape) — callers must treat null as "unknown", never "empty".
 */
export async function listTreeFiles(
	reader: CommitTreeReader,
	rootHash: string,
	maxEntries = 2000,
	maxDepth = 12,
): Promise<Map<string, string> | null> {
	const out = new Map<string, string>();
	const stack: Array<{ hash: string; prefix: string; depth: number }> = [
		{ hash: rootHash, prefix: "", depth: 0 },
	];
	try {
		while (stack.length > 0) {
			const { hash, prefix, depth } = stack.pop()!;
			if (depth > maxDepth || out.size > maxEntries) return null;
			const entries = await reader.readTree(hash);
			if (!entries) return null;
			for (const e of entries) {
				if (!e || typeof e.name !== "string") return null;
				const p = prefix + e.name;
				if (isTreeDir(e.type)) {
					if (typeof e.hash !== "string") return null;
					stack.push({ hash: e.hash, prefix: p + "/", depth: depth + 1 });
				} else {
					out.set(p, typeof e.hash === "string" ? e.hash : "");
					if (out.size > maxEntries) return null;
				}
			}
		}
		return out;
	} catch {
		return null;
	}
}

/**
 * Paths changed by a push (added, modified, or deleted).
 *
 * The base commit is resolved two ways:
 * - existing branch: the event's `before` sha (exact);
 * - new branch (`before` is all zeros): the fork point, found by locating
 *   the default branch's tip inside the event's commit chain.
 * Returns null when indeterminable; a null result must never be treated
 * as "nothing changed".
 */
export async function pushChangedPaths(
	reader: CommitTreeReader,
	push: PushInfo,
	onError?: (stage: string, err: unknown) => void,
): Promise<string[] | null> {
	if (!push.after || /^0+$/.test(push.after)) return null;
	const fail = (stage: string, err?: unknown): null => {
		if (onError) {
			try {
				onError(stage, err);
			} catch {
				// never break reconciliation for observability
			}
		}
		return null;
	};
	try {
		let baseHash: string | null = null;
		if (push.before && !/^0+$/.test(push.before)) {
			baseHash = push.before;
		} else {
			// New branch: find the fork point via the default branch tip.
			let defaultBranch: string | null;
			try {
				defaultBranch = await reader.getDefaultBranch();
			} catch (err) {
				return fail("getDefaultBranch", err);
			}
			if (!defaultBranch) return fail("getDefaultBranch: null");
			let defaultTip: string | null;
			try {
				defaultTip = await reader.getBranchTip(defaultBranch);
			} catch (err) {
				return fail("getBranchTip", err);
			}
			if (!defaultTip) return fail("getBranchTip: null");
			const idx = push.commits.findIndex((c) => c.id === defaultTip);
			if (idx < 0) return fail("fork point not in commit chain");
			baseHash = push.commits[idx].id;
		}
		let baseTree: string | null;
		let afterTree: string | null;
		try {
			baseTree = (await reader.readCommit(baseHash))?.treeHash ?? null;
			afterTree = (await reader.readCommit(push.after))?.treeHash ?? null;
		} catch (err) {
			return fail("readCommit", err);
		}
		if (!baseTree) return fail("readCommit(base): null");
		if (!afterTree) return fail("readCommit(after): null");
		let a: Map<string, string> | null;
		let b: Map<string, string> | null;
		try {
			[a, b] = await Promise.all([
				listTreeFiles(reader, baseTree),
				listTreeFiles(reader, afterTree),
			]);
		} catch (err) {
			return fail("listTreeFiles", err);
		}
		if (!a || !b) return fail("listTreeFiles: null");
		const changed: string[] = [];
		for (const [p, h] of b) if (a.get(p) !== h) changed.push(p);
		for (const p of a.keys()) if (!b.has(p)) changed.push(p);
		return changed;
	} catch (err) {
		return fail("unexpected", err);
	}
}

/** Every changed path must be covered by at least one allowed glob. */
export function pathsCoverGlobs(changed: string[], globs: string[]): boolean {
	return changed.every((p) => globs.some((g) => globToRegExp(g).test(p)));
}

export type ContainmentOutcome =
	| { ok: true; revoked: number; total: number; skipped?: string }
	| { ok: false; error: string };

/**
 * Hooks for side effects during event handling. Containment runs only on
 * UNEXPLAINED pushes: the push already landed, so we disarm outstanding
 * write tokens to bound the breach to the detection window. The hook must never
 * throw — a containment failure is recorded in the event detail, never
 * allowed to break event logging (which would cause queue redelivery and
 * duplicate audit records).
 */
export interface ContainmentHooks {
	onUnexplainedPush?: (
		repo: string,
		branch: string,
	) => Promise<{ revoked: number; total: number; skipped?: string }>;
	/**
	 * Best-effort content diff for a push. Returns changed paths, or null
	 * (with an optional error stage for observability) when
	 * indeterminable. Must not throw — a null result falls back to
	 * branch-only matching.
	 */
	verifyPushContent?: (
		push: PushInfo,
	) => Promise<{ changed: string[] | null; error?: string }>;
}

/** Consume one Artifacts event: log it, and verdict pushes against decisions. */
export async function handleArtifactsEvent(
	audit: AuditLog,
	event: ArtifactsQueueEvent,
	nowMs = Date.now(),
	hooks: ContainmentHooks = {},
): Promise<RepoEvent> {
	const type = event.type ?? "unknown";
	const repo = event.source?.repoName ?? "";
	const namespace = event.source?.namespace ?? "";
	const payload = event.payload ?? {};

	if (type === "cf.artifacts.repo.pushed") {
		const ref = typeof payload.ref === "string" ? payload.ref : "";
		const branch = branchFromRef(ref);
		const after = typeof payload.after === "string" ? payload.after : "";
		const before = typeof payload.before === "string" ? payload.before : "";
		// Only pushes need the reconciliation reads; other events are
		// informational. Keeps D1 read load down under burst.
		const decisions = await audit.recent(100);
		const pastEvents = await audit.recentRepoEvents(100);
		// Dedupe: a redelivered queue message must not log twice or
		// trigger containment twice. Match on repo+ref+commit sha.
		if (after) {
			const dup = pastEvents.find((e) => {
				if (e.type !== type || e.repo !== repo || e.ref !== ref) return false;
				try {
					return (JSON.parse(e.detail) as { after?: string }).after === after;
				} catch {
					return false;
				}
			});
			if (dup) return dup;
		}
		// Single-use: decisions already consumed by an earlier explained
		// push cannot launder a later bypass (piggyback attack).
		const consumed = new Set(
			pastEvents
				.filter((e) => e.verdict === "explained" && e.explainedBy)
				.map((e) => e.explainedBy as string),
		);
		// Candidates, newest-first (audit.recent returns newest-first).
		const candidates = decisions
			.filter((r) => r.decision.allowed)
			.map((r) => ({
				id: r.id,
				repo: r.req.repo,
				branch: r.req.branch,
				ts: r.ts,
				paths: r.req.paths,
			}))
			.filter(
				(d) =>
					!consumed.has(d.id) &&
					d.repo === repo &&
					d.branch === branch &&
					nowMs - d.ts <= 30 * 60 * 1000,
			);
		// Content-aware matching: a push is explained only if its changed
		// files fall within the decision's declared paths. Without this, an
		// agent could mint for docs/** and push src/auth/** to the same
		// branch — branch matches, content violates, and the old code would
		// have marked it explained. When the diff is indeterminable (or no
		// decision declares paths), fall back to branch-only matching and
		// say so honestly in the event detail.
		let explainedBy: string | null = null;
		let contentVerified: boolean | undefined;
		let contentError: string | undefined;
		let contentViolation: { changed: string[]; allowedPaths: string[] } | undefined;
		if (candidates.length > 0) {
			const needsContent = candidates.some(
				(c) => c.paths && c.paths.length > 0,
			);
			let changed: string[] | null = null;
			if (needsContent && after && hooks.verifyPushContent) {
				const commits: PushedCommit[] = Array.isArray(payload.commits)
					? (payload.commits as Array<Record<string, unknown>>)
							.slice(0, 200)
							.map((c) => ({
								id: typeof c.id === "string" ? c.id : "",
								parents: Array.isArray(c.parents)
									? c.parents.filter(
											(p): p is string => typeof p === "string",
										)
									: [],
							}))
							.filter((c) => c.id)
					: [];
				try {
					const r = await hooks.verifyPushContent({
						repo,
						branch,
						before,
						after,
						commits,
					});
					changed = r.changed;
					contentError = r.error;
				} catch (err) {
					changed = null;
					contentError = err instanceof Error ? err.message : String(err);
				}
			}
			if (changed) {
				const hit = candidates.find(
					(c) =>
						!c.paths ||
						c.paths.length === 0 ||
						pathsCoverGlobs(changed, c.paths),
				);
				if (hit) {
					explainedBy = hit.id;
					contentVerified = true;
				} else {
					const newest = candidates[0];
					contentViolation = {
						changed,
						allowedPaths: newest.paths ?? [],
					};
				}
			} else {
				explainedBy = candidates[0].id;
				if (needsContent) contentVerified = false;
			}
		}
		// Containment: an unexplained push means something bypassed the
		// gate. Disarm outstanding write tokens so the breach stays at
		// one push. Never throws — failure is recorded, not propagated.
		let containment: ContainmentOutcome | undefined;
		if (!explainedBy && hooks.onUnexplainedPush) {
			try {
				const r = await hooks.onUnexplainedPush(repo, branch);
				containment = {
					ok: true,
					revoked: r.revoked,
					total: r.total,
					...(r.skipped ? { skipped: r.skipped } : {}),
				};
			} catch (err) {
				containment = {
					ok: false,
					error: err instanceof Error ? err.message : String(err),
				};
			}
		}
		return audit.logRepoEvent({
			type,
			repo,
			namespace,
			ref,
			verdict: explainedBy ? "explained" : "unexplained",
			explainedBy: explainedBy ?? undefined,
			detail: JSON.stringify({
				after,
				before,
				commits: Array.isArray(payload.commits) ? payload.commits.length : 0,
				...(contentVerified !== undefined ? { contentVerified } : {}),
				...(contentError ? { contentError } : {}),
				...(contentViolation ? { contentViolation } : {}),
				...(containment ? { containment } : {}),
			}),
		});
	}

	// token.created / token.revoked / cloned / fetched: informational.
	return audit.logRepoEvent({
		type,
		repo,
		namespace,
		verdict: "observed",
		detail: JSON.stringify(payload),
	});
}
