// HTTP route handlers for the Cerberus Worker.
// Pure request handling — entrypoint wiring lives in index.ts,
// shared context (policy/audit/auth) in context.ts.

import { verifyChain } from "./audit.js";
import { mintToken, revokeToken } from "./broker.js";
import {
	getAudit,
	getPolicy,
	getPolicyHash,
	requireKey,
} from "./context.js";
import { evaluate, severityFor } from "./policy.js";
import type { AccessRequest, Decision, Env } from "./types.js";
import { auditPage } from "./ui.js";
import { hmacSha256Hex, json, readJson } from "./util.js";

interface ElevationPayload {
	event: string;
	ticketId?: string;
	agentId?: string;
	repo?: string;
	scope?: string;
	ttlSeconds?: number;
	justification?: string;
	approveUrl?: string;
	rejectUrl?: string;
	ts: number;
}

/**
 * POST a signed JSON payload to NOTIFY_WEBHOOK_URL. Throws on non-2xx —
 * callers must treat this as best-effort (fail-open): the ticket is the
 * record, the notification is a courtesy.
 */
async function postWebhook(
	env: Env,
	payload: ElevationPayload,
): Promise<void> {
	const url = env.NOTIFY_WEBHOOK_URL;
	if (!url) throw new Error("NOTIFY_WEBHOOK_URL is not set");
	const body = JSON.stringify(payload);
	const headers: Record<string, string> = {
		"content-type": "application/json",
	};
	if (env.NOTIFY_WEBHOOK_SECRET) {
		const sig = await hmacSha256Hex(env.NOTIFY_WEBHOOK_SECRET, body);
		headers["x-cerberus-signature"] = `sha256=${sig}`;
	}
	const res = await fetch(url, { method: "POST", headers, body });
	if (!res.ok) throw new Error(`webhook responded ${res.status}`);
}

async function notifyElevation(
	env: Env,
	req: Request,
	ticket: { id: string; repo: string; tokenScope: string; ttlSeconds: number; justification: string },
	agentId: string,
): Promise<void> {
	const origin = new URL(req.url).origin;
	await postWebhook(env, {
		event: "elevation.created",
		ticketId: ticket.id,
		agentId,
		repo: ticket.repo,
		scope: ticket.tokenScope,
		ttlSeconds: ticket.ttlSeconds,
		justification: ticket.justification,
		approveUrl: `${origin}/v1/elevate/${ticket.id}/approve`,
		rejectUrl: `${origin}/v1/elevate/${ticket.id}/reject`,
		ts: Date.now(),
	});
}

/** Narrowest grant the approver can issue: ≤5 min TTL. */
const ELEVATION_TTL_CAP = 300;

/** Denials by one agent in 60s that trigger a probing_suspected flag. */
const PROBE_DENIAL_THRESHOLD = 5;
/** Trailing window (ms) for probing detection. */
const PROBE_WINDOW_MS = 60_000;

export async function handleFetch(
	req: Request,
	env: Env,
	ctx?: ExecutionContext,
): Promise<Response> {
		const url = new URL(req.url);
		const path = url.pathname;
		const policy = getPolicy(env);
		const audit = getAudit(env);

		// POST /v1/admin/repos — demo-only repo provisioning.
		// Bearer key with isAdmin. Production deployments should disable
		// this route entirely.
		if (req.method === "POST" && path === "/v1/admin/repos") {
			const auth = requireKey(req, env, { admin: true });
			if (auth instanceof Response) return auth;
			const { name, description } = await readJson<{
				name: string;
				description?: string;
			}>(req);
			const created = await env.ARTIFACTS.create(name, {
				description,
				setDefaultBranch: "main",
			});
			await audit.append({
				req: {
					agentId: "admin",
					roles: ["admin"],
					taskId: "admin-provision",
					action: "create-repo",
					repo: name,
				},
				decision: { allowed: true, reason: "admin repo provisioning" },
				enforcement: policy.mode ?? "enforce",
			});
			return json({
				name: created.name,
				remote: created.remote,
				defaultBranch: created.defaultBranch,
			});
		}

		// POST /v1/token — the core gate.
		// Identity comes from the bearer key, never from the body.
		// Ordering: evaluate → audit → mint. The decision record is
		// written BEFORE any token exists, so a token never exists
		// without a decision on file (if mint fails, the agent retries
		// and gets a fresh decision record — no orphan tokens).
		if (req.method === "POST" && path === "/v1/token") {
			const auth = requireKey(req, env);
			if (auth instanceof Response) return auth;
			const body = await readJson<Omit<AccessRequest, "agentId" | "roles">>(req);
			const access: AccessRequest = {
				agentId: auth.agentId,
				roles: auth.roles,
				taskId: body.taskId,
				action: body.action,
				repo: body.repo,
				branch: body.branch,
				paths: body.paths,
			};
			const enforcement = policy.mode ?? "enforce";
			const decision = evaluate(policy, access);
			// Advisory severity for filtering/display (never changes the outcome).
			decision.severity = severityFor(access, decision);
			// Bind the decision to the exact policy version that produced it.
			decision.policyHash = await getPolicyHash(env);
			const record = await audit.append({
				req: access,
				decision,
				enforcement,
			});

			if (!decision.allowed) {
				// Probing detection (InnerWarden correlation.rs idea): a burst of
				// denials from one agent smells like casing the repo. Advisory
				// ONLY — it never blocks anything by itself. Fires once per
				// cluster: exactly at the threshold crossing.
				const denials = await audit.countDenials(
					access.agentId,
					Date.now() - PROBE_WINDOW_MS,
				);
				let probing: string | undefined;
				if (denials === PROBE_DENIAL_THRESHOLD) {
					const probe = await audit.append({
						req: access,
						decision: {
							allowed: false,
							reason: `probing_suspected: ${denials} denials in 60s by ${access.agentId}`,
							severity: "critical",
						},
						enforcement,
					});
					probing = probe.id;
				}
				return json(
					{
						allowed: false,
						reason: decision.reason,
						decisionId: record.id,
						enforcement,
						probingSuspected: probing,
						note:
							enforcement === "observe"
								? "observe mode: this would block in enforce mode"
								: undefined,
					},
					403,
				);
			}
			if (decision.requireApproval) {
				return json(
					{
						allowed: true,
						requireApproval: true,
						reason: decision.reason,
						decisionId: record.id,
						hint: "POST /v1/elevate {decisionId, justification} to request approval",
					},
					202,
				);
			}
			const minted = await mintToken(
				env.ARTIFACTS,
				access.repo,
				decision.tokenScope ?? "read",
				decision.ttlSeconds ?? 900,
			);
			return json({
				allowed: true,
				token: minted.plaintext,
				expiresAt: minted.expiresAt,
				scope: decision.tokenScope,
				ttlSeconds: decision.ttlSeconds,
				decisionId: record.id,
			});
		}

		// POST /v1/elevate — agent escalates a requireApproval decision.
		// The ticket is bound to the requesting key's identity: an agent can
		// only elevate its own decisions.
		if (req.method === "POST" && path === "/v1/elevate") {
			const auth = requireKey(req, env);
			if (auth instanceof Response) return auth;
			const { decisionId, justification } = await readJson<{
				decisionId: string;
				justification: string;
			}>(req);
			const rec = await audit.getDecision(decisionId);
			if (!rec) return json({ error: "decision not found" }, 404);
			if (rec.req.agentId !== auth.agentId)
				return json({ error: "cannot elevate another agent's decision" }, 403);
			if (!rec.decision.allowed || !rec.decision.requireApproval) {
				return json(
					{ error: "decision is not eligible for elevation" },
					422,
				);
			}
			const ticket = await audit.createElevation({
				decisionId,
				justification: justification ?? "",
				repo: rec.req.repo,
				tokenScope: rec.decision.tokenScope ?? "read",
				ttlSeconds: Math.min(rec.decision.ttlSeconds ?? 300, ELEVATION_TTL_CAP),
				requiredApprovals: Math.max(1, policy.elevationQuorum ?? 1),
				approvals: [],
			});
			// Approver alerting (InnerWarden notifier pattern): a human approval
			// nobody hears about is theater. Best-effort + fail-open — if the
			// webhook is down, the ticket still exists; the ticket, not the
			// notification, is the record of truth.
			if (env.NOTIFY_WEBHOOK_URL && ctx) {
				ctx.waitUntil(
					notifyElevation(env, req, ticket, auth.agentId).catch((err) =>
						console.error("cerberus webhook notify failed (best-effort):", err),
					),
				);
			}
			return json({ elevationId: ticket.id, status: ticket.status }, 202);
		}

		// POST /v1/elevate/:id/approve — human approves (approver key required).
		// Quorum: the ticket mints only after `requiredApprovals` DISTINCT
		// approvers (never the requester) have approved. Earlier approvals
		// return 202 with progress; the final one returns the token.
		let m = path.match(/^\/v1\/elevate\/([^/]+)\/approve$/);
		if (req.method === "POST" && m) {
			const auth = requireKey(req, env, { approve: true });
			if (auth instanceof Response) return auth;
			const ticket = await audit.getElevation(m[1]);
			if (!ticket) return json({ error: "elevation not found" }, 404);
			if (ticket.status !== "pending") {
				return json(
					{ error: `already ${ticket.status}` },
					409,
				);
			}
			const rec = await audit.getDecision(ticket.decisionId);
			// Anti-self-approval: the requester can never approve their own
			// ticket, even if their key has canApprove.
			if (rec && rec.req.agentId === auth.agentId) {
				return json(
					{ error: "forbidden: cannot approve your own elevation" },
					403,
				);
			}
			// One approval per agent: no double-counting.
			if ((ticket.approvals ?? []).some((a) => a.agentId === auth.agentId)) {
				return json(
					{ error: "already approved by this agent" },
					409,
				);
			}
			const { ticket: updated, added } = await audit.addElevationApproval(
				ticket.id,
				{
					agentId: auth.agentId,
					ts: Date.now(),
				},
			);
			if (!added) {
				// Lost a race: re-read for an accurate error.
				const fresh = await audit.getElevation(ticket.id);
				if (fresh?.status !== "pending") {
					return json({ error: `already ${fresh?.status}` }, 409);
				}
				return json({ error: "already approved by this agent" }, 409);
			}
			const approvals = updated?.approvals ?? [];
			const required = ticket.requiredApprovals ?? 1;
			if (approvals.length < required) {
				return json(
					{
						approved: false,
						status: "pending",
						approvals: approvals.length,
						requiredApprovals: required,
					},
					202,
				);
			}
			// Quorum met. Only one concurrent winner mints: the status
			// transition is conditional on still being pending.
			const won = await audit.setElevationStatus(
				ticket.id,
				"approved",
				Date.now(),
			);
			if (!won) {
				return json({ error: "already approved" }, 409);
			}
			const minted = await mintToken(
				env.ARTIFACTS,
				ticket.repo,
				ticket.tokenScope,
				ticket.ttlSeconds,
			);
			if (rec) {
				const approvalDecision: Decision = {
					allowed: true,
					reason: `elevation ${ticket.id} approved by ${approvals.length} approver(s)`,
					ruleId: rec.decision.ruleId,
					tokenScope: ticket.tokenScope,
					ttlSeconds: ticket.ttlSeconds,
				};
				approvalDecision.severity = severityFor(rec.req, approvalDecision);
				approvalDecision.policyHash = await getPolicyHash(env);
				await audit.append({
					req: rec.req,
					decision: approvalDecision,
					enforcement: policy.mode ?? "enforce",
				});
			}
			return json({
				approved: true,
				token: minted.plaintext,
				expiresAt: minted.expiresAt,
				scope: ticket.tokenScope,
				ttlSeconds: ticket.ttlSeconds,
				approvals: approvals.length,
			});
		}

		// POST /v1/elevate/:id/reject — human rejects (approver key required).
		m = path.match(/^\/v1\/elevate\/([^/]+)\/reject$/);
		if (req.method === "POST" && m) {
			const auth = requireKey(req, env, { approve: true });
			if (auth instanceof Response) return auth;
			const ticket = await audit.getElevation(m[1]);
			if (!ticket) return json({ error: "elevation not found" }, 404);
			if (ticket.status !== "pending") {
				return json({ error: `already ${ticket.status}` }, 409);
			}
			await audit.setElevationStatus(ticket.id, "rejected", Date.now());
			return json({ rejected: true });
		}

		// GET /v1/elevations — list tickets.
		if (req.method === "GET" && path === "/v1/elevations") {			const status = url.searchParams.get("status") as
				| "pending"
				| "approved"
				| "rejected"
				| null;
			return json({
				elevations: await audit.listElevations(status ?? undefined),
			});
		}

		// POST /v1/admin/notify-test — admin-only. Sends a test payload to
		// NOTIFY_WEBHOOK_URL (mirrors InnerWarden's `notify test`).
		if (req.method === "POST" && path === "/v1/admin/notify-test") {
			const auth = requireKey(req, env, { admin: true });
			if (auth instanceof Response) return auth;
			if (!env.NOTIFY_WEBHOOK_URL) {
				return json(
					{ ok: false, error: "NOTIFY_WEBHOOK_URL is not set" },
					501,
				);
			}
			try {
				await postWebhook(env, { event: "notify.test", ts: Date.now() });
				return json({ ok: true });
			} catch (err) {
				return json(
					{
						ok: false,
						error: err instanceof Error ? err.message : String(err),
					},
					502,
				);
			}
		}

		// POST /v1/revoke — kill switch (any valid key; revoking is defensive).
		if (req.method === "POST" && path === "/v1/revoke") {
			const auth = requireKey(req, env);
			if (auth instanceof Response) return auth;
			const { repo, tokenOrId } = await readJson<{
				repo: string;
				tokenOrId: string;
			}>(req);
			const ok = await revokeToken(env.ARTIFACTS, repo, tokenOrId);
			return json({ revoked: ok });
		}

		// GET /v1/verify — tamper-evidence check over the decision hash chain.
		if (req.method === "GET" && path === "/v1/verify") {
			const records = await audit.recent(10000);
			const { ok, badIndex } = await verifyChain([...records].reverse());
			return json({ ok, badIndex, checked: records.length });
		}

		// GET /v1/decisions — audit trail.
		if (req.method === "GET" && path === "/v1/decisions") {
			const limit = Math.min(
				Number(url.searchParams.get("limit") ?? 50),
				200,
			);
			const [records, stats] = await Promise.all([
				audit.recent(limit),
				audit.stats(),
			]);
			return json({ stats, decisions: records });
		}

		// GET /v1/events — observed repo activity (push/token/clone events
		// reconciled against decisions).
		if (req.method === "GET" && path === "/v1/events") {
			const limit = Math.min(Number(url.searchParams.get("limit") ?? 50), 200);
			const events = await audit.recentRepoEvents(limit);
			const unexplained = events.filter((e) => e.verdict === "unexplained").length;
			return json({ unexplained, events });
		}

		// GET / — audit UI.
		if (req.method === "GET" && (path === "/" || path === "/index.html")) {
			return new Response(auditPage(), {
				headers: { "content-type": "text/html; charset=utf-8" },
			});
		}

		return json({ error: "not found" }, 404);
}
