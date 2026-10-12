// Cerberus Worker — entrypoint wiring only.
// Route handlers live in routes.ts, shared context in context.ts,
// the audit UI in ui.ts, pure helpers in util.ts.

import { revokeAllWriteTokens } from "./broker.js";
import { getAudit, shouldContain } from "./context.js";
import { handleFetch } from "./routes.js";
import type { Env } from "./types.js";
import { json } from "./util.js";
import {
	handleArtifactsEvent,
	pushChangedPaths,
	type ArtifactsQueueEvent,
} from "./watch.js";

export default {
	/**
	 * Fail-closed wrapper: ANY internal failure (policy unloadable, D1 down,
	 * binding error) denies the request instead of crashing open.
	 * A gatekeeper must never fail open — the opposite of InnerWarden's
	 * skill-execution discipline (fail-open there, because a crashed security
	 * agent is worse than a missed response).
	 */
	async fetch(
		req: Request,
		env: Env,
		ctx?: ExecutionContext,
	): Promise<Response> {
		try {
			return await handleFetch(req, env, ctx);
		} catch (err) {
			// Logged server-side only; never leak internals to the client.
			console.error("cerberus fail-closed:", err);
			return json(
				{
					allowed: false,
					reason: "internal error — fail-closed, no token minted",
				},
				503,
			);
		}
	},

	/**
	 * Queue consumer for the Artifacts event subscription
	 * (pushed / cloned / fetched / token.created / token.revoked).
	 * Post-hoc reconciliation: every observed event is cross-checked
	 * against the decision log.
	 */
	async queue(batch: MessageBatch, env: Env): Promise<void> {
		const audit = getAudit(env);
		for (const msg of batch.messages) {
			try {
				await handleArtifactsEvent(
					audit,
					msg.body as ArtifactsQueueEvent,
					Date.now(),
					{
						// Containment: an unexplained push bypassed the gate.
						// Disarm outstanding write tokens to bound the breach
						// to the detection window. Best-effort by design:
						// handleArtifactsEvent records failures in the event
						// detail instead of throwing (which would redeliver
						// the message and duplicate audit records).
						onUnexplainedPush: async (repo) => {
							if (!shouldContain(repo)) {
								return { revoked: 0, total: 0, skipped: "cooldown" };
							}
							return revokeAllWriteTokens(env.ARTIFACTS, repo);
						},
						// Content verification: a push is explained only if
						// its changed files fall within the decision's
						// declared paths. Closes the hole where an agent
						// mints for docs/** but pushes src/auth/** to the
						// same branch.
						verifyPushContent: async (push) => {
							using repo = await env.ARTIFACTS.get(push.repo);
							let contentError: string | undefined;
							const changed = await pushChangedPaths(
								{
									readCommit: (h: string) => repo.readCommit(h),
									readTree: (h: string) => repo.readTree(h),
									getDefaultBranch: () =>
										repo.info().then((i) => i.defaultBranch),
									getBranchTip: (branch: string) =>
										repo
											.log({ ref: branch, limit: 1 })
											.then((cs) => cs[0]?.hash ?? null),
								},
								push,
								(stage, err) => {
									contentError = `${stage}: ${err instanceof Error ? err.message : String(err)}`;
								},
							);
							return { changed, error: contentError };
						},
					},
				);
				msg.ack();
			} catch (err) {
				console.error("cerberus event handling failed:", err);
				msg.retry();
			}
		}
	},
} satisfies ExportedHandler<Env>;

// Re-export for the demo harness.
export { evaluate } from "./policy.js";
export type { Decision } from "./types.js";
