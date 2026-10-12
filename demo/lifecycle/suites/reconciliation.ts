// Post-hoc reconciliation: containment, piggyback, cooldown.
// Part of the lifecycle suite. Run via: npm run lifecycle [-- --suite=reconciliation]

import type { Suite, TestContext } from "../harness.js";
import { MemoryAuditLog } from "../../../src/audit.js";
import { handleArtifactsEvent } from "../../../src/watch.js";
import { revokeAllWriteTokens } from "../../../src/broker.js";
import { shouldContain } from "../../../src/context.js";

export const suite: Suite = async (ctx: TestContext) => {
// containment: unexplained push disarms outstanding write tokens
const memAudit = new MemoryAuditLog();
const containHandle = await ctx.binding.get("containment-repo");
await containHandle.createToken("write", 900);
await containHandle.createToken("write", 900);
await containHandle.createToken("read", 900);
const revokedBefore = ctx.revoked.length;
const t29evt = await handleArtifactsEvent(
	memAudit,
	{
		type: "cf.artifacts.repo.pushed",
		source: { type: "artifacts.repo", namespace: "test", repoName: "containment-repo" },
		payload: { ref: "refs/heads/main", after: "abc123", commits: [] },
	},
	Date.now(),
	{ onUnexplainedPush: (repo) => revokeAllWriteTokens(ctx.binding, repo) },
);
const t29detail = JSON.parse(t29evt.detail);
ctx.check(
	"unexplained push → containment revokes 2 write tokens, read survives",
	t29evt.verdict === "unexplained" &&
		t29detail.containment?.ok === true &&
		t29detail.containment.revoked === 2 &&
		t29detail.containment.total === 3 &&
		ctx.revoked.length === revokedBefore + 2,
	{ verdict: t29evt.verdict, containment: t29detail.containment },
);

// explained push → containment hook NOT called
let hookCalls = 0;
const memAudit2 = new MemoryAuditLog();
await memAudit2.append({
	req: {
		agentId: "agent-docs-1",
		roles: ["docs-writer"],
		taskId: "seed-explained",
		action: "push",
		repo: "containment-repo",
		branch: "docs/guide",
		paths: ["docs/guide.md"],
	},
	decision: { allowed: true, reason: "seed" },
	enforcement: "enforce",
});
const t30evt = await handleArtifactsEvent(
	memAudit2,
	{
		type: "cf.artifacts.repo.pushed",
		source: { type: "artifacts.repo", namespace: "test", repoName: "containment-repo" },
		payload: { ref: "refs/heads/docs/guide", after: "def456", commits: [] },
	},
	Date.now(),
	{
		onUnexplainedPush: async () => {
			hookCalls++;
			return { revoked: 0, total: 0 };
		},
	},
);
ctx.check(
	"explained push → no containment, verdict explained",
	t30evt.verdict === "explained" && hookCalls === 0,
	{ verdict: t30evt.verdict, hookCalls },
);

// containment hook throwing → event still logged, failure recorded
const memAudit3 = new MemoryAuditLog();
const t31evt = await handleArtifactsEvent(
	memAudit3,
	{
		type: "cf.artifacts.repo.pushed",
		source: { type: "artifacts.repo", namespace: "test", repoName: "containment-repo" },
		payload: { ref: "refs/heads/evil", after: "666", commits: [] },
	},
	Date.now(),
	{
		onUnexplainedPush: async () => {
			throw new Error("binding exploded");
		},
	},
);
const t31detail = JSON.parse(t31evt.detail);
ctx.check(
	"hook throws → event logged unexplained, containment failure recorded",
	t31evt.verdict === "unexplained" &&
		t31detail.containment?.ok === false &&
		typeof t31detail.containment.error === "string",
	t31detail.containment,
);

// piggyback: a second push to the same branch cannot reuse the decision
const memAudit4 = new MemoryAuditLog();
await memAudit4.append({
	req: {
		agentId: "agent-docs-1",
		roles: ["docs-writer"],
		taskId: "seed-piggyback",
		action: "push",
		repo: "containment-repo",
		branch: "docs/pb",
		paths: ["docs/pb.md"],
	},
	decision: { allowed: true, reason: "seed" },
	enforcement: "enforce",
});
const pbHook = {
	calls: 0,
	async onUnexplainedPush(_repo: string, _branch: string) {
		pbHook.calls++;
		return { revoked: 0, total: 0 };
	},
};
const pbEvent = (after: string) => ({
	type: "cf.artifacts.repo.pushed",
	source: { type: "artifacts.repo", namespace: "test", repoName: "containment-repo" },
	payload: { ref: "refs/heads/docs/pb", after, commits: [] },
});
const t32a = await handleArtifactsEvent(memAudit4, pbEvent("aaa"), Date.now(), pbHook);
const t32b = await handleArtifactsEvent(memAudit4, pbEvent("bbb"), Date.now(), pbHook);
ctx.check(
	"piggyback blocked: 1st push explained, 2nd unexplained + containment",
	t32a.verdict === "explained" &&
		t32b.verdict === "unexplained" &&
		pbHook.calls === 1,
	{ first: t32a.verdict, second: t32b.verdict, hookCalls: pbHook.calls },
);


// containment cooldown: first fires, second within window skips,
// after window fires again
const cdRepo = `cd-test-${Date.now()}`;
const cdT0 = Date.now();
ctx.check("cooldown: first → fire", shouldContain(cdRepo, cdT0) === true, null);
ctx.check(
	"cooldown: second within 5min → skip",
	shouldContain(cdRepo, cdT0 + 60_000) === false,
	null,
);
ctx.check(
	"cooldown: after 5min → fire again",
	shouldContain(cdRepo, cdT0 + 5 * 60_000 + 1) === true,
	null,
);
ctx.check(
	"cooldown: per-repo isolation",
	shouldContain(cdRepo + "-other", cdT0 + 60_000) === true,
	null,
);

};
