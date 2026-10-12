// Content-aware verification: tree diffs, fork points.
// Part of the lifecycle suite. Run via: npm run lifecycle [-- --suite=content]

import type { Suite, TestContext } from "../harness.js";
import { MemoryAuditLog } from "../../../src/audit.js";
import { handleArtifactsEvent, pushChangedPaths } from "../../../src/watch.js";

export const suite: Suite = async (ctx: TestContext) => {
// content violation: branch matches but pushed files exceed the
// decision's declared paths → unexplained + containment
const memAudit5 = new MemoryAuditLog();
await memAudit5.append({
	req: {
		agentId: "agent-docs-1",
		roles: ["docs-writer"],
		taskId: "seed-cv",
		action: "push",
		repo: "containment-repo",
		branch: "docs/cv",
		paths: ["docs/**"],
	},
	decision: { allowed: true, reason: "seed" },
	enforcement: "enforce",
});
let cvHookCalls = 0;
const cvEvent = (after: string) => ({
	type: "cf.artifacts.repo.pushed",
	source: { type: "artifacts.repo", namespace: "test", repoName: "containment-repo" },
	payload: { ref: "refs/heads/docs/cv", before: "aaa", after, commits: [] },
});
const cvHooks = {
	verifyPushContent: async () => ({ changed: ["src/auth/evil.ts", "docs/guide.md"] }),
	onUnexplainedPush: async (_r: string, _b: string) => {
		cvHookCalls++;
		return { revoked: 1, total: 1 };
	},
};
const t33evt = await handleArtifactsEvent(memAudit5, cvEvent("bbb"), Date.now(), cvHooks);
const t33d = JSON.parse(t33evt.detail);
ctx.check(
	"content violation → unexplained + containment, violation recorded",
	t33evt.verdict === "unexplained" &&
		cvHookCalls === 1 &&
		t33d.contentVerified !== true &&
		t33d.contentViolation?.changed?.includes("src/auth/evil.ts") &&
		JSON.stringify(t33d.contentViolation?.allowedPaths)?.includes("docs/**"),
	{ verdict: t33evt.verdict, detail: t33d },
);

// content within declared paths → explained, no containment
const memAudit6 = new MemoryAuditLog();
await memAudit6.append({
	req: {
		agentId: "agent-docs-1",
		roles: ["docs-writer"],
		taskId: "seed-ok",
		action: "push",
		repo: "containment-repo",
		branch: "docs/ok",
		paths: ["docs/**"],
	},
	decision: { allowed: true, reason: "seed" },
	enforcement: "enforce",
});
let okHookCalls = 0;
const t34evt = await handleArtifactsEvent(
	memAudit6,
	{
		type: "cf.artifacts.repo.pushed",
		source: { type: "artifacts.repo", namespace: "test", repoName: "containment-repo" },
		payload: { ref: "refs/heads/docs/ok", before: "aaa", after: "ccc", commits: [] },
	},
	Date.now(),
	{
		verifyPushContent: async () => ({ changed: ["docs/guide.md"] }),
		onUnexplainedPush: async () => {
			okHookCalls++;
			return { revoked: 0, total: 0 };
		},
	},
);
const t34d = JSON.parse(t34evt.detail);
ctx.check(
	"content within paths → explained, contentVerified, no containment",
	t34evt.verdict === "explained" &&
		okHookCalls === 0 &&
		t34d.contentVerified === true,
	{ verdict: t34evt.verdict, detail: t34d },
);

// content indeterminable (null) → branch-only fallback, honest flag
const memAudit7 = new MemoryAuditLog();
await memAudit7.append({
	req: {
		agentId: "agent-docs-1",
		roles: ["docs-writer"],
		taskId: "seed-unk",
		action: "push",
		repo: "containment-repo",
		branch: "docs/unk",
		paths: ["docs/**"],
	},
	decision: { allowed: true, reason: "seed" },
	enforcement: "enforce",
});
const t35evt = await handleArtifactsEvent(
	memAudit7,
	{
		type: "cf.artifacts.repo.pushed",
		source: { type: "artifacts.repo", namespace: "test", repoName: "containment-repo" },
		payload: { ref: "refs/heads/docs/unk", before: "aaa", after: "ddd", commits: [] },
	},
	Date.now(),
	{ verifyPushContent: async () => ({ changed: null }) },
);
const t35d = JSON.parse(t35evt.detail);
ctx.check(
	"content unknown → explained with contentVerified:false (no false positive)",
	t35evt.verdict === "explained" && t35d.contentVerified === false,
	{ verdict: t35evt.verdict, detail: t35d },
);

// pushChangedPaths diffs trees (added + modified + deleted)
const stubReader = {
	commits: new Map([
		["c1", { treeHash: "t1" }],
		["c2", { treeHash: "t2" }],
		["c0", { treeHash: "t0" }],
	]),
	trees: new Map<string, Array<{ name: string; type: string; hash: string }>>([
		[
			"t1",
			[
				{ name: "a.md", type: "blob", hash: "h1" },
				{ name: "gone.md", type: "blob", hash: "h9" },
				{ name: "sub", type: "tree", hash: "st1" },
			],
		],
		[
			"t2",
			[
				{ name: "a.md", type: "blob", hash: "h2" },
				{ name: "b.md", type: "blob", hash: "h3" },
				{ name: "sub", type: "tree", hash: "st1" },
			],
		],
		["t0", [{ name: "a.md", type: "blob", hash: "h1" }]],
		["st1", [{ name: "deep.md", type: "blob", hash: "h4" }]],
	]),
	async readCommit(h: string) {
		return stubReader.commits.get(h) ?? null;
	},
	async readTree(h: string) {
		return stubReader.trees.get(h) ?? null;
	},
	async getDefaultBranch() {
		return "main";
	},
	async getBranchTip(_b: string) {
		return "c0";
	},
};
const t36changed = await pushChangedPaths(stubReader, {
	repo: "r",
	branch: "docs/x",
	before: "c1",
	after: "c2",
	commits: [],
});
ctx.check(
	"pushChangedPaths: modified + added + deleted, recursive",
	t36changed !== null &&
		t36changed.includes("a.md") &&
		t36changed.includes("b.md") &&
		t36changed.includes("gone.md") &&
		!t36changed.includes("sub/deep.md") &&
		t36changed.length === 3,
	t36changed,
);
// zero before-sha (new branch): fork point found via default tip in chain
const t37changed = await pushChangedPaths(stubReader, {
	repo: "r",
	branch: "docs/new",
	before: "0000000",
	after: "c2",
	commits: [
		{ id: "c2", parents: ["c1"] },
		{ id: "c1", parents: ["c0"] },
		{ id: "c0", parents: [] },
	],
});
ctx.check(
	"pushChangedPaths: zero before → fork point from chain",
	t37changed !== null &&
		t37changed.includes("a.md") &&
		t37changed.includes("b.md") &&
		t37changed.includes("sub/deep.md") &&
		t37changed.length === 3,
	t37changed,
);
// zero before, default tip not in chain → null (unknown, not empty)
const t38changed = await pushChangedPaths(stubReader, {
	repo: "r",
	branch: "docs/new",
	before: "0000000",
	after: "c2",
	commits: [
		{ id: "c2", parents: ["cx"] },
		{ id: "cx", parents: [] },
	],
});
ctx.check(
	"pushChangedPaths: fork point absent → null (unknown)",
	t38changed === null,
	t38changed,
);

};
