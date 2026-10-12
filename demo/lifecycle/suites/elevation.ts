// Elevation tickets: quorum approvals, anti-self-approval, reject.
// Part of the lifecycle suite. Run via: npm run lifecycle [-- --suite=elevation]

import type { Suite, TestContext } from "../harness.js";

export const suite: Suite = async (ctx: TestContext) => {
// requireApproval → 202 with decisionId
const t3 = await ctx.call(
	"POST",
	"/v1/token",
	{
		taskId: "t3",
		action: "push",
		repo: "api",
		branch: "main",
		paths: ["src/api/paginate.ts"],
	},
	"test-key-rel",
);
const decisionId = t3.data.decisionId as string;
ctx.check(
	"requireApproval → 202 + decisionId",
	t3.status === 202 && typeof decisionId === "string",
	t3.data,
);

// hard deny is NOT eligible for elevation → 422
const t4deny = await ctx.call("POST", "/v1/token", {
	taskId: "t4deny",
	action: "push",
	repo: "website",
	branch: "main",
	paths: ["src/evil.ts"],
});
const t4 = await ctx.call("POST", "/v1/elevate", {
	decisionId: t4deny.data.decisionId,
	justification: "please?",
});
ctx.check("elevate hard-deny → 422", t4.status === 422, t4.data);

// elevate the requireApproval decision → 202 + ticket
const t5 = await ctx.call(
	"POST",
	"/v1/elevate",
	{
		decisionId,
		justification: "hotfix needs to ship before freeze",
	},
	"test-key-rel",
);
const elevationId = t5.data.elevationId as string;
ctx.check(
	"elevate → 202 + ticket",
	t5.status === 202 && typeof elevationId === "string",
	t5.data,
);

// pending list contains it
const t6 = await ctx.call("GET", "/v1/elevations?status=pending");
ctx.check(
	"pending list contains ticket",
	(t6.data.elevations as unknown[]).length === 1,
	t6.data,
);

// approve → token with capped TTL (approver key required;
// must differ from the requester — anti-self-approval)
const t7 = await ctx.call(
	"POST",
	`/v1/elevate/${elevationId}/approve`,
	{},
	"test-key-admin",
);
ctx.check(
	"approve → 200 + token, ttl ≤ 300",
	t7.status === 200 &&
		typeof t7.data.token === "string" &&
		(t7.data.ttlSeconds as number) <= 300,
	t7.data,
);

// double approve → 409
const t8 = await ctx.call(
	"POST",
	`/v1/elevate/${elevationId}/approve`,
	{},
	"test-key-admin",
);
ctx.check("double approve → 409", t8.status === 409, t8.data);

// kill switch
const t9 = await ctx.call("POST", "/v1/revoke", {
	repo: "website",
	tokenOrId: ctx.minted[0].plaintext,
});
ctx.check(
	"revoke → true, recorded",
	t9.status === 200 && t9.data.revoked === true && ctx.revoked.length === 1,
	t9.data,
);


// non-approver key cannot approve: fresh ticket, docs key → 403
const t19d = await ctx.call(
	"POST",
	"/v1/token",
	{
		taskId: "t19",
		action: "push",
		repo: "api",
		branch: "main",
		paths: ["src/api/other.ts"],
	},
	"test-key-rel",
);
const t19e = await ctx.call(
	"POST",
	"/v1/elevate",
	{ decisionId: t19d.data.decisionId, justification: "x" },
	"test-key-rel",
);
const t19a = await ctx.call(
	"POST",
	`/v1/elevate/${t19e.data.elevationId}/approve`,
	{},
	"test-key-docs",
);
ctx.check("non-approver approve → 403", t19a.status === 403, t19a.data);
// approver key cannot approve their OWN ticket (anti-self-approval)
const t19b = await ctx.call(
	"POST",
	`/v1/elevate/${t19e.data.elevationId}/approve`,
	{},
	"test-key-rel",
);
ctx.check(
	"self-approve → 403",
	t19b.status === 403 && String(t19b.data.error).includes("own elevation"),
	t19b.data,
);
// a different approver can approve → 200
const t19c = await ctx.call(
	"POST",
	`/v1/elevate/${t19e.data.elevationId}/approve`,
	{},
	"test-key-admin",
);
ctx.check("other approver → 200", t19c.status === 200, t19c.data);


// notify-test without NOTIFY_WEBHOOK_URL → 501, not a crash
const t26 = await ctx.call("POST", "/v1/admin/notify-test", {}, "test-key-admin");
ctx.check(
	"notify-test w/o webhook URL → 501",
	t26.status === 501 && t26.data.ok === false,
	t26.data,
);

// elevation works with no webhook configured (fail-open): ticket created
const t27d = await ctx.call(
	"POST",
	"/v1/token",
	{
		taskId: "t27",
		action: "push",
		repo: "api",
		branch: "main",
		paths: ["src/api/x.ts"],
	},
	"test-key-rel",
);
const t27e = await ctx.call(
	"POST",
	"/v1/elevate",
	{ decisionId: t27d.data.decisionId, justification: "no webhook configured" },
	"test-key-rel",
);
ctx.check(
	"elevate w/o webhook → 202 ticket (fail-open)",
	t27e.status === 202 && typeof t27e.data.elevationId === "string",
	t27e.data,
);


// quorum=2: first approval → 202 pending, no token yet
const t44d = await ctx.callQ2(
	"POST",
	"/v1/token",
	{
		taskId: "t44",
		action: "push",
		repo: "api",
		branch: "main",
		paths: ["src/api/other.ts"],
	},
	"test-key-rel",
);
const t44e = await ctx.callQ2(
	"POST",
	"/v1/elevate",
	{ decisionId: t44d.data.decisionId, justification: "quorum test" },
	"test-key-rel",
);
const t44a1 = await ctx.callQ2(
	"POST",
	`/v1/elevate/${t44e.data.elevationId}/approve`,
	{},
	"test-key-admin",
);
ctx.check(
	"quorum=2: 1st approval → 202 pending",
	t44a1.status === 202 &&
		t44a1.data.approved === false &&
		t44a1.data.approvals === 1 &&
		t44a1.data.requiredApprovals === 2 &&
		!t44a1.data.token,
	t44a1.data,
);

// quorum=2: same approver twice → 409, no double count
const t45dup = await ctx.callQ2(
	"POST",
	`/v1/elevate/${t44e.data.elevationId}/approve`,
	{},
	"test-key-admin",
);
ctx.check(
	"quorum=2: duplicate approval → 409",
	t45dup.status === 409,
	t45dup.data,
);

// quorum=2: second DISTINCT approver → 200 + token
const t46a2 = await ctx.callQ2(
	"POST",
	`/v1/elevate/${t44e.data.elevationId}/approve`,
	{},
	"test-key-lead2",
);
ctx.check(
	"quorum=2: 2nd distinct approval → 200 + token",
	t46a2.status === 200 &&
		t46a2.data.approved === true &&
		typeof t46a2.data.token === "string" &&
		t46a2.data.approvals === 2,
	t46a2.data,
);

// quorum=2: requester cannot be one of the approvers
const t47d = await ctx.callQ2(
	"POST",
	"/v1/token",
	{
		taskId: "t47",
		action: "push",
		repo: "api",
		branch: "main",
		paths: ["src/api/other.ts"],
	},
	"test-key-lead2",
);
const t47e = await ctx.callQ2(
	"POST",
	"/v1/elevate",
	{ decisionId: t47d.data.decisionId, justification: "self quorum test" },
	"test-key-lead2",
);
const t47self = await ctx.callQ2(
	"POST",
	`/v1/elevate/${t47e.data.elevationId}/approve`,
	{},
	"test-key-lead2",
);
ctx.check(
	"quorum=2: requester self-approve → 403",
	t47self.status === 403,
	t47self.data,
);


// reject flow: reject → 200, then approve → 409 (already rejected)
const t48d = await ctx.call(
	"POST",
	"/v1/token",
	{
		taskId: "t48",
		action: "push",
		repo: "api",
		branch: "main",
		paths: ["src/api/other.ts"],
	},
	"test-key-rel",
);
const t48e = await ctx.call(
	"POST",
	"/v1/elevate",
	{ decisionId: t48d.data.decisionId, justification: "reject test" },
	"test-key-rel",
);
const t48r = await ctx.call(
	"POST",
	`/v1/elevate/${t48e.data.elevationId}/reject`,
	{},
	"test-key-admin",
);
ctx.check("reject → 200", t48r.status === 200 && t48r.data.rejected === true, t48r.data);
const t48a = await ctx.call(
	"POST",
	`/v1/elevate/${t48e.data.elevationId}/approve`,
	{},
	"test-key-admin",
);
ctx.check("approve after reject → 409", t48a.status === 409, t48a.data);


// concurrent duplicate approvals: same agent twice at once →
// only one counts, quorum NOT bypassed
const t50d = await ctx.callQ2(
	"POST",
	"/v1/token",
	{
		taskId: "t50",
		action: "push",
		repo: "api",
		branch: "main",
		paths: ["src/api/other.ts"],
	},
	"test-key-rel",
);
const t50e = await ctx.callQ2(
	"POST",
	"/v1/elevate",
	{ decisionId: t50d.data.decisionId, justification: "race test" },
	"test-key-rel",
);
const t50id = t50e.data.elevationId as string;
const mintsBefore50 = ctx.minted.length;
const [t50r1, t50r2] = await Promise.all([
	ctx.callQ2("POST", `/v1/elevate/${t50id}/approve`, {}, "test-key-admin"),
	ctx.callQ2("POST", `/v1/elevate/${t50id}/approve`, {}, "test-key-admin"),
]);
const t50codes = [t50r1.status, t50r2.status].sort();
const t50list = await ctx.callQ2("GET", "/v1/elevations?status=pending");
const t50ticket = (
	t50list.data.elevations as Array<{ id: string; approvals: unknown[] }>
).find((t) => t.id === t50id);
ctx.check(
	"concurrent duplicate approve → one 202, one 409, single approval counted",
	t50codes[0] === 202 &&
		t50codes[1] === 409 &&
		t50ticket?.approvals.length === 1 &&
		ctx.minted.length === mintsBefore50,
	{ codes: t50codes, approvals: t50ticket?.approvals.length },
);

// concurrent distinct approvals, quorum=2 → exactly one mints
const t51d = await ctx.callQ2(
	"POST",
	"/v1/token",
	{
		taskId: "t51",
		action: "push",
		repo: "api",
		branch: "main",
		paths: ["src/api/other.ts"],
	},
	"test-key-rel",
);
const t51e = await ctx.callQ2(
	"POST",
	"/v1/elevate",
	{ decisionId: t51d.data.decisionId, justification: "double mint race" },
	"test-key-rel",
);
const t51id = t51e.data.elevationId as string;
const mintsBefore51 = ctx.minted.length;
const [t51r1, t51r2] = await Promise.all([
	ctx.callQ2("POST", `/v1/elevate/${t51id}/approve`, {}, "test-key-admin"),
	ctx.callQ2("POST", `/v1/elevate/${t51id}/approve`, {}, "test-key-lead2"),
]);
const t51tokens = [t51r1, t51r2].filter(
	(r) => r.status === 200 && typeof r.data.token === "string",
);
ctx.check(
	"concurrent distinct approves → exactly one token ctx.minted",
	t51tokens.length === 1 && ctx.minted.length === mintsBefore51 + 1,
	{ statuses: [t51r1.status, t51r2.status], mints: ctx.minted.length - mintsBefore51 },
);

// quorum + reject: one approval (202), then reject kills the ticket
const t52d = await ctx.callQ2(
	"POST",
	"/v1/token",
	{
		taskId: "t52",
		action: "push",
		repo: "api",
		branch: "main",
		paths: ["src/api/other.ts"],
	},
	"test-key-rel",
);
const t52e = await ctx.callQ2(
	"POST",
	"/v1/elevate",
	{ decisionId: t52d.data.decisionId, justification: "quorum reject" },
	"test-key-rel",
);
const t52id = t52e.data.elevationId as string;
await ctx.callQ2("POST", `/v1/elevate/${t52id}/approve`, {}, "test-key-admin");
const t52r = await ctx.callQ2(
	"POST",
	`/v1/elevate/${t52id}/reject`,
	{},
	"test-key-lead2",
);
ctx.check("quorum ticket reject → 200", t52r.status === 200, t52r.data);
const t52a = await ctx.callQ2(
	"POST",
	`/v1/elevate/${t52id}/approve`,
	{},
	"test-key-lead2",
);
ctx.check("approve after quorum reject → 409", t52a.status === 409, t52a.data);

};
