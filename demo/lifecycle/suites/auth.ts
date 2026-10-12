// Agent authentication: keys, expiry, role binding.
// Part of the lifecycle suite. Run via: npm run lifecycle [-- --suite=auth]

import type { Suite, TestContext } from "../harness.js";

export const suite: Suite = async (ctx: TestContext) => {
// no key → 401
const t16 = await ctx.call(
	"POST",
	"/v1/token",
	{ taskId: "t16", action: "read", repo: "website" },
	null,
);
ctx.check("no key → 401", t16.status === 401, t16.data);

// bad key → 401
const t17 = await ctx.call(
	"POST",
	"/v1/token",
	{ taskId: "t17", action: "read", repo: "website" },
	"wrong-key",
);
ctx.check("bad key → 401", t17.status === 401, t17.data);


// expired key → 401 with expiry message
const t39 = await ctx.call(
	"POST",
	"/v1/token",
	{ taskId: "t39", action: "read", repo: "website", paths: ["README.md"] },
	"test-key-expired",
);
ctx.check(
	"expired key → 401 key expired",
	t39.status === 401 && String(t39.data.error).includes("expired"),
	t39.data,
);

// unparseable expiresAt → 503 fail-closed (misconfiguration)
const t40 = await ctx.call(
	"POST",
	"/v1/token",
	{ taskId: "t40", action: "read", repo: "website", paths: ["README.md"] },
	"test-key-badexp",
);
ctx.check("bad expiresAt → 503 fail-closed", t40.status === 503, t40.data);

// future expiry → works normally
const t41 = await ctx.call(
	"POST",
	"/v1/token",
	{ taskId: "t41", action: "read", repo: "website", paths: ["README.md"] },
	"test-key-future",
);
ctx.check("future expiresAt → 200", t41.status === 200, t41.data);


// role spoofing is ignored: body claims release-manager, but the
// docs key's identity is used → evaluated as docs-writer → 403 on main.
const t18 = await ctx.call("POST", "/v1/token", {
	agentId: "mallory",
	roles: ["release-manager"],
	taskId: "t18",
	action: "push",
	repo: "website",
	branch: "main",
	paths: ["docs/x.md"],
});
const t18rec = (
	(await ctx.call("GET", "/v1/decisions?limit=1")).data.decisions as unknown[]
)[0] as import("../../../src/audit.js").AuditRecord;
ctx.check(
	"spoofed roles ignored → 403, audit shows key identity",
	t18.status === 403 && t18rec.req.agentId === "agent-docs-1",
	{ status: t18.status, agentId: t18rec.req.agentId },
);

};
