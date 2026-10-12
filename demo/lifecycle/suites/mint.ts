// Token minting: allow/deny, fail-closed, observe mode.
// Part of the lifecycle suite. Run via: npm run lifecycle [-- --suite=mint]

import { POLICY_JSON, type Suite, type TestContext } from "../harness.js";
import handler from "../../../src/index.js";
import type { Env } from "../../../src/types.js";

export const suite: Suite = async (ctx: TestContext) => {
// allowed request mints a token through the broker
const t1 = await ctx.call("POST", "/v1/token", {
	agentId: "agent-docs-1",
	roles: ["docs-writer"],
	taskId: "t1",
	action: "push",
	repo: "website",
	branch: "docs/faq",
	paths: ["docs/faq.md"],
});
ctx.check("allow → 200 + token", t1.status === 200 && typeof t1.data.token === "string", t1.data);
ctx.check(
	"broker ctx.minted write/900 via binding",
	ctx.minted.length === 1 && ctx.minted[0].scope === "write" && ctx.minted[0].ttl === 900,
	ctx.minted,
);

// denied request → 403, no mint
const t2 = await ctx.call("POST", "/v1/token", {
	agentId: "agent-docs-1",
	roles: ["docs-writer"],
	taskId: "t2",
	action: "push",
	repo: "website",
	branch: "main",
	paths: ["docs/faq.md"],
});
ctx.check("deny → 403, no new mint", t2.status === 403 && ctx.minted.length === 1, t2.data);


// fail-closed: broken policy → 503, allowed:false, no mint
const brokenEnv = { ...ctx.env, POLICY_JSON: "not-json{{{" } as unknown as Env;
const mintsBefore = ctx.minted.length;
const t14 = await handler.fetch(
	new Request("http://localhost/v1/token", {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify({
			agentId: "x",
			roles: [],
			taskId: "t",
			action: "read",
			repo: "r",
		}),
	}),
	brokenEnv,
);
const t14data = (await t14.json()) as Record<string, unknown>;
ctx.check(
	"broken policy → 503 fail-closed, no mint",
	t14.status === 503 && t14data.allowed === false && ctx.minted.length === mintsBefore,
	{ status: t14.status, data: t14data },
);

// observe mode: deny still blocks mint, but is labeled would-deny
const observePolicy = JSON.stringify({
	...JSON.parse(POLICY_JSON),
	mode: "observe",
});
const observeEnv = { ...ctx.env, POLICY_JSON: observePolicy } as unknown as Env;
const t15res = await handler.fetch(
	new Request("http://localhost/v1/token", {
		method: "POST",
		headers: {
			"content-type": "application/json",
			authorization: "Bearer test-key-docs",
		},
		body: JSON.stringify({
			agentId: "agent-docs-1",
			roles: ["docs-writer"],
			taskId: "t-obs",
			action: "push",
			repo: "website",
			branch: "main",
			paths: ["docs/faq.md"],
		}),
	}),
	observeEnv,
);
const t15data = (await t15res.json()) as Record<string, unknown>;
ctx.check(
	"observe mode → 403 labeled would-deny, no mint",
	t15res.status === 403 &&
		t15data.enforcement === "observe" &&
		ctx.minted.length === mintsBefore,
	{ status: t15res.status, data: t15data },
);

};
