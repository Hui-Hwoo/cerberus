// Audit log: hash chain, tamper detection, policy hash.
// Part of the lifecycle suite. Run via: npm run lifecycle [-- --suite=audit]

import type { Suite, TestContext } from "../harness.js";
import { verifyChain, MemoryAuditLog } from "../../../src/audit.js";
import type { AuditRecord } from "../../../src/audit.js";
import { getPolicyHash } from "../../../src/context.js";

export const suite: Suite = async (ctx: TestContext) => {
// seed: 2 allows + 1 deny + 1 elevation approval (self-contained)
await ctx.call("POST", "/v1/token", {
	taskId: "audit-seed-1",
	action: "read",
	repo: "website",
	paths: ["README.md"],
});
await ctx.call("POST", "/v1/token", {
	taskId: "audit-seed-2",
	action: "push",
	repo: "website",
	branch: "main",
	paths: ["src/evil.ts"],
});
await ctx.call("POST", "/v1/token", {
	taskId: "audit-seed-3",
	action: "read",
	repo: "website",
	paths: ["docs/guide.md"],
});

// audit trail has everything
const t10 = await ctx.call("GET", "/v1/decisions?limit=50");
const stats = t10.data.stats as { total: number; allowed: number; denied: number };
ctx.check(
	"audit stats sane (3 records: 2 allow, 1 deny)",
	stats.total === 3 && stats.allowed === 2 && stats.denied === 1,
	stats,
);

// broker was the ONLY minter
ctx.check(
	"all mints went through broker mock (2 total)",
	ctx.minted.length === 2,
	ctx.minted,
);

// hash-chained audit verifies (tamper-evident, oldest-first)
const chain = await ctx.call("GET", "/v1/decisions?limit=50");
const records = (
	(chain.data.decisions as AuditRecord[]).slice().reverse()
);
const v = await verifyChain(records);
ctx.check("audit hash chain verifies", v.ok, v);

// tamper is detected: flip one record's reason → chain breaks
const tampered = records.map((r) => ({ ...r }));
tampered[1] = { ...tampered[1], decision: { ...tampered[1].decision, reason: "forged" } };
const v2 = await verifyChain(tampered);
ctx.check("tampered chain detected", !v2.ok && v2.badIndex === 1, v2);


// 50 concurrent appends keep a linear hash chain (no fork)
{
	const { MemoryAuditLog } = await import("../../../src/audit.js");
	const log = new MemoryAuditLog();
	await Promise.all(
		Array.from({ length: 50 }, (_, i) =>
			log.append({
				req: {
					agentId: `agent-${i}`,
					roles: [],
					taskId: `tc-${i}`,
					action: "push",
					repo: "r",
					branch: "b",
					paths: [],
				},
				decision: { allowed: true, reason: "concurrency test" },
				enforcement: "enforce",
			}),
		),
	);
	const all = (await log.recent(100)).slice().reverse();
	const vc = await verifyChain(all);
	ctx.check("50 concurrent appends → chain verifies", vc.ok, vc);
}

// /v1/verify exposes the tamper check
const t21 = await ctx.call("GET", "/v1/verify");
ctx.check(
	"/v1/verify → ok:true",
	t21.status === 200 && t21.data.ok === true,
	t21.data,
);


// chain still verifies after all new appends (severity is in the hash now,
// but old records hash identically — undefined severity is omitted)
const t28all = (
	(await ctx.call("GET", "/v1/decisions?limit=1000")).data
		.decisions as import("../../../src/audit.js").AuditRecord[]
)
	.slice()
	.reverse();
const t28v = await verifyChain(t28all);
ctx.check("chain verifies after severity upgrade", t28v.ok, t28v);


// policy hash is deterministic and matches SHA-256(POLICY_JSON)
const t42h1 = await getPolicyHash(ctx.env as never);
const t42h2 = await getPolicyHash(ctx.env as never);
const t42expected = [...new Uint8Array(
	await crypto.subtle.digest(
		"SHA-256",
		new TextEncoder().encode((ctx.env as unknown as { POLICY_JSON: string }).POLICY_JSON),
	),
)].map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 16);
ctx.check(
	"policyHash deterministic, 16 hex, matches POLICY_JSON",
	t42h1 === t42h2 && t42h1 === t42expected && /^[0-9a-f]{16}$/.test(t42h1),
	{ h1: t42h1, expected: t42expected },
);


// policyHash integration: a real decision carries the policy hash
const t49m = await ctx.call("POST", "/v1/token", {
	taskId: "t49",
	action: "read",
	repo: "website",
	paths: ["README.md"],
});
const t49d = await ctx.call("GET", "/v1/decisions?limit=5");
const t49rec = (
	t49d.data.decisions as Array<{ id: string; decision: { policyHash?: string } }>
).find((r) => r.id === t49m.data.decisionId);
ctx.check(
	"decision record carries policyHash",
	typeof t49rec?.decision.policyHash === "string" &&
		t49rec.decision.policyHash.length === 16,
	t49rec?.decision.policyHash,
);

};
