// Policy engine: traversal, severity, probing detection.
// Part of the lifecycle suite. Run via: npm run lifecycle [-- --suite=policy]

import type { Suite, TestContext } from "../harness.js";

export const suite: Suite = async (ctx: TestContext) => {
// path traversal bypass is closed: docs/../../infra/secrets/key must NOT
// match the docs/** allow-rule → 403 fail-closed before rule evaluation
const t22 = await ctx.call("POST", "/v1/token", {
	taskId: "t22",
	action: "push",
	repo: "website",
	branch: "docs/guide",
	paths: ["docs/../../infra/secrets/key"],
});
ctx.check(
	"traversal path → 403, escapes-root",
	t22.status === 403 &&
		String(t22.data.reason).includes("escapes repository root"),
	t22.data,
);

// benign dot-segments are normalized, not rejected: docs/./faq.md →
// docs/faq.md matches the docs/** allow-rule → 200
const t23 = await ctx.call("POST", "/v1/token", {
	taskId: "t23",
	action: "push",
	repo: "website",
	branch: "docs/guide",
	paths: ["docs/./faq.md"],
});
ctx.check(
	"docs/./faq.md → 200 (canonicalized)",
	t23.status === 200 && typeof t23.data.token === "string",
	t23.data,
);

// severity labels: allow → info, main-branch deny → high
const t24deny = await ctx.call("POST", "/v1/token", {
	taskId: "t24",
	action: "push",
	repo: "website",
	branch: "main",
	paths: ["docs/x.md"],
});
const t24all = (
	(await ctx.call("GET", "/v1/decisions?limit=10")).data
		.decisions as import("../../../src/audit.js").AuditRecord[]
);
const t24allowRec = t24all.find(
	(r) => r.id === t23.data.decisionId,
);
const t24denyRec = t24all.find((r) => r.id === t24deny.data.decisionId);
ctx.check(
	"severity: allow→info, main deny→high",
	t24deny.status === 403 &&
		t24allowRec?.decision.severity === "info" &&
		t24denyRec?.decision.severity === "high",
	{
		allowSev: t24allowRec?.decision.severity,
		denySev: t24denyRec?.decision.severity,
	},
);

// probing detection: 5 rapid denials by one agent → probing_suspected
// flag (critical), advisory only — the 5 denials themselves still just 403
let probeFlag: unknown;
for (let i = 0; i < 5; i++) {
	const r = await ctx.call(
		"POST",
		"/v1/token",
		{
			taskId: `t25-${i}`,
			action: "push",
			repo: "website",
			branch: "main",
			paths: ["docs/x.md"],
		},
		"test-key-probe",
	);
	if (i === 4) probeFlag = r.data.probingSuspected;
	ctx.check(`probe denial ${i + 1} → 403`, r.status === 403, r.status);
}
const t25all = (
	(await ctx.call("GET", "/v1/decisions?limit=10")).data
		.decisions as import("../../../src/audit.js").AuditRecord[]
);
const t25probe = t25all.find((r) =>
	r.decision.reason.startsWith("probing_suspected:"),
);
ctx.check(
	"5th denial → probing_suspected flag, severity critical",
	typeof probeFlag === "string" &&
		t25probe?.id === probeFlag &&
		t25probe.decision.severity === "critical",
	{ probeFlag, reason: t25probe?.decision.reason },
);

};
