// Lifecycle test runner: full request flow against a MOCK Artifacts binding.
// No Cloudflare account needed. Exercises the real Worker routes, the real
// policy engine, and the real broker logic (only the binding is faked).
//
//   npm run lifecycle                 → all suites
//   npm run lifecycle -- --suite=auth → one suite (isolated context)
//
// Each suite gets a FRESH context, so suites are independent and can run
// in any order. Within a suite, tests share the context (multi-step flows
// like elevate → approve need it).

import { createContext, type Suite } from "./harness.js";
import { suite as mintSuite } from "./suites/mint.js";
import { suite as authSuite } from "./suites/auth.js";
import { suite as elevationSuite } from "./suites/elevation.js";
import { suite as auditSuite } from "./suites/audit.js";
import { suite as policySuite } from "./suites/policy.js";
import { suite as reconciliationSuite } from "./suites/reconciliation.js";
import { suite as contentSuite } from "./suites/content.js";

const suites: Array<{ name: string; run: Suite }> = [
	{ name: "mint", run: mintSuite },
	{ name: "auth", run: authSuite },
	{ name: "elevation", run: elevationSuite },
	{ name: "audit", run: auditSuite },
	{ name: "policy", run: policySuite },
	{ name: "reconciliation", run: reconciliationSuite },
	{ name: "content", run: contentSuite },
];

const filter = process.argv
	.find((a: string) => a.startsWith("--suite="))
	?.split("=")[1];

let totalFailures = 0;
for (const s of suites) {
	if (filter && s.name !== filter) continue;
	console.log(`\n━━━ suite: ${s.name} ━━━`);
	const ctx = createContext();
	await s.run(ctx);
	totalFailures += ctx.failures;
}

if (filter && !suites.some((s) => s.name === filter)) {
	console.log(`\nUnknown suite "${filter}". Available: ${suites.map((s) => s.name).join(", ")}`);
	process.exit(2);
}

console.log(
	totalFailures === 0
		? "\nLifecycle: ALL GREEN"
		: `\nLifecycle: ${totalFailures} FAILURES`,
);
process.exit(totalFailures === 0 ? 0 : 1);
