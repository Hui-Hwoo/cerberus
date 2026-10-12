// Local demo: runs scripted agent scenarios against the policy engine.
// No Cloudflare account needed. Prints the decision table + metrics.
//
//   npm run demo

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { evaluate } from "../src/policy.js";
import type { AccessRequest, Policy } from "../src/types.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const policy = JSON.parse(
	readFileSync(join(root, "policy.example.json"), "utf8"),
) as Policy;

interface Scenario {
	name: string;
	request: AccessRequest;
	expectAllowed: boolean;
	expectRequireApproval?: boolean;
}

const scenarios = JSON.parse(
	readFileSync(join(root, "demo", "scenarios.json"), "utf8"),
) as Scenario[];

let correct = 0;
let allowed = 0;
let denied = 0;
let approvalTickets = 0;
const latencies: number[] = [];

console.log("Cerberus policy demo — 14 scripted agent scenarios\n");
console.log(
	"scenario".padEnd(52) +
		"expected".padEnd(10) +
		"got".padEnd(10) +
		"rule".padEnd(34) +
		"match",
);

for (const s of scenarios) {
	const t0 = performance.now();
	const d = evaluate(policy, s.request);
	const t1 = performance.now();
	latencies.push(t1 - t0);

	const ok =
		d.allowed === s.expectAllowed &&
		(d.requireApproval ?? false) === (s.expectRequireApproval ?? false);
	if (ok) correct++;
	if (d.allowed) allowed++;
	else denied++;
	if (d.requireApproval) approvalTickets++;

	const flag = d.allowed
		? d.requireApproval
			? "ALLOW+APPR"
			: "ALLOW"
		: "DENY";
	console.log(
		s.name.padEnd(52) +
			(s.expectAllowed ? "allow" : "deny").padEnd(10) +
			flag.padEnd(10) +
			(d.ruleId ?? "-").padEnd(34) +
			(ok ? "✓" : `✗ (${d.reason})`),
	);
}

latencies.sort((a, b) => a - b);
const p50 = latencies[Math.floor(latencies.length * 0.5)];
const p99 = latencies[latencies.length - 1];

console.log("\n—— metrics ——");
console.log(`scenarios        : ${scenarios.length}`);
console.log(`correct decisions: ${correct}/${scenarios.length}`);
console.log(`allowed          : ${allowed} (incl. ${approvalTickets} approval tickets)`);
console.log(`denied           : ${denied}`);
console.log(`decision latency : p50 ${p50.toFixed(3)}ms · max ${p99.toFixed(3)}ms`);
console.log(
	`unauthorized pushes blocked: ${scenarios.filter((s) => !s.expectAllowed && s.request.action === "push").length}/${scenarios.filter((s) => s.request.action === "push").length} push attempts denied as expected`,
);

if (correct !== scenarios.length) {
	console.error("\nFAIL: some scenarios mismatched.");
	process.exit(1);
}
console.log("\nAll scenarios behaved as policy dictates.");
