// Policy linter: structural validation + heuristic warnings.
// Catches the "my allow rule can never fire" class of mistakes before deploy.
//
//   npm run lint:policy [-- policy.json]

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Policy } from "../src/types.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const file = process.argv[2] ?? join(root, "policy.example.json");
const policy = JSON.parse(readFileSync(file, "utf8")) as Policy;

const errors: string[] = [];
const warnings: string[] = [];

if (policy.version !== 1) errors.push(`version must be 1, got ${policy.version}`);
if (!["allow", "deny"].includes(policy.defaultEffect)) {
	errors.push(`defaultEffect must be allow|deny, got ${policy.defaultEffect}`);
}
if (!Array.isArray(policy.rules) || policy.rules.length === 0) {
	errors.push("rules must be a non-empty array");
}

const seen = new Set<string>();
const ACTIONS = ["read", "push", "create-branch", "fork"];
for (const r of policy.rules ?? []) {
	if (!r.id) errors.push("rule without id");
	else if (seen.has(r.id)) errors.push(`duplicate rule id "${r.id}"`);
	else seen.add(r.id);

	if (!["allow", "deny"].includes(r.effect)) errors.push(`[${r.id}] bad effect`);
	if (!Array.isArray(r.actions) || r.actions.length === 0) {
		errors.push(`[${r.id}] no actions`);
	} else for (const a of r.actions) {
		if (!ACTIONS.includes(a)) errors.push(`[${r.id}] unknown action "${a}"`);
	}
	if (r.effect === "deny" && r.requireApproval) {
		warnings.push(
			`[${r.id}] requireApproval on a deny rule has no effect (denies can't be elevated)`,
		);
	}
	if (
		r.effect === "allow" &&
		!r.repos?.length && !r.branches?.length && !r.paths?.length &&
		(!r.roles?.length || r.roles.includes("*"))
	) {
		warnings.push(`[${r.id}] unconstrained allow rule — grants ${r.actions.join(",")} widely`);
	}
}

// Heuristic: an allow rule fully shadowed by an earlier deny rule can never fire.
// Conservative check: deny.roles ⊇ allow.roles (or "*"), deny.actions ⊇ allow.actions,
// and deny's repo/branch/path globs are all "*" (or absent).
for (let i = 0; i < (policy.rules ?? []).length; i++) {
	const allow = policy.rules[i];
	if (allow.effect !== "allow") continue;
	for (let j = 0; j < i; j++) {
		const deny = policy.rules[j];
		if (deny.effect !== "deny") continue;
		const rolesCover =
			!deny.roles?.length || deny.roles.includes("*") ||
			(allow.roles ?? []).every((r) => deny.roles!.includes(r));
		const actionsCover = (allow.actions ?? []).every((a) =>
			(deny.actions ?? []).includes(a),
		);
		const wide = (g?: string[]) => !g?.length || g.includes("*");
		if (rolesCover && actionsCover && wide(deny.repos) && wide(deny.branches) && wide(deny.paths)) {
			warnings.push(
				`[${allow.id}] may be shadowed by earlier deny rule "${deny.id}" and never fire`,
			);
			break;
		}
	}
}

for (const e of errors) console.log(`ERROR: ${e}`);
for (const w of warnings) console.log(`WARN:  ${w}`);
console.log(
	errors.length === 0
		? `\npolicy OK (${policy.rules.length} rules, ${warnings.length} warnings)`
		: `\npolicy INVALID (${errors.length} errors)`,
);
process.exit(errors.length === 0 ? 0 : 1);
