// Pure policy engine. No I/O, no Cloudflare dependencies — fully unit-testable.
//
// Semantics:
//   1. Rules are evaluated in order; collect all matches.
//   2. Any matching DENY beats any matching ALLOW (explicit deny wins).
//   3. Otherwise the first matching ALLOW applies.
//   4. No match → policy.defaultEffect (deny in practice).

import type {
	AccessRequest,
	Decision,
	Policy,
	PolicyRule,
	Severity,
} from "./types.js";

/** Glob → RegExp. Supports `*` (within a path segment) and `**` (across segments). */
export function globToRegExp(glob: string): RegExp {
	let re = "";
	for (let i = 0; i < glob.length; i++) {
		const c = glob[i];
		if (c === "*") {
			if (glob[i + 1] === "*") {
				re += ".*";
				i++;
			} else {
				re += "[^/]*";
			}
		} else if ("\\.+?^${}()|[]".includes(c)) {
			re += "\\" + c;
		} else {
			re += c;
		}
	}
	return new RegExp(`^${re}$`);
}

function listMatches(
	globs: string[] | undefined,
	value: string | undefined,
): boolean {
	if (!globs || globs.length === 0) return true; // no constraint on this dimension
	if (value === undefined) return false;
	return globs.some((g) => globToRegExp(g).test(value));
}

/**
 * Canonicalize a repository-relative path BEFORE policy matching.
 * Resolves "." / ".." segments and strips leading slashes.
 * Returns null when the path escapes the repository root (".." above root).
 *
 * Why: an uncanonicalized path like "docs/../../secrets/key" would match an
 * allow-rule for "docs/**" — a policy bypass via traversal. Untrusted input
 * must never be matched against security globs raw (InnerWarden's
 * sanitize-before-match discipline, cf. report.rs::safe_dated_file).
 */
export function canonicalizePath(p: string): string | null {
	const out: string[] = [];
	for (const seg of p.replace(/^\/+/, "").split("/")) {
		if (seg === "" || seg === ".") continue;
		if (seg === "..") {
			if (out.length === 0) return null; // escapes root → reject
			out.pop();
		} else {
			out.push(seg);
		}
	}
	return out.join("/");
}

function ruleMatches(rule: PolicyRule, req: AccessRequest): boolean {
	if (
		rule.agents &&
		!rule.agents.includes("*") &&
		!rule.agents.includes(req.agentId)
	) {
		return false;
	}
	if (
		rule.roles &&
		!rule.roles.includes("*") &&
		!req.roles.some((r) => rule.roles!.includes(r))
	) {
		return false;
	}
	if (!rule.actions.includes(req.action)) return false;
	if (!listMatches(rule.repos, req.repo)) return false;

	if (req.action === "push" || req.action === "create-branch") {
		if (!listMatches(rule.branches, req.branch)) return false;
	}

	if (req.paths && req.paths.length > 0) {
		if (rule.paths && rule.paths.length > 0) {
			const hit = (p: string) =>
				rule.paths!.some((g) => globToRegExp(g).test(p));
			if (rule.effect === "deny") {
				// Deny rules: ANY touched path hitting the glob triggers the rule.
				if (!req.paths.some(hit)) return false;
			} else {
				// Allow rules: EVERY touched path must be covered by the globs.
				if (!req.paths.every(hit)) return false;
			}
		}
	}
	return true;
}

export function evaluate(policy: Policy, req: AccessRequest): Decision {
	// Canonicalize request paths BEFORE any rule matching (fail-closed):
	// "docs/../../secrets/key" must never match an allow-rule for "docs/**".
	if (req.paths && req.paths.length > 0) {
		const clean: string[] = [];
		for (const p of req.paths) {
			const c = canonicalizePath(p);
			if (c === null) {
				return {
					allowed: false,
					reason: `path escapes repository root: ${p}`,
				};
			}
			clean.push(c);
		}
		req = { ...req, paths: clean };
	}

	const matches = policy.rules.filter((r) => ruleMatches(r, req));

	const deny = matches.find((r) => r.effect === "deny");
	if (deny) {
		return {
			allowed: false,
			reason: `denied by rule "${deny.id}"`,
			ruleId: deny.id,
		};
	}

	const allow = matches.find((r) => r.effect === "allow");
	if (allow) {
		return {
			allowed: true,
			reason: `allowed by rule "${allow.id}"`,
			ruleId: allow.id,
			tokenScope: req.action === "read" ? "read" : "write",
			ttlSeconds: Math.min(allow.maxTtlSeconds ?? 900, 3600),
			requireApproval: allow.requireApproval ?? false,
		};
	}

	return {
		allowed: false,
		reason: `no matching rule (default ${policy.defaultEffect})`,
	};
}

/**
 * Advisory severity for a decision — filtering/display only, never changes
 * the allow/deny outcome. Keep the mapping to a handful of hardcoded rules;
 * a config schema would be over-engineering here.
 * (Borrowed from InnerWarden's crates/core/src/event.rs::Severity.)
 */
export function severityFor(req: AccessRequest, d: Decision): Severity {
	if (d.reason.startsWith("probing_suspected:")) return "critical";
	if (!d.allowed) {
		const branch = req.branch ?? "";
		if (
			branch === "main" ||
			branch === "master" ||
			/protect/i.test(d.ruleId ?? "")
		) {
			return "high";
		}
		return "medium";
	}
	if (d.reason.startsWith("elevation ")) return "medium";
	if (d.requireApproval) return "low";
	return "info";
}
