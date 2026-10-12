// Lifecycle test: full request flow against a MOCK Artifacts binding.
// No Cloudflare account needed. Exercises the real Worker routes, the real
// policy engine, and the real broker logic (only the binding is faked).
//
//   npm run build && node dist/demo/lifecycle.js

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import handler from "../src/index.js";
import { getPolicyHash, shouldContain } from "../src/context.js";
import { verifyChain, MemoryAuditLog } from "../src/audit.js";
import { handleArtifactsEvent, pushChangedPaths } from "../src/watch.js";
import { revokeAllWriteTokens } from "../src/broker.js";
import type {
	ArtifactsBinding,
	Env,
	TokenScope,
} from "../src/types.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const POLICY_JSON = readFileSync(join(root, "policy.example.json"), "utf8");
// Quorum variant: elevation needs 2 distinct approvers.
const POLICY_JSON_QUORUM2 = JSON.stringify({
	...JSON.parse(POLICY_JSON),
	elevationQuorum: 2,
});

// ---- mock binding: records every mint/revoke, never touches the network ----
interface MintCall {
	repo: string;
	scope: TokenScope;
	ttl: number;
	plaintext: string;
}
const minted: MintCall[] = [];
const revoked: string[] = [];

const fakeBinding: ArtifactsBinding = {
	async create(name: string) {
		return {
			name,
			remote: `https://fake/${name}.git`,
			defaultBranch: "main",
			token: "fake-initial-token",
		};
	},
	async get(name: string) {
		return {
			async createToken(scope: TokenScope = "write", ttl = 900) {
				const plaintext = `fake-token-${minted.length + 1}`;
				minted.push({ repo: name, scope, ttl, plaintext });
				return {
					plaintext,
					scope,
					expiresAt: new Date(Date.now() + ttl * 1000).toISOString(),
				};
			},
			async revokeToken(tokenOrId: string) {
				revoked.push(tokenOrId);
				return true;
			},
			async listTokens() {
				const live = minted.filter(
					(m) =>
						m.repo === name && !revoked.includes(`tok-${m.plaintext}`),
				);
				return {
					total: live.length,
					tokens: live.map((m) => ({ id: `tok-${m.plaintext}`, scope: m.scope })),
				};
			},
			async readCommit(_hash: string) {
				return null;
			},
			async readTree(_hash: string) {
				return null;
			},
			async log(_opts?: { ref?: string; limit?: number; offset?: number }) {
				return [];
			},
			async info() {
				return { defaultBranch: "main" };
			},
			[Symbol.dispose]() {},
		};
	},
};

const env = {
	ARTIFACTS: fakeBinding,
	AUDIT_DB: undefined,
	POLICY_JSON,
	AGENT_KEYS_JSON: JSON.stringify({
		keys: {
			"test-key-docs": { agentId: "agent-docs-1", roles: ["docs-writer"] },
			"test-key-be": { agentId: "agent-be-1", roles: ["backend-dev"] },
			"test-key-rel": {
				agentId: "agent-rel-1",
				roles: ["release-manager"],
				canApprove: true,
			},
			"test-key-admin": {
				agentId: "admin",
				roles: ["admin"],
				canApprove: true,
				isAdmin: true,
			},
			"test-key-lead2": {
				agentId: "agent-lead-2",
				roles: ["release-manager"],
				canApprove: true,
			},
			"test-key-probe": { agentId: "agent-probe-1", roles: ["docs-writer"] },
			"test-key-expired": {
				agentId: "agent-old-1",
				roles: ["docs-writer"],
				expiresAt: "2020-01-01T00:00:00Z",
			},
			"test-key-badexp": {
				agentId: "agent-bad-1",
				roles: ["docs-writer"],
				expiresAt: "not-a-date",
			},
			"test-key-future": {
				agentId: "agent-new-1",
				roles: ["docs-writer"],
				expiresAt: "2099-01-01T00:00:00Z",
			},
		},
	}),
} as unknown as Env;

async function call(
	method: string,
	path: string,
	body?: unknown,
	key: string | null = "test-key-docs",
	customEnv?: typeof env,
): Promise<{ status: number; data: Record<string, unknown> }> {
	const headers: Record<string, string> = { "content-type": "application/json" };
	if (key) headers["authorization"] = `Bearer ${key}`;
	const res = await handler.fetch(
		new Request(`http://localhost${path}`, {
			method,
			headers,
			body: body === undefined ? undefined : JSON.stringify(body),
		}),
		customEnv ?? env,
	);
	return { status: res.status, data: (await res.json()) as Record<string, unknown> };
}

// Quorum env: same keys/audit, policy requires 2 distinct approvers.
const envQuorum2 = {
	...env,
	POLICY_JSON: POLICY_JSON_QUORUM2,
} as unknown as Env;
const callQ2 = (
	method: string,
	path: string,
	body?: unknown,
	key: string | null = "test-key-docs",
) => call(method, path, body, key, envQuorum2);

let failures = 0;
function check(name: string, cond: boolean, extra?: unknown) {
	console.log(`${cond ? "✓" : "✗"} ${name}`);
	if (!cond) {
		failures++;
		if (extra !== undefined) console.log(`  → ${JSON.stringify(extra)}`);
	}
}

// 1. allowed request mints a token through the broker
const t1 = await call("POST", "/v1/token", {
	agentId: "agent-docs-1",
	roles: ["docs-writer"],
	taskId: "t1",
	action: "push",
	repo: "website",
	branch: "docs/faq",
	paths: ["docs/faq.md"],
});
check("allow → 200 + token", t1.status === 200 && typeof t1.data.token === "string", t1.data);
check(
	"broker minted write/900 via binding",
	minted.length === 1 && minted[0].scope === "write" && minted[0].ttl === 900,
	minted,
);

// 2. denied request → 403, no mint
const t2 = await call("POST", "/v1/token", {
	agentId: "agent-docs-1",
	roles: ["docs-writer"],
	taskId: "t2",
	action: "push",
	repo: "website",
	branch: "main",
	paths: ["docs/faq.md"],
});
check("deny → 403, no new mint", t2.status === 403 && minted.length === 1, t2.data);

// 3. requireApproval → 202 with decisionId
const t3 = await call(
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
check(
	"requireApproval → 202 + decisionId",
	t3.status === 202 && typeof decisionId === "string",
	t3.data,
);

// 4. hard deny is NOT eligible for elevation → 422
const t4 = await call("POST", "/v1/elevate", {
	decisionId: t2.data.decisionId,
	justification: "please?",
});
check("elevate hard-deny → 422", t4.status === 422, t4.data);

// 5. elevate the requireApproval decision → 202 + ticket
const t5 = await call(
	"POST",
	"/v1/elevate",
	{
		decisionId,
		justification: "hotfix needs to ship before freeze",
	},
	"test-key-rel",
);
const elevationId = t5.data.elevationId as string;
check(
	"elevate → 202 + ticket",
	t5.status === 202 && typeof elevationId === "string",
	t5.data,
);

// 6. pending list contains it
const t6 = await call("GET", "/v1/elevations?status=pending");
check(
	"pending list contains ticket",
	(t6.data.elevations as unknown[]).length === 1,
	t6.data,
);

// 7. approve → token with capped TTL (approver key required;
// must differ from the requester — anti-self-approval)
const t7 = await call(
	"POST",
	`/v1/elevate/${elevationId}/approve`,
	{},
	"test-key-admin",
);
check(
	"approve → 200 + token, ttl ≤ 300",
	t7.status === 200 &&
		typeof t7.data.token === "string" &&
		(t7.data.ttlSeconds as number) <= 300,
	t7.data,
);

// 8. double approve → 409
const t8 = await call(
	"POST",
	`/v1/elevate/${elevationId}/approve`,
	{},
	"test-key-admin",
);
check("double approve → 409", t8.status === 409, t8.data);

// 9. kill switch
const t9 = await call("POST", "/v1/revoke", {
	repo: "website",
	tokenOrId: minted[0].plaintext,
});
check(
	"revoke → true, recorded",
	t9.status === 200 && t9.data.revoked === true && revoked.length === 1,
	t9.data,
);

// 10. audit trail has everything
const t10 = await call("GET", "/v1/decisions?limit=50");
const stats = t10.data.stats as { total: number; allowed: number; denied: number };
check(
	"audit stats sane (4 records: 3 allow, 1 deny)",
	stats.total === 4 && stats.allowed === 3 && stats.denied === 1,
	stats,
);

// 11. broker was the ONLY minter
check(
	"all mints went through broker mock (2 total)",
	minted.length === 2,
	minted,
);

// 12. hash-chained audit verifies (tamper-evident, oldest-first)
const chain = await call("GET", "/v1/decisions?limit=50");
const records = (
	(chain.data.decisions as import("../src/audit.js").AuditRecord[]).slice().reverse()
);
const v = await verifyChain(records);
check("audit hash chain verifies", v.ok, v);

// 13. tamper is detected: flip one record's reason → chain breaks
const tampered = records.map((r) => ({ ...r }));
tampered[1] = { ...tampered[1], decision: { ...tampered[1].decision, reason: "forged" } };
const v2 = await verifyChain(tampered);
check("tampered chain detected", !v2.ok && v2.badIndex === 1, v2);

// 14. fail-closed: broken policy → 503, allowed:false, no mint
const brokenEnv = { ...env, POLICY_JSON: "not-json{{{" } as unknown as Env;
const mintsBefore = minted.length;
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
check(
	"broken policy → 503 fail-closed, no mint",
	t14.status === 503 && t14data.allowed === false && minted.length === mintsBefore,
	{ status: t14.status, data: t14data },
);

// 15. observe mode: deny still blocks mint, but is labeled would-deny
const observePolicy = JSON.stringify({
	...JSON.parse(POLICY_JSON),
	mode: "observe",
});
const observeEnv = { ...env, POLICY_JSON: observePolicy } as unknown as Env;
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
check(
	"observe mode → 403 labeled would-deny, no mint",
	t15res.status === 403 &&
		t15data.enforcement === "observe" &&
		minted.length === mintsBefore,
	{ status: t15res.status, data: t15data },
);

// 16. no key → 401
const t16 = await call(
	"POST",
	"/v1/token",
	{ taskId: "t16", action: "read", repo: "website" },
	null,
);
check("no key → 401", t16.status === 401, t16.data);

// 17. bad key → 401
const t17 = await call(
	"POST",
	"/v1/token",
	{ taskId: "t17", action: "read", repo: "website" },
	"wrong-key",
);
check("bad key → 401", t17.status === 401, t17.data);

// 39. expired key → 401 with expiry message
const t39 = await call(
	"POST",
	"/v1/token",
	{ taskId: "t39", action: "read", repo: "website", paths: ["README.md"] },
	"test-key-expired",
);
check(
	"expired key → 401 key expired",
	t39.status === 401 && String(t39.data.error).includes("expired"),
	t39.data,
);

// 40. unparseable expiresAt → 503 fail-closed (misconfiguration)
const t40 = await call(
	"POST",
	"/v1/token",
	{ taskId: "t40", action: "read", repo: "website", paths: ["README.md"] },
	"test-key-badexp",
);
check("bad expiresAt → 503 fail-closed", t40.status === 503, t40.data);

// 41. future expiry → works normally
const t41 = await call(
	"POST",
	"/v1/token",
	{ taskId: "t41", action: "read", repo: "website", paths: ["README.md"] },
	"test-key-future",
);
check("future expiresAt → 200", t41.status === 200, t41.data);

// 42. policy hash is deterministic and matches SHA-256(POLICY_JSON)
const t42h1 = await getPolicyHash(env as never);
const t42h2 = await getPolicyHash(env as never);
const t42expected = [...new Uint8Array(
	await crypto.subtle.digest(
		"SHA-256",
		new TextEncoder().encode((env as unknown as { POLICY_JSON: string }).POLICY_JSON),
	),
)].map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 16);
check(
	"policyHash deterministic, 16 hex, matches POLICY_JSON",
	t42h1 === t42h2 && t42h1 === t42expected && /^[0-9a-f]{16}$/.test(t42h1),
	{ h1: t42h1, expected: t42expected },
);

// 43. containment cooldown: first fires, second within window skips,
// after window fires again
const cdRepo = `cd-test-${Date.now()}`;
const cdT0 = Date.now();
check("cooldown: first → fire", shouldContain(cdRepo, cdT0) === true, null);
check(
	"cooldown: second within 5min → skip",
	shouldContain(cdRepo, cdT0 + 60_000) === false,
	null,
);
check(
	"cooldown: after 5min → fire again",
	shouldContain(cdRepo, cdT0 + 5 * 60_000 + 1) === true,
	null,
);
check(
	"cooldown: per-repo isolation",
	shouldContain(cdRepo + "-other", cdT0 + 60_000) === true,
	null,
);

// 18. role spoofing is ignored: body claims release-manager, but the
// docs key's identity is used → evaluated as docs-writer → 403 on main.
const t18 = await call("POST", "/v1/token", {
	agentId: "mallory",
	roles: ["release-manager"],
	taskId: "t18",
	action: "push",
	repo: "website",
	branch: "main",
	paths: ["docs/x.md"],
});
const t18rec = (
	(await call("GET", "/v1/decisions?limit=1")).data.decisions as unknown[]
)[0] as import("../src/audit.js").AuditRecord;
check(
	"spoofed roles ignored → 403, audit shows key identity",
	t18.status === 403 && t18rec.req.agentId === "agent-docs-1",
	{ status: t18.status, agentId: t18rec.req.agentId },
);

// 19. non-approver key cannot approve: fresh ticket, docs key → 403
const t19d = await call(
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
const t19e = await call(
	"POST",
	"/v1/elevate",
	{ decisionId: t19d.data.decisionId, justification: "x" },
	"test-key-rel",
);
const t19a = await call(
	"POST",
	`/v1/elevate/${t19e.data.elevationId}/approve`,
	{},
	"test-key-docs",
);
check("non-approver approve → 403", t19a.status === 403, t19a.data);
// approver key cannot approve their OWN ticket (anti-self-approval)
const t19b = await call(
	"POST",
	`/v1/elevate/${t19e.data.elevationId}/approve`,
	{},
	"test-key-rel",
);
check(
	"self-approve → 403",
	t19b.status === 403 && String(t19b.data.error).includes("own elevation"),
	t19b.data,
);
// a different approver can approve → 200
const t19c = await call(
	"POST",
	`/v1/elevate/${t19e.data.elevationId}/approve`,
	{},
	"test-key-admin",
);
check("other approver → 200", t19c.status === 200, t19c.data);

// 20. 50 concurrent appends keep a linear hash chain (no fork)
{
	const { MemoryAuditLog } = await import("../src/audit.js");
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
	check("50 concurrent appends → chain verifies", vc.ok, vc);
}

// 21. /v1/verify exposes the tamper check
const t21 = await call("GET", "/v1/verify");
check(
	"/v1/verify → ok:true",
	t21.status === 200 && t21.data.ok === true,
	t21.data,
);

// 22. path traversal bypass is closed: docs/../../infra/secrets/key must NOT
// match the docs/** allow-rule → 403 fail-closed before rule evaluation
const t22 = await call("POST", "/v1/token", {
	taskId: "t22",
	action: "push",
	repo: "website",
	branch: "docs/guide",
	paths: ["docs/../../infra/secrets/key"],
});
check(
	"traversal path → 403, escapes-root",
	t22.status === 403 &&
		String(t22.data.reason).includes("escapes repository root"),
	t22.data,
);

// 23. benign dot-segments are normalized, not rejected: docs/./faq.md →
// docs/faq.md matches the docs/** allow-rule → 200
const t23 = await call("POST", "/v1/token", {
	taskId: "t23",
	action: "push",
	repo: "website",
	branch: "docs/guide",
	paths: ["docs/./faq.md"],
});
check(
	"docs/./faq.md → 200 (canonicalized)",
	t23.status === 200 && typeof t23.data.token === "string",
	t23.data,
);

// 24. severity labels: allow → info, main-branch deny → high
const t24deny = await call("POST", "/v1/token", {
	taskId: "t24",
	action: "push",
	repo: "website",
	branch: "main",
	paths: ["docs/x.md"],
});
const t24all = (
	(await call("GET", "/v1/decisions?limit=10")).data
		.decisions as import("../src/audit.js").AuditRecord[]
);
const t24allowRec = t24all.find(
	(r) => r.id === t23.data.decisionId,
);
const t24denyRec = t24all.find((r) => r.id === t24deny.data.decisionId);
check(
	"severity: allow→info, main deny→high",
	t24deny.status === 403 &&
		t24allowRec?.decision.severity === "info" &&
		t24denyRec?.decision.severity === "high",
	{
		allowSev: t24allowRec?.decision.severity,
		denySev: t24denyRec?.decision.severity,
	},
);

// 25. probing detection: 5 rapid denials by one agent → probing_suspected
// flag (critical), advisory only — the 5 denials themselves still just 403
let probeFlag: unknown;
for (let i = 0; i < 5; i++) {
	const r = await call(
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
	check(`probe denial ${i + 1} → 403`, r.status === 403, r.status);
}
const t25all = (
	(await call("GET", "/v1/decisions?limit=10")).data
		.decisions as import("../src/audit.js").AuditRecord[]
);
const t25probe = t25all.find((r) =>
	r.decision.reason.startsWith("probing_suspected:"),
);
check(
	"5th denial → probing_suspected flag, severity critical",
	typeof probeFlag === "string" &&
		t25probe?.id === probeFlag &&
		t25probe.decision.severity === "critical",
	{ probeFlag, reason: t25probe?.decision.reason },
);

// 26. notify-test without NOTIFY_WEBHOOK_URL → 501, not a crash
const t26 = await call("POST", "/v1/admin/notify-test", {}, "test-key-admin");
check(
	"notify-test w/o webhook URL → 501",
	t26.status === 501 && t26.data.ok === false,
	t26.data,
);

// 27. elevation works with no webhook configured (fail-open): ticket created
const t27d = await call(
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
const t27e = await call(
	"POST",
	"/v1/elevate",
	{ decisionId: t27d.data.decisionId, justification: "no webhook configured" },
	"test-key-rel",
);
check(
	"elevate w/o webhook → 202 ticket (fail-open)",
	t27e.status === 202 && typeof t27e.data.elevationId === "string",
	t27e.data,
);

// 28. chain still verifies after all new appends (severity is in the hash now,
// but old records hash identically — undefined severity is omitted)
const t28all = (
	(await call("GET", "/v1/decisions?limit=1000")).data
		.decisions as import("../src/audit.js").AuditRecord[]
)
	.slice()
	.reverse();
const t28v = await verifyChain(t28all);
check("chain verifies after severity upgrade", t28v.ok, t28v);

// 29. containment: unexplained push disarms outstanding write tokens
const memAudit = new MemoryAuditLog();
const containHandle = await fakeBinding.get("containment-repo");
await containHandle.createToken("write", 900);
await containHandle.createToken("write", 900);
await containHandle.createToken("read", 900);
const revokedBefore = revoked.length;
const t29evt = await handleArtifactsEvent(
	memAudit,
	{
		type: "cf.artifacts.repo.pushed",
		source: { type: "artifacts.repo", namespace: "test", repoName: "containment-repo" },
		payload: { ref: "refs/heads/main", after: "abc123", commits: [] },
	},
	Date.now(),
	{ onUnexplainedPush: (repo) => revokeAllWriteTokens(fakeBinding, repo) },
);
const t29detail = JSON.parse(t29evt.detail);
check(
	"unexplained push → containment revokes 2 write tokens, read survives",
	t29evt.verdict === "unexplained" &&
		t29detail.containment?.ok === true &&
		t29detail.containment.revoked === 2 &&
		t29detail.containment.total === 3 &&
		revoked.length === revokedBefore + 2,
	{ verdict: t29evt.verdict, containment: t29detail.containment },
);

// 30. explained push → containment hook NOT called
let hookCalls = 0;
const memAudit2 = new MemoryAuditLog();
await memAudit2.append({
	req: {
		agentId: "agent-docs-1",
		roles: ["docs-writer"],
		taskId: "seed-explained",
		action: "push",
		repo: "containment-repo",
		branch: "docs/guide",
		paths: ["docs/guide.md"],
	},
	decision: { allowed: true, reason: "seed" },
	enforcement: "enforce",
});
const t30evt = await handleArtifactsEvent(
	memAudit2,
	{
		type: "cf.artifacts.repo.pushed",
		source: { type: "artifacts.repo", namespace: "test", repoName: "containment-repo" },
		payload: { ref: "refs/heads/docs/guide", after: "def456", commits: [] },
	},
	Date.now(),
	{
		onUnexplainedPush: async () => {
			hookCalls++;
			return { revoked: 0, total: 0 };
		},
	},
);
check(
	"explained push → no containment, verdict explained",
	t30evt.verdict === "explained" && hookCalls === 0,
	{ verdict: t30evt.verdict, hookCalls },
);

// 31. containment hook throwing → event still logged, failure recorded
const memAudit3 = new MemoryAuditLog();
const t31evt = await handleArtifactsEvent(
	memAudit3,
	{
		type: "cf.artifacts.repo.pushed",
		source: { type: "artifacts.repo", namespace: "test", repoName: "containment-repo" },
		payload: { ref: "refs/heads/evil", after: "666", commits: [] },
	},
	Date.now(),
	{
		onUnexplainedPush: async () => {
			throw new Error("binding exploded");
		},
	},
);
const t31detail = JSON.parse(t31evt.detail);
check(
	"hook throws → event logged unexplained, containment failure recorded",
	t31evt.verdict === "unexplained" &&
		t31detail.containment?.ok === false &&
		typeof t31detail.containment.error === "string",
	t31detail.containment,
);

// 32. piggyback: a second push to the same branch cannot reuse the decision
const memAudit4 = new MemoryAuditLog();
await memAudit4.append({
	req: {
		agentId: "agent-docs-1",
		roles: ["docs-writer"],
		taskId: "seed-piggyback",
		action: "push",
		repo: "containment-repo",
		branch: "docs/pb",
		paths: ["docs/pb.md"],
	},
	decision: { allowed: true, reason: "seed" },
	enforcement: "enforce",
});
const pbHook = {
	calls: 0,
	async onUnexplainedPush(_repo: string, _branch: string) {
		pbHook.calls++;
		return { revoked: 0, total: 0 };
	},
};
const pbEvent = (after: string) => ({
	type: "cf.artifacts.repo.pushed",
	source: { type: "artifacts.repo", namespace: "test", repoName: "containment-repo" },
	payload: { ref: "refs/heads/docs/pb", after, commits: [] },
});
const t32a = await handleArtifactsEvent(memAudit4, pbEvent("aaa"), Date.now(), pbHook);
const t32b = await handleArtifactsEvent(memAudit4, pbEvent("bbb"), Date.now(), pbHook);
check(
	"piggyback blocked: 1st push explained, 2nd unexplained + containment",
	t32a.verdict === "explained" &&
		t32b.verdict === "unexplained" &&
		pbHook.calls === 1,
	{ first: t32a.verdict, second: t32b.verdict, hookCalls: pbHook.calls },
);

// 33. content violation: branch matches but pushed files exceed the
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
check(
	"content violation → unexplained + containment, violation recorded",
	t33evt.verdict === "unexplained" &&
		cvHookCalls === 1 &&
		t33d.contentVerified !== true &&
		t33d.contentViolation?.changed?.includes("src/auth/evil.ts") &&
		JSON.stringify(t33d.contentViolation?.allowedPaths)?.includes("docs/**"),
	{ verdict: t33evt.verdict, detail: t33d },
);

// 34. content within declared paths → explained, no containment
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
check(
	"content within paths → explained, contentVerified, no containment",
	t34evt.verdict === "explained" &&
		okHookCalls === 0 &&
		t34d.contentVerified === true,
	{ verdict: t34evt.verdict, detail: t34d },
);

// 35. content indeterminable (null) → branch-only fallback, honest flag
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
check(
	"content unknown → explained with contentVerified:false (no false positive)",
	t35evt.verdict === "explained" && t35d.contentVerified === false,
	{ verdict: t35evt.verdict, detail: t35d },
);

// 36. pushChangedPaths diffs trees (added + modified + deleted)
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
check(
	"pushChangedPaths: modified + added + deleted, recursive",
	t36changed !== null &&
		t36changed.includes("a.md") &&
		t36changed.includes("b.md") &&
		t36changed.includes("gone.md") &&
		!t36changed.includes("sub/deep.md") &&
		t36changed.length === 3,
	t36changed,
);
// 37. zero before-sha (new branch): fork point found via default tip in chain
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
check(
	"pushChangedPaths: zero before → fork point from chain",
	t37changed !== null &&
		t37changed.includes("a.md") &&
		t37changed.includes("b.md") &&
		t37changed.includes("sub/deep.md") &&
		t37changed.length === 3,
	t37changed,
);
// 38. zero before, default tip not in chain → null (unknown, not empty)
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
check(
	"pushChangedPaths: fork point absent → null (unknown)",
	t38changed === null,
	t38changed,
);

// 44. quorum=2: first approval → 202 pending, no token yet
const t44d = await callQ2(
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
const t44e = await callQ2(
	"POST",
	"/v1/elevate",
	{ decisionId: t44d.data.decisionId, justification: "quorum test" },
	"test-key-rel",
);
const t44a1 = await callQ2(
	"POST",
	`/v1/elevate/${t44e.data.elevationId}/approve`,
	{},
	"test-key-admin",
);
check(
	"quorum=2: 1st approval → 202 pending",
	t44a1.status === 202 &&
		t44a1.data.approved === false &&
		t44a1.data.approvals === 1 &&
		t44a1.data.requiredApprovals === 2 &&
		!t44a1.data.token,
	t44a1.data,
);

// 45. quorum=2: same approver twice → 409, no double count
const t45dup = await callQ2(
	"POST",
	`/v1/elevate/${t44e.data.elevationId}/approve`,
	{},
	"test-key-admin",
);
check(
	"quorum=2: duplicate approval → 409",
	t45dup.status === 409,
	t45dup.data,
);

// 46. quorum=2: second DISTINCT approver → 200 + token
const t46a2 = await callQ2(
	"POST",
	`/v1/elevate/${t44e.data.elevationId}/approve`,
	{},
	"test-key-lead2",
);
check(
	"quorum=2: 2nd distinct approval → 200 + token",
	t46a2.status === 200 &&
		t46a2.data.approved === true &&
		typeof t46a2.data.token === "string" &&
		t46a2.data.approvals === 2,
	t46a2.data,
);

// 47. quorum=2: requester cannot be one of the approvers
const t47d = await callQ2(
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
const t47e = await callQ2(
	"POST",
	"/v1/elevate",
	{ decisionId: t47d.data.decisionId, justification: "self quorum test" },
	"test-key-lead2",
);
const t47self = await callQ2(
	"POST",
	`/v1/elevate/${t47e.data.elevationId}/approve`,
	{},
	"test-key-lead2",
);
check(
	"quorum=2: requester self-approve → 403",
	t47self.status === 403,
	t47self.data,
);

console.log(failures === 0 ? "\nLifecycle: ALL GREEN" : `\nLifecycle: ${failures} FAILURES`);
process.exit(failures === 0 ? 0 : 1);
