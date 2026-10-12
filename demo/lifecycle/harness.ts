// Shared test harness for lifecycle suites.
// Each suite gets a FRESH context (mock binding, keys, audit log) so
// suites run in isolation — safe to run one suite alone via --suite=.
// Within a suite, tests share the context (multi-step flows like
// elevate → approve need it).

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import handler from "../../src/index.js";
import { resetFallbackAudit } from "../../src/context.js";
import type { ArtifactsBinding, Env, TokenScope } from "../../src/types.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
export const POLICY_JSON = readFileSync(
	join(root, "policy.example.json"),
	"utf8",
);
// Quorum variant: elevation needs 2 distinct approvers.
export const POLICY_JSON_QUORUM2 = JSON.stringify({
	...JSON.parse(POLICY_JSON),
	elevationQuorum: 2,
});

export interface MintCall {
	repo: string;
	scope: TokenScope;
	ttl: number;
	plaintext: string;
}

export interface CallResult {
	status: number;
	data: Record<string, unknown>;
}

export interface TestContext {
	env: Env;
	envQuorum2: Env;
	binding: ArtifactsBinding;
	minted: MintCall[];
	revoked: string[];
	call: (
		method: string,
		path: string,
		body?: unknown,
		key?: string | null,
		customEnv?: Env,
	) => Promise<CallResult>;
	callQ2: (
		method: string,
		path: string,
		body?: unknown,
		key?: string | null,
	) => Promise<CallResult>;
	check: (name: string, cond: boolean, extra?: unknown) => void;
	failures: number;
}

function makeBinding(minted: MintCall[], revoked: string[]): ArtifactsBinding {
	return {
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
						tokens: live.map((m) => ({
							id: `tok-${m.plaintext}`,
							scope: m.scope,
						})),
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
}

const KEYS_JSON = JSON.stringify({
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
});

/** Build an isolated context for one suite. */
export function createContext(): TestContext {
	resetFallbackAudit();
	const minted: MintCall[] = [];
	const revoked: string[] = [];
	const binding = makeBinding(minted, revoked);

	const env = {
		ARTIFACTS: binding,
		AUDIT_DB: undefined,
		POLICY_JSON,
		AGENT_KEYS_JSON: KEYS_JSON,
	} as unknown as Env;

	const envQuorum2 = { ...env, POLICY_JSON: POLICY_JSON_QUORUM2 } as Env;

	let failures = 0;
	function check(name: string, cond: boolean, extra?: unknown) {
		console.log(`${cond ? "✓" : "✗"} ${name}`);
		if (!cond) {
			failures++;
			if (extra !== undefined) console.log(`  → ${JSON.stringify(extra)}`);
		}
	}

	async function call(
		method: string,
		path: string,
		body?: unknown,
		key: string | null = "test-key-docs",
		customEnv?: Env,
	): Promise<CallResult> {
		const headers: Record<string, string> = {
			"content-type": "application/json",
		};
		if (key) headers["authorization"] = `Bearer ${key}`;
		const res = await handler.fetch(
			new Request(`http://localhost${path}`, {
				method,
				headers,
				body: body === undefined ? undefined : JSON.stringify(body),
			}),
			customEnv ?? env,
		);
		return {
			status: res.status,
			data: (await res.json()) as Record<string, unknown>,
		};
	}

	const callQ2 = (
		method: string,
		path: string,
		body?: unknown,
		key: string | null = "test-key-docs",
	) => call(method, path, body, key, envQuorum2);

	return {
		env,
		envQuorum2,
		binding,
		minted,
		revoked,
		call,
		callQ2,
		check,
		get failures() {
			return failures;
		},
	};
}

/** A named group of tests sharing one context. */
export type Suite = (ctx: TestContext) => Promise<void>;
