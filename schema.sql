-- Cerberus audit log (D1). Append-only: decisions are never updated or deleted.
CREATE TABLE IF NOT EXISTS decisions (
	id TEXT PRIMARY KEY,            -- uuid v4
	ts INTEGER NOT NULL,             -- unix ms
	agent_id TEXT NOT NULL,
	task_id TEXT NOT NULL,
	action TEXT NOT NULL,            -- read | push | create-branch | fork
	repo TEXT NOT NULL,
	branch TEXT,
	paths TEXT,                     -- JSON array of touched paths
	allowed INTEGER NOT NULL,       -- 0 | 1
	reason TEXT NOT NULL,
	rule_id TEXT,
	token_scope TEXT,               -- read | write | NULL when denied
	ttl_seconds INTEGER,
	token_id TEXT,                  -- Artifacts token id when minted
	require_approval INTEGER NOT NULL DEFAULT 0,
	enforcement TEXT NOT NULL DEFAULT 'enforce',  -- enforce | observe
	severity TEXT,              -- info | low | medium | high | critical (advisory)
	-- Tamper-evident hash chain (borrowed from InnerWarden's decision log):
	-- each entry commits to the previous entry's hash.
	prev_hash TEXT,
	hash TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_decisions_agent ON decisions(agent_id);
CREATE INDEX IF NOT EXISTS idx_decisions_ts ON decisions(ts);
CREATE INDEX IF NOT EXISTS idx_decisions_allowed ON decisions(allowed);
-- Linear-chain invariant: two records may never share a prev_hash.
-- NULLs (the genesis record) are exempt in SQLite.
CREATE UNIQUE INDEX IF NOT EXISTS idx_decisions_prev_hash ON decisions(prev_hash);

-- Elevation (privilege-escalation approval) requests.
-- Only decisions the policy marks requireApproval are eligible: the policy
-- author decides what is escalatable; hard denies cannot be elevated.
CREATE TABLE IF NOT EXISTS elevations (
	id TEXT PRIMARY KEY,
	decision_id TEXT NOT NULL REFERENCES decisions(id),
	ts INTEGER NOT NULL,
	justification TEXT NOT NULL,
	status TEXT NOT NULL DEFAULT 'pending',  -- pending | approved | rejected
	decided_ts INTEGER,
	repo TEXT NOT NULL,
	token_scope TEXT NOT NULL,               -- read | write
	ttl_seconds INTEGER NOT NULL,
	token_id TEXT,
	required_approvals INTEGER NOT NULL DEFAULT 1,
	approvals TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_elevations_status ON elevations(status);

-- Raw Artifacts repo events observed via the Queue event subscription
-- (pushed / cloned / fetched / token.created / token.revoked).
-- Pushes are reconciled against decisions: a push with no matching
-- allow-decision is flagged UNEXPLAINED.
CREATE TABLE IF NOT EXISTS repo_events (
	id TEXT PRIMARY KEY,
	ts INTEGER NOT NULL,
	type TEXT NOT NULL,             -- cf.artifacts.repo.pushed | token.created | …
	repo TEXT NOT NULL,
	namespace TEXT NOT NULL,
	ref TEXT,                       -- refs/heads/<branch> for pushes
	verdict TEXT NOT NULL,          -- explained | unexplained | observed
	explained_by TEXT,              -- decision id when verdict=explained
	detail TEXT                     -- JSON (commit sha, token scope, …)
);

CREATE INDEX IF NOT EXISTS idx_repo_events_repo ON repo_events(repo, ts);
CREATE INDEX IF NOT EXISTS idx_repo_events_verdict ON repo_events(verdict);
