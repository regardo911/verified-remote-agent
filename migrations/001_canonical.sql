-- Chapter 5: canonical durable state with finite job transitions.
PRAGMA foreign_keys=ON;
PRAGMA journal_mode=WAL;
PRAGMA busy_timeout=5000;

CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS jobs (
  job_id TEXT PRIMARY KEY,
  contract_digest TEXT NOT NULL,
  base_sha TEXT NOT NULL CHECK(length(base_sha)=40),
  state TEXT NOT NULL CHECK(state IN ('queued','leased','running','verifying','waiting_for_review','accepted','rejected','failed','blocked','cancelling','cancelled','expired')),
  owner_attempt_id TEXT,
  lease_expires_at TEXT,
  accepted_head_sha TEXT,
  version INTEGER NOT NULL DEFAULT 0,
  last_heartbeat_at TEXT,
  last_progress_at TEXT,
  blocker_code TEXT,
  blocker_message TEXT,
  repo TEXT,
  branch TEXT,
  workspace_id TEXT,
  head_sha TEXT,
  evidence_uri TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attempts (
  attempt_id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
  actor_id TEXT NOT NULL,
  workspace_id TEXT NOT NULL,
  trace_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('leased','running','waiting_for_review','accepted','rejected','cancelled','failed','lost')),
  fencing_token INTEGER NOT NULL UNIQUE,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  head_sha TEXT,
  runtime_cost TEXT NOT NULL DEFAULT '0',
  model_cost TEXT NOT NULL DEFAULT '0',
  storage_cost TEXT NOT NULL DEFAULT '0',
  network_cost TEXT NOT NULL DEFAULT '0',
  reviewer_minutes INTEGER NOT NULL DEFAULT 0 CHECK(reviewer_minutes >= 0)
);

CREATE TABLE IF NOT EXISTS events (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
  attempt_id TEXT REFERENCES attempts(attempt_id) ON DELETE SET NULL,
  event_type TEXT NOT NULL,
  payload_json TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS effects (
  effect_key TEXT PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
  attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id) ON DELETE CASCADE,
  effect_type TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('reserved','started','completed','ambiguous','failed')),
  external_ref TEXT,
  payload_digest TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidence (
  evidence_id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
  attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id) ON DELETE CASCADE,
  head_sha TEXT NOT NULL CHECK(length(head_sha)=40),
  bundle_path TEXT NOT NULL,
  bundle_digest TEXT NOT NULL,
  checks_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS command_results (
  result_id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
  attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id) ON DELETE CASCADE,
  command_name TEXT NOT NULL,
  argv_digest TEXT NOT NULL,
  exit_code INTEGER NOT NULL,
  duration_ms INTEGER NOT NULL CHECK(duration_ms >= 0),
  stdout_digest TEXT NOT NULL,
  stderr_digest TEXT NOT NULL,
  raw_stdout_path TEXT NOT NULL,
  raw_stderr_path TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(attempt_id,command_name)
);

CREATE TABLE IF NOT EXISTS usage_records (
  usage_id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
  attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id) ON DELETE CASCADE,
  runtime_cost TEXT NOT NULL,
  model_cost TEXT NOT NULL,
  storage_cost TEXT NOT NULL,
  network_cost TEXT NOT NULL,
  recorded_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_decisions (
  decision_id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
  attempt_id TEXT REFERENCES attempts(attempt_id) ON DELETE SET NULL,
  target TEXT NOT NULL,
  result TEXT NOT NULL CHECK(result IN ('allowed','denied')),
  reason TEXT NOT NULL,
  policy_digest TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS queue_control (
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  state TEXT NOT NULL CHECK(state IN ('running','draining','stopped')),
  reason TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cost_windows (
  window_id TEXT PRIMARY KEY,
  starts_at TEXT NOT NULL,
  ends_at TEXT NOT NULL,
  budget TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS resource_locks (
  resource_key TEXT PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
  attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id) ON DELETE CASCADE,
  fencing_token INTEGER NOT NULL,
  acquired_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS job_dependencies (
  job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
  depends_on_job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
  required_head_sha TEXT NOT NULL,
  PRIMARY KEY(job_id,depends_on_job_id)
);

CREATE TABLE IF NOT EXISTS budget_reservations (
  reservation_id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
  amount TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('reserved','released','blocked')),
  reason TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS billing_imports (
  billing_id TEXT PRIMARY KEY,
  attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id) ON DELETE CASCADE,
  amount TEXT,
  imported_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS attempts_job_idx ON attempts(job_id);
CREATE INDEX IF NOT EXISTS events_job_idx ON events(job_id,event_id);
CREATE INDEX IF NOT EXISTS effects_attempt_idx ON effects(attempt_id);
CREATE INDEX IF NOT EXISTS evidence_job_idx ON evidence(job_id);
CREATE INDEX IF NOT EXISTS command_results_attempt_idx ON command_results(attempt_id);
CREATE INDEX IF NOT EXISTS usage_records_attempt_idx ON usage_records(attempt_id);

INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(1,datetime('now'));
INSERT OR IGNORE INTO queue_control(singleton,state,reason,updated_at)
VALUES(1,'running','initialized',datetime('now'));
