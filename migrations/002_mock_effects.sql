-- Chapter 11: isolated effect ledger for guarded replay drills only.
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS effects (
  effect_key TEXT PRIMARY KEY,
  job_id TEXT NOT NULL,
  attempt_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('reserved','started','completed','ambiguous','failed')),
  delivery_count INTEGER NOT NULL DEFAULT 0,
  payload_digest TEXT NOT NULL,
  external_ref TEXT,
  updated_at TEXT NOT NULL
);
