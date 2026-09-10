PRAGMA foreign_keys=ON;
INSERT INTO jobs(job_id,contract_digest,base_sha,state,created_at,updated_at)
VALUES
 ('queue-one','sha256:q1','1111111111111111111111111111111111111111','queued',datetime('now'),datetime('now')),
 ('queue-two','sha256:q2','1111111111111111111111111111111111111111','queued',datetime('now'),datetime('now')),
 ('queue-three','sha256:q3','1111111111111111111111111111111111111111','queued',datetime('now'),datetime('now')),
 ('queue-four','sha256:q4','1111111111111111111111111111111111111111','queued',datetime('now'),datetime('now'));
