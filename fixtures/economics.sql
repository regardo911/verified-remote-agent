PRAGMA foreign_keys=ON;
INSERT INTO cost_windows(window_id,starts_at,ends_at,budget) VALUES
 ('fixture-window','2000-01-01T00:00:00Z','2040-01-01T00:00:00Z','10.00'),
 ('empty-window','2040-01-01T00:00:00Z','2050-01-01T00:00:00Z','10.00');
INSERT INTO jobs(job_id,contract_digest,base_sha,state,accepted_head_sha,created_at,updated_at)
VALUES
 ('econ-accepted','sha256:econ-a','1111111111111111111111111111111111111111','accepted','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',datetime('now'),datetime('now')),
 ('econ-rejected','sha256:econ-r','1111111111111111111111111111111111111111','rejected',NULL,datetime('now'),datetime('now')),
 ('econ-cancelled','sha256:econ-c','1111111111111111111111111111111111111111','cancelled',NULL,datetime('now'),datetime('now')),
 ('budget-a','sha256:budget-a','1111111111111111111111111111111111111111','queued',NULL,datetime('now'),datetime('now')),
 ('budget-b','sha256:budget-b','1111111111111111111111111111111111111111','blocked',NULL,datetime('now'),datetime('now'));

INSERT INTO attempts(attempt_id,job_id,actor_id,workspace_id,trace_id,state,fencing_token,started_at,finished_at,head_sha,runtime_cost,model_cost,storage_cost,network_cost,reviewer_minutes)
VALUES
 ('econ-a1','econ-accepted','fixture','w-a1','t-a1','failed',301,datetime('now'),datetime('now'),'9999999999999999999999999999999999999999','0.10','0.20','0.01','0.01',2),
 ('econ-a2','econ-accepted','fixture','w-a2','t-a2','accepted',302,datetime('now'),datetime('now'),'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','0.10','0.20','0.01','0.01',3),
 ('econ-r1','econ-rejected','fixture','w-r1','t-r1','rejected',303,datetime('now'),datetime('now'),'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','0.10','0.20','0.01','0.01',4),
 ('econ-c1','econ-cancelled','fixture','w-c1','t-c1','cancelled',304,datetime('now'),datetime('now'),'cccccccccccccccccccccccccccccccccccccccc','unknown','0.20','0.01','0.01',1);

INSERT OR IGNORE INTO billing_imports VALUES('bill-econ-a2','econ-a2','0.20',datetime('now'));
INSERT OR IGNORE INTO billing_imports VALUES('bill-econ-a2','econ-a2','0.20',datetime('now'));
INSERT INTO budget_reservations VALUES('reservation-a','budget-a','8.00','reserved',NULL,datetime('now'));
INSERT INTO budget_reservations VALUES('reservation-b','budget-b','8.00','blocked','BUDGET_APPROVAL_REQUIRED',datetime('now'));
