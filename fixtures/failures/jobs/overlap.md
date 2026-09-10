schema_version: 1
job_id: fixture-job
requested_by: fixture-operator
repository: .
base_sha: 1111111111111111111111111111111111111111
branch: remote/fixture-job
workspace: .remote-agent/workspaces/fixture-job
objective: Write one deterministic documentation fixture and return exact commit evidence.
allowed_paths:
  - docs/
denied_paths:
  - docs/private/
allowed_tools:
  - editor
  - git-diff
  - format
  - unit
  - type
network: deny-by-default
acceptance_commands:
  - format
  - unit
  - type
limits:
  max_wall_seconds: 300
  max_cost_usd: 2.00
stop_on:
  - policy-denial
  - destructive-migration
  - missing-secret-reference
  - acceptance-command-change
  - base-sha-drift
evidence_required:
  - diff-stat
  - changed-paths
  - commands
  - exit-codes
  - test-summary
  - head-sha
  - rollback
  - unresolved-risks
  - runtime
  - usage
idempotency_key: job_id + action_name + normalized-parameters-hash
