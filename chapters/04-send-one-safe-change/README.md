# Chapter 4 — Send one safe change

After the first `init`, review and commit the copied control files. Run `init` again so the contract binds to that commit, then replace the already-reserved fixture identity with a new job ID, branch, and workspace. The local fixture can now prove dispatch mechanics without contacting a service:

```sh
./remote-agent dispatch remote-job.md --adapter local-fixture
```

Look for a new `remote/<job_id>` branch, `.remote-agent/workspaces/<job_id>`, `evidence.json`, and a `waiting_for_review` database state. The only worktree change is under `docs/`. Move to a live adapter in your project only after it preserves these branch, workspace, cancellation, and exact-SHA return boundaries; don't translate a hosted success into a local fixture claim.
