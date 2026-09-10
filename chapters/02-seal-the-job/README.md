# Chapter 2 — Seal the job

Copy `../../remote-job.md` into the initialized repository. Replace the fixture identity, objective, paths, limits, and the `base_sha` returned by Git; keep the branch bound to the job ID.

## Refuse before dispatch

```sh
./remote-agent validate-job remote-job.md
```

The valid contract exits 0 and prints `dispatch_started=false`. Try `fixtures/failures/jobs/overlap.md`; it must exit 2 before work starts. For your own job, use only symbolic acceptance commands already mapped by the repository and add a new identity whenever the objective or repository changes.
