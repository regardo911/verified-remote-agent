# Chapter 12 — Adopt and upgrade

Prove adoption in a clean disposable repository before touching a long-lived one. Initialization should produce the same contract refusals, durable state, fixture dispatch, evidence, and guarded drill as this repository.

## Inspect, then plan

Inspect and plan first:

```sh
./remote-agent upgrade inspect --config remote-agent.json
./remote-agent upgrade plan --config remote-agent.json --output upgrade-plan.json
```

`inspect` is read-only. `plan` writes a digest-bound proposal; `apply` refuses unless you supply that exact plan and digest. In your project, retain local policy and adapter settings, test the plan in a clean copy, and store before/after receipts. No upgrade step publishes or enables a live adapter.
