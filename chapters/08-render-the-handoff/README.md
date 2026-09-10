# Chapter 8 — Render the handoff

Dispatch the fixture, then recapture from durable state:

## One source, two views

```sh
./remote-agent evidence capture fixture-job --db agent.db --branch remote/fixture-job --output evidence.json
```

The command verifies the canonical bundle before writing `handoff.md` and `handoff-manifest.json`. The human view answers what was requested, what changed, what passed or failed, what still needs judgment, and how to reject or roll back. Its manifest binds both rendered output and source evidence digests.

Give those files without the author transcript to a reviewer. Your project passes this exercise only when the reviewer can point each answer to the canonical packet and a corrupt artifact or moved branch makes verification nonzero.
