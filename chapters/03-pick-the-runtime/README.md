# Chapter 3 — Pick the runtime from observations

The bundled pair has the same job, base, acceptance digest, and reviewer rule. Generate the scorecard:

```sh
./remote-agent runtime-scorecard --attempt fixtures/evidence/local.json --attempt fixtures/evidence/remote.json --output runtime-scorecard.csv
```

Open the CSV. It must contain two `attempt` rows and one `decision` row. Then replace both inputs with observations from one comparable task in your repository: setup time, wall time, reviewer time, every cost source, evidence completeness, and hard constraints. A mismatch should refuse instead of producing a winner.
