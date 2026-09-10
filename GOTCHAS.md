# Gotchas

## renamed a key and broke dispatch

I moved validation from `commands` to `acceptance_commands` and missed the dispatch loop. Validation passed; dispatch died with `KeyError`. Search every admission, explanation, dispatch, and evidence consumer when a contract field moves.

## five green words prove nothing

The negative aggregate cases caught results from the wrong source, a different SHA, and a duplicate name. `ci/aggregate-gate` rejects all three. Keep result names and source identities aligned with branch protection.

## the drill wants an empty directory

It writes `agent.db`, `mock-effects.db`, and a receipt where it runs. A second run in the same directory refuses instead of replacing them. Use a new empty directory, then keep or move the outputs.
