# Contributing

Keep changes small enough to reproduce locally.

1. Run `./ci/format-check`, `./ci/type-check`, and `./ci/unit-test` without network access.
2. Add a negative fixture when a parser, policy, state transition, gate, or recovery boundary changes.
3. Don't weaken a fixed command, exact-SHA check, independent-review source, or no-replacement restore rule to make a test pass.
4. Keep generated databases, receipts, logs, worktrees, credentials, and environment files out of commits.

For changes to executable contracts, include the valid case, the expected refusal, and the observable exit code.
