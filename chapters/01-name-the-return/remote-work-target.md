# Chapter 1 — Name the return

Build a one-sentence target before choosing a runtime: **return one bounded repository change, on its own branch, with exact-SHA checks and a separate review decision.**

## Pin the start

Record the repository and its real immutable starting point:

```sh
git -C /absolute/path/to/repository rev-parse HEAD
```

Success is one 40-character commit you can place in `base_sha`, plus a result narrow enough for the repository's existing checks to judge. In your project, replace this note with the exact changed behavior, expected path set, and person or service authorized to review it.
