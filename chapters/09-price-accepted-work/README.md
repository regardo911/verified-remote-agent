# Chapter 9 — Price accepted work

Load the bundled measurement window into an initialized disposable database, then report it:

```sh
sqlite3 agent.db < fixtures/economics.sql
./remote-agent economics-report --db agent.db --window fixture-window --output economics.csv
```

The CSV separates attempt rows from the accepted-change summary, records the selected window, and prints `undefined` when no accepted result exists. Change the window to `empty-window`; the bytes should change. Import your own reconciled billing and reviewer-time records under stable IDs, and don't convert an absent price into zero.
