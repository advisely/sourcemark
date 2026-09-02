# sourcemark/ — anchor, emit, adapters

**Licence:** Apache-2.0. These are the distribution surface; any licensing friction here kills the growth loop. See `docs/DISTRIBUTION.md` §2.

## Phase 0 deliverable

| Item | Detail |
|---|---|
| `anchor/` | Leaf construction, Merkle build, batch submission, metadata write-back |
| `emit/` | Retriever wrapper, receipt assembly, COSE signing |
| `adapters/stores/pgvector.py` | The one store adapter in Phase 0 |
| `adapters/parsers/docling.py` | The one parser adapter in Phase 0 |

Python only in Phase 0. TypeScript lands in Phase 1.

## Acceptance

- `anchor.commit()` is the single line a user adds to an existing ingest job
- `Emit` returns **bit-identical** ranking to the retriever it wraps — this is a test, not a promise
- Query-path overhead under 2 ms p95, and no network call on the query path
- A 10k-chunk corpus anchors end to end

## Out of scope, permanently

Storage engine. Index. Query planner. Parser. Embedding model. See `docs/SPEC.md §10`.
