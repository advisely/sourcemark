# sourcemark/ — anchor, emit, adapters

**Licence:** Apache-2.0. These are the distribution surface; any licensing friction here kills the growth loop. See [`docs/DISTRIBUTION.md`](../docs/DISTRIBUTION.md) §2.

## What is here

| Module | What it does |
|---|---|
| [`cbor.py`](cbor.py) | Deterministic CBOR encoder and a strict decoder — `canonicalization.md` clause 2 |
| [`crypto.py`](crypto.py) | Salts, commitments, leaves, Merkle trees, COSE_Sign1 — clauses 3, 4, 5 |
| [`models.py`](models.py) | The values that cross Anchor, the store, and Emit |
| [`anchor.py`](anchor.py) | Commit at ingest: hash, fold, submit, write back |
| [`emit.py`](emit.py) | Sign at query time, as a pass-through wrapper |
| [`receipt.py`](receipt.py) | Receipt assembly, signing, and the JSON projection |
| [`keys.py`](keys.py) | Version keys (erasure) and the receipt signing key |
| [`log.py`](log.py) | Transparency log clients — `InProcessLog` for tests, `RekorLog` for Sigstore |
| [`adapters/stores/pgvector.py`](adapters/stores/pgvector.py) | The Phase 0 store adapter |
| [`adapters/parsers/docling.py`](adapters/parsers/docling.py) | The Phase 0 parser adapter |

Python only in Phase 0. TypeScript lands in Phase 1.

## Running the tests

```bash
python3 -m sourcemark.tests                       # every suite
SOURCEMARK_TEST_DSN=postgresql:///sourcemark_test \
SOURCEMARK_REKOR=https://rekor.sigstore.dev \
  python3 -m sourcemark.tests                     # including the two live ones
```

| Suite | Checks | What it settles |
|---|---|---|
| `test_conformance` | 29 | Reproduces every value in `spec/examples/derivation.txt`, byte for byte |
| `test_pipeline` | 27 | The Phase 0 acceptance criteria, end to end |
| `test_regressions` | 27 | One per defect found by adversarial probing |
| `test_pgvector` | 19 | A live Postgres: migrate, anchor, emit, detect an `UPDATE`, tear down |
| `test_rekor_live` | 9 | Our understanding of Rekor's format, against production, read-only |
| `test_rekor_integration` | 10 | Real submissions to a **local** Rekor on Trillian, end to end |

The two live suites skip with a printed reason when their dependency is absent. A skip that is silent is a test that passes because it never ran.

`test_conformance` is the one that matters. It recomputes every value in [`spec/examples/derivation.txt`](../spec/examples/derivation.txt) with this package — a separate implementation from the one that produced them — and asserts byte equality, including the signed COSE receipts and the JSON projection. If it passes, the spec's vectors are reproducible by something other than the script that wrote them, which is the only evidence that the canonicalization rules are written down rather than merely implemented.

## Acceptance, and where it stands

| Criterion | Status |
|---|---|
| `commit()` is the single line a user adds to an existing ingest job | met |
| Emit returns **bit-identical** ranking to the retriever it wraps | met — asserted on the result objects, not just their order |
| Query-path overhead under 2 ms p95, no network call on the query path | met — 0.49 ms p95 in `test_pipeline` |
| A 10k-chunk corpus anchors end to end | met — 200 document versions, 10,000 chunks, 4 log submissions |
| Reproduces the published spec vectors byte for byte | met — 29 checks |
| The pgvector adapter runs against a real database | met — Postgres 18, migration through teardown |
| Every conformance vector reaches its required outcome in an independent verifier | met — 16 of 16, in [`sourcemark-verify`](https://github.com/advisely/sourcemark-verify) |

## Two things to know before using it

**`InProcessLog` is not a transparency log.** It builds a real RFC 6962 tree and produces real proofs, signed with a key this process holds. That proves you are consistent with yourself and nothing else. The entire argument for a transparency log is that somebody other than the issuer signs the tree head. Use `RekorLog` for that. It is exercised against a real Rekor on a real Trillian, and the integration suite refuses by hostname to submit to a public log — a submission cannot be withdrawn, and the guard exists because the failure being prevented is somebody reusing the variable from the read-only suite.

**`LocalVersionKeys` cannot demonstrate erasure.** It keeps version keys in a JSON file, and a filesystem backup silently resurrects a key that erasure was supposed to destroy. Use a KMS-backed `VersionKeys` anywhere the erasure property is being claimed.

## Out of scope, permanently

Storage engine. Index. Query planner. Parser. Embedding model. See [`docs/SPEC.md`](../docs/SPEC.md) §10.
