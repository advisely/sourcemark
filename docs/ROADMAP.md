# Sourcemark — Roadmap & Phase 0 Commit Contract

> The v1 contract committed six months of engineering to a storage engine, MVCC, WAL, HNSW, BM25, RRF, an SQL surface and a Jepsen suite — and explicitly deferred Merkle anchoring, the only differentiated item, to Phase 1.5 or 2. This document inverts that ordering. The differentiator ships first because it is the only thing worth finding out about early.

---

## Phase 0 — Prove the receipt · 8 weeks · 1 engineer

**The question this phase answers:** can a party with no access to our systems verify where an AI answer came from?

If the answer is no, nothing later matters. If it is yes, the rest is adapters.

### In scope

| # | Deliverable | Acceptance | Status |
|---|---|---|---|
| 1 | Receipt spec v0.1 — CBOR schema, C2PA assertion profile, canonical serialization | Published; a second implementer can write a verifier from the document alone | **done** — `spec/`, C2PA profile still draft |
| 2 | `sourcemark-py` — Anchor + Emit | Anchors a 10k-chunk corpus; emits a signed receipt per result | **done** — 10k chunks in 0.23 s, 0.49 ms p95 per receipt |
| 3 | pgvector adapter | Five metadata fields written at ingest, read at query, no schema migration beyond `ALTER TABLE ADD COLUMN` | written, **not yet run against a live database** |
| 4 | Docling coordinate adapter | Page, bbox, byte range normalized from Docling output | **done** |
| 5 | `sourcemark verify` — CLI, offline (ships from [`sourcemark-verify`](https://github.com/advisely/sourcemark-verify)) | Seven distinct outcomes per `ARCHITECTURE.md §7`, not a boolean | not started |
| 6 | Transparency log integration | Roots submitted to Rekor or a Trillian instance; signed tree heads retrievable | not started — `InProcessLog` is a test fixture, not a log |
| 7 | One design partner, real corpus | Their documents, their store, their auditor | not started |

The `spec/` vectors are now load-bearing rather than illustrative: `sourcemark/tests/test_conformance.py` recomputes every value in `spec/examples/derivation.txt` with a separate implementation and asserts byte equality, signatures included. That is the acceptance criterion for deliverable 1 pointed inward, and it is the reason deliverable 5 can be written in another repository against the document alone.

### Explicitly out of scope

Storage engine. Index. Query planner. SQL. Parser. Embeddings. UI. Multi-tenancy. RBAC. HA. Sharding. Support scoring. Any second language binding. Any second store adapter.

### Launch gate — a single test

> A person who has never had access to our code, our infrastructure, or our design partner's systems is handed three files: an answer, a receipt, and the original PDF. Using only the open-source verifier and a public key, they determine — correctly, offline, in under a minute — that the cited text is genuinely at page 47 of that document and that the commitment predates the answer.

That is the whole gate. It is binary, it is cheap to run, and it cannot be passed by a system that does not work.

### What Phase 0 costs to be wrong about

Eight weeks and one salary. The v1 equivalent was six months and a team, spent on the commodity half.

---

## Phase 1 — Make it adoptable · months 3–6

- COSE/CBOR canonical form; C2PA assertion registered
- TypeScript SDK alongside Python
- Adapters: Qdrant, Weaviate, Elasticsearch, MongoDB Atlas
- Parser adapters: Reducto, Unstructured, Azure Document Intelligence
- **MCP delivery** — receipts inside resource-link annotations, so any MCP host gets them with no integration
- WASM verifier for in-browser checking; GitHub Action for CI
- Hosted log with published tree heads and third-party witnessing
- Cryptographic-erasure path implemented end to end (`SPEC.md §7`)

**Gate:** three design partners in production; one external party integrates using only the published spec.

---

## Phase 2 — Make it defensible · months 6–12

- **Bind** — support scoring, shipped with the `proven: false` discipline intact
- Policy binding: which policy decision authorized this retrieval, recorded in the receipt
- **EU AI Act evidence pack** — Article 12/19 field mapping, retention tooling, an export a Notified Body will accept
- Connectors into Credo AI, Vanta, watsonx.governance as an evidence source
- Reproducible builds and a formally reviewed verifier

**Gate:** one regulated customer passes an external audit citing Sourcemark receipts as the evidence.

---

## Phase 3 — Research horizon · 12 months+

Each of these is genuinely open, and none is required for the business to work.

- **Selective disclosure** — prove a chunk was retrieved and is authentic without revealing its contents. Directly relevant to classified and privileged corpora. The ZK-for-RAG literature is moving quickly here.
- **Redaction-tolerant proofs** — beyond salt destruction, toward proofs that survive partial redaction of a source document.
- **Cross-corpus consistency** — detect the same claim anchored to contradicting sources across an organization.
- **Witness network** — independent parties co-signing tree heads, removing the log operator from the trust set entirely.

---

## Rejected scope, and why

Recording these prevents them from being relitigated every quarter.

| Rejected | Why |
|---|---|
| Building a storage engine | Postgres won. Matching it costs a decade; beating it is not the business. |
| Building a parser | Four vendors do it well and give away the coordinates we need. |
| An end-user application | Puts us against funded workflow vendors who should be our channel. |
| A benchmarking harness ("Arena") | Nobody buys infrastructure because it ships a benchmark reporting that its vendor wins. |
| An operator console | A layer with no data plane has little to operate. Build it when a customer asks twice. |
| Our own transparency log format | The value of a log is its history and its scrutiny. Both argue for the standard one. |
| A compliance certification product | We produce evidence. Interpreting it is a different company with a different sales motion. |

---

## The two risks worth naming

**1. The receipt proves less than a buyer will assume.** Custody is not support. If marketing blurs them, the first customer to act on a well-anchored wrong answer destroys the trust proposition permanently. Mitigation is structural, not editorial: `proven: false` is a mandatory field, `Support` is optional in the schema while `Custody` is not, and no material describes a receipt as proving an answer correct.

**2. Cryptography may exceed what the market will pay for.** A signed, append-only log entry may capture most of the value at a fraction of the effort, and no organization has yet been fined under the provisions driving this. Mitigation: Phase 0 ships the simplest thing that passes the gate, and a design partner's auditor — not our engineering taste — decides how much depth the next phase buys.
