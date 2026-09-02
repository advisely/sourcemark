# Why v2 exists

> This document exists so the pivot is legible and so the reasoning can be attacked rather than assumed.
>
> The v1 document set was removed from the working tree when the repository was restructured. It is retained in full in the private repository of record. Nothing quoted below was edited before deletion, and every claim about v1 below is checkable against it.

---

## The v1 thesis

ScaleDB v1: enterprises pay an "integration tax" of 3–5 systems for enterprise RAG, so build one Rust-native engine that consolidates ACID storage, vector search, lexical search, document parsing, graph extraction and lineage — and return a proof bundle with every result.

Two ideas were fused: **consolidation** and **provable provenance**. One of them survived contact with the 2026 market.

---

## What broke

**1. Consolidation lost.** Postgres absorbed vector search rather than being displaced by it — April 2026 benchmarks put pgvector+pgvectorscale at roughly ten times a standalone engine's throughput at 50M vectors and 99% recall. MongoDB, Oracle and Elastic all shipped native vector features; ANSI SQL began drafting vector extensions; Elastic's CEO called the category a feature; Pinecone was reported to be exploring a sale. The integration tax is being paid down by incumbents adding columns. Entering that market as the newest, least-proven engine was the plan.

**2. Three claimed moats were already commodity.**

| v1 claim | Reality when checked |
|---|---|
| "Lineage to page / paragraph / bbox — nearest alternative: **None**" | Reducto ships per-block and per-chunk bboxes and per-field citations; Unstructured returns element coordinates; LlamaParse does bbox layout extraction; Azure Document Intelligence and Textract return bbox with confidence |
| "No database ships MCP in its initial release" | MongoDB ships 40+ MCP tools; Neo4j and Weaviate ship MCP servers. v1's own Tier-1 table conceded this on the same page. The claim reduces to a schedule, not a moat |
| "Native RAGAS `/eval`" | RAGAS is an open-source library. Wrapping it in an endpoint is a feature |

**3. The roadmap deferred the only differentiator.** `PHASE1_COMMIT_CONTRACT.md §4.7` explicitly decommitted from Merkle anchoring and third-party verification, pushing them to Phase 1.5/2 — 2027–2028 — while `ScaleDB.md §13` listed Merkle-anchored proof bundles as moat item one. Six months of launch gates were gates on the commodity.

**4. The timing argument was understated.** EU AI Act high-risk obligations became enforceable in **August 2026**, after v1 was written: Article 12 mandates automatic logging over the system lifetime, Article 19 mandates retention, and tamper-evidence requires cryptographic chaining because ordinary stores permit silent updates. C2PA v2.3 shipped manifests for unstructured text in December 2025 specifically to cover LLM outputs. The forcing function arrived; the roadmap scheduled the response for two years later.

**5. A citation error worth fixing.** `APPENDIX_GTM.md` cites `github.com/milla-jovovich/mempalace` twice for temporal-validity and a "30x compression" claim. The project lives at `github.com/MemPalace/mempalace`, and its README warns explicitly about impostor sites. An investor-facing document citing a look-alike URL is a credibility problem independent of the technical argument.

---

## What survived

`ScaleDB.md §5.3` — the verification contract. Five offline checks against a bundle and a public tree head, with a reference verifier and no network call to the vendor. That page was the company; the other 200 pages were a database wrapped around it.

Nothing found in the market does this at the retrieval layer. A receipt category is forming at the **decision** layer — Veridra, EQTY Lab, VeriTrace, LedgerProof, agent-receipts — and every one of them signs the model's *output*. None binds a claim to a page, a bounding box and a byte range in a specific version of a specific document. The research says the problem is real and unsolved in product form: Proof-Carrying Answers, VeriRAG, Policy-Checked RAG with Cryptographic Receipts, ContextNest, SAG.

---

## The v2 thesis

Keep §5.3. Delete the database.

Sourcemark is a layer that makes an AI answer's citation into offline-verifiable evidence, riding on whatever retrieval stack the customer already runs. No data plane, no engine, no parser, no application. Every name on v1's competitor list becomes a partner, an integration target, or an acquirer.

---

## Claim-by-claim mapping

| v1 | v2 |
|---|---|
| "Consolidate 3–5 systems into one engine" | **Dropped.** Postgres won; the tax is being paid down by incumbents |
| "Proof bundles with verifiable lineage" | **Kept and promoted to the entire product** |
| "Merkle anchoring in Phase 1.5/2" | **Moved to Phase 0**, week one |
| "Lineage to bbox is unique" | **Reframed:** parsers produce coordinates; we make them provable |
| "MCP as a co-primary surface" | **Kept, reframed:** delivery channel via existing annotations, not a moat |
| "Native RAGAS `/eval`" | **Kept, demoted:** `Bind`, optional, explicitly `proven: false` |
| "Arena benchmarking, Console UI" | **Dropped.** Sales collateral, not product |
| "Proposal Intelligence as flagship product" | **Inverted:** GovDash, Rohirrim and Unanet become customers, not competition |
| "Trust boundaries at the storage layer" | **Kept, relocated:** policy reference recorded in the receipt |
| Tier 1 parity with Postgres/Mongo/Neo4j/Weaviate | **Abandoned as a goal.** Parity with an incumbent is a decade of work and no differentiation |

---

## The strongest argument against v2

A layer this thin is a few thousand lines of code. Once the pattern is proven, MongoDB or Elastic can reimplement it in a quarter, and being easy to absorb is the same property as being easy to copy.

The counter is that the defensible assets are not the code:

1. **The published profile** — whoever's format the ecosystem interoperates with sets the terms, and that is won by shipping a spec early and getting it into C2PA
2. **The log's operating history** — a transparency log's value is monotonic in its age, and a 2026 tree head cannot be manufactured in 2028
3. **Receipts already in regulators' hands** — evidence a Notified Body has accepted is a reference no competitor can retroactively acquire

All three compound with time. All three argue for shipping in weeks rather than months, which is what `ROADMAP.md` Phase 0 does.
