# Sourcemark — Specification v0.1

> **Working name.** "Sourcemark" appears as a single token throughout this document set. It is not load-bearing; swap it if a better name lands.
>
> **Status.** Draft specification. Supersedes the ScaleDB v1 document set — see [`PIVOT.md`](PIVOT.md) for what changed and why.

---

## 1. What Sourcemark is

**Sourcemark makes an AI answer's citation into evidence.**

When a retrieval system returns a chunk of text, Sourcemark returns a **receipt** alongside it: a small, signed object proving that this exact text came from that exact place — page, paragraph, bounding box, byte range — in that exact version of that document, and that the commitment was made *before* the answer was generated.

Anyone can check that receipt offline, with no account, no network call to us, and no trust in us. The verifier is open source. It keeps working if this company disappears.

### What Sourcemark is not

Sourcemark is **not a database.** It stores no documents, serves no queries, and owns no data plane. It rides on whatever retrieval stack you already run — Postgres/pgvector, Qdrant, Weaviate, Elasticsearch, MongoDB Atlas, Azure AI Search, LanceDB. Your documents never leave your boundary. The only thing that leaves is a Merkle root: a 32-byte hash from which nothing can be reconstructed.

It is also **not a document parser.** Sourcemark consumes the coordinates that Docling, Reducto, Unstructured, LlamaParse, and Azure Document Intelligence already produce. Those are inputs, not competitors.

---

## 2. The problem, stated precisely

Enterprises are deploying retrieval-augmented AI into decisions that are now legally consequential. EU AI Act high-risk obligations became enforceable in August 2026: Article 12 mandates automatic event logging over the system's lifetime; Article 19 mandates retention. Regulators expect an organization to show *how* an AI-assisted conclusion was reached and *what source* supported it.

The current answer to "where did this come from?" is a citation: a filename, maybe a page number, rendered as a link in a chat UI.

A citation is a **claim about provenance**. It is not evidence of provenance. Specifically:

| Question an auditor asks | What a citation gives you |
|---|---|
| Is this text really in that document? | Nothing. The string was assembled by a pipeline you can't inspect. |
| Which *version* of the document? | Usually nothing. Most stacks overwrite on re-ingest. |
| Has the source changed since? | Nothing. |
| Was the citation attached before or after the answer? | Nothing — and this is the one that matters, because a citation added post-hoc is indistinguishable from a citation invented post-hoc. |
| Can I check this without the vendor's cooperation? | No. Every check routes back through the system under audit. |

**The structural flaw: the system being audited is the same system producing the audit evidence.** A standard database fails a tamper-evidence requirement not because it is badly built but because rows can be silently updated, and nothing in the record distinguishes an original from a revision.

---

## 3. Design principles

These are constraints, not aspirations. Each one closes off a direction that would make the product worse.

1. **No data plane.** Sourcemark never stores customer content. Only hashes cross the boundary. This is a privacy property, a security property, and a go-to-market property simultaneously.
2. **Verification survives the vendor.** The verifier is open source, offline, and dependency-light. If a receipt only verifies against our running service, we have built a trust-me system and solved nothing.
3. **Ride, don't replace.** Every capability ships as an adapter over an incumbent, never as a substitute for one.
4. **Custody and support are separate claims.** What is cryptographically proven and what is statistically scored are held in distinct fields with distinct semantics. See §5.
5. **Silence is a bug.** When a result cannot carry a receipt, the response says so explicitly, with a reason. A missing receipt must never look like a passing one.
6. **Standard formats over invented ones.** COSE/JOSE signing, C2PA manifests, RFC 6962 transparency logs. We contribute a profile, not a new stack.

---

## 4. Architecture: four components

Full diagrams in [`ARCHITECTURE.md`](ARCHITECTURE.md).

### 4.1 Anchor — commit at ingest

Runs as a library inside the customer's existing ingestion job.

**Input:** parser output — chunk text plus its coordinates, which every modern parser already emits.

**Per chunk, compute a leaf:**

```
leaf = H( doc_version_id ‖ chunk_id ‖ page ‖ bbox ‖ byte_range ‖ H(salt ‖ chunk_text) )
```

**Per document version, build a Merkle tree** over its leaves → `doc_root`.
**Per batch window, build a corpus tree** over doc_roots → `corpus_root`.
**Submit `corpus_root`** to an RFC 6962 transparency log (customer-hosted Trillian, Sigstore Rekor, or a Sourcemark-operated public log). Nothing else is submitted.

**Write back** into the customer's own store, as ordinary metadata alongside the chunk: `leaf_hash`, `inclusion_path`, `tree_size`, `log_entry_id`, `salt_ref`. Roughly 300–600 bytes per chunk, in columns the store already supports.

The salt is not decoration — see §7 on erasure.

### 4.2 Emit — sign at query time

A thin wrapper around the customer's retriever. It does not re-rank, re-embed, or otherwise touch retrieval quality; it reads the metadata Anchor wrote and assembles a receipt.

Delivered three ways, all from the same code path:
- **SDK** — the receipt is a field on the result object
- **HTTP** — a `Sourcemark-Receipt` header or an envelope field
- **MCP** — carried in the resource-link annotations that MCP already defines for provenance metadata, so any MCP host gets receipts without integrating anything

### 4.3 Verify — check offline

```
sourcemark verify receipt.cbor --log-key public.pem [--source original.pdf]
```

Five checks, all local:

1. **Content binding** — recompute `H(salt ‖ chunk_text)`; confirm it matches the receipt.
2. **Leaf construction** — recompute the leaf from the coordinates; confirm it matches `leaf_hash`.
3. **Inclusion** — fold `inclusion_path` into `leaf_hash`; confirm it reduces to `corpus_root`.
4. **Log consistency** — verify the signed tree head's signature and that `corpus_root` is committed at `tree_size`.
5. **Ordering** — confirm the log entry timestamp precedes the answer timestamp.

With `--source`, a sixth check re-derives the chunk from the original file at the recorded byte range and confirms byte identity. This is the check an auditor actually wants: *the document I am holding contains this text at this location, and your system committed to that before it answered.*

Ships as a static CLI binary, a WASM module for in-browser verification, and a GitHub Action.

### 4.4 Bind — score the support (optional, honest)

Custody proves the text is authentic. It says nothing about whether the model's sentence follows from that text. Bind scores that separately and labels it as a score.

| Class | Meaning | Basis |
|---|---|---|
| `QUOTED` | Generated span is a verbatim substring of the cited chunk | Deterministic |
| `SUPPORTED` | Entailment score ≥ threshold | Model-scored |
| `INFERRED` | Combines multiple chunks or requires a leap | Model-scored |
| `UNSUPPORTED` | No cited chunk supports the span | Model-scored |

`QUOTED` is the only class that is *decided* rather than *estimated*, and the receipt records the distinction.

---

## 5. The two-layer claim model

This is the core design contribution and the thing the rest of the category gets wrong.

A receipt asserts two different kinds of claim, and they must never be collapsed:

| | **Layer 1 — Custody** | **Layer 2 — Support** |
|---|---|---|
| Claim | This text is byte-identical to what was ingested from that source at those coordinates, committed at time *T* | This generated sentence follows from that text |
| Nature | Cryptographic | Statistical |
| Result | Binary: true or false | Continuous: a score against a threshold |
| Fails when | Bytes were altered, or the commitment is backdated | The model reasoned badly, or the threshold is wrong |
| Verifiable by | Anyone, offline, forever | Only reproducibly, with the same scorer and version |
| Receipt field | `custody` | `support` |

**Why this matters commercially:** every receipt product surveyed — decision-level attestation platforms, signed-output frameworks, AI integrity suites — signs the *output* and lets the buyer infer that the output is therefore trustworthy. It isn't. Signing a hallucination produces a cryptographically impeccable hallucination.

Sourcemark refuses that inference in the data model. A receipt whose `custody` verifies and whose `support` is `UNSUPPORTED` is a *correctly functioning* receipt reporting a *failed* answer. That is the product working.

**Why it matters legally:** an auditor's questions split cleanly along the same line. "Is this really from the document?" is a custody question with a provable answer. "Was the conclusion reasonable?" is a judgment question, and a vendor claiming to have proven it is overclaiming in a way that will not survive a deposition.

---

## 6. Receipt format

Canonical form is **COSE-signed CBOR**, profiled as a **C2PA manifest for unstructured text** (C2PA v2.3, December 2025, added manifests for unstructured text specifically to cover LLM outputs). A JSON projection exists for debugging and human reading; the CBOR is normative.

Emitting a C2PA manifest rather than a bespoke envelope means existing C2PA verifiers already parse the outer structure. We define an assertion, not a format.

```json
{
  "receipt_version": "0.1",
  "kind": "sourcemark.retrieval.receipt",

  "custody": {
    "source": {
      "document_id": "doc_2f8a91e",
      "document_version_id": "dv_c3e2881",
      "source_uri": "s3://policies/2026/SOP-114.pdf",
      "content_hash": "sha256:4a7e…c9b1",
      "committed_at": "2026-03-14T09:22:11Z"
    },
    "location": {
      "page": 47,
      "paragraph": "p-14",
      "bbox": [72, 318, 540, 402],
      "byte_range": [98211, 98644]
    },
    "derivation": {
      "chunk_id": "chk_88a1c",
      "parser": "docling@2.3.1",
      "salt_ref": "kms://tenant-acme/salt/dv_c3e2881"
    },
    "proof": {
      "leaf_hash": "sha256:…",
      "inclusion_path": ["sha256:…", "sha256:…"],
      "tree_size": 4218837,
      "corpus_root": "sha256:…",
      "log": "https://log.sourcemark.dev/2026",
      "log_entry_id": "0x3f21a…",
      "signed_tree_head": "cose:…"
    },
    "verified_offline": true
  },

  "support": {
    "class": "SUPPORTED",
    "score": 0.91,
    "scorer": "bge-reranker-v2@1.0",
    "threshold": 0.85,
    "proven": false,
    "note": "Statistical estimate. Not a cryptographic claim."
  },

  "context": {
    "query_id": "q_a8c01",
    "retriever": "pgvector@0.8.1",
    "retrieved_at": "2026-09-02T14:02:44Z",
    "policy_ref": "pol_dec_4421"
  }
}
```

The `"proven": false` field inside `support` is deliberate and mandatory. It is the machine-readable form of the honesty constraint in §5.

### 6.1 When a receipt cannot be issued

```json
{ "receipt_unavailable": {
    "reason": "chunk predates anchoring (ingested 2025-11-02, anchoring enabled 2026-01-15)",
    "remedy": "re-anchor corpus segment 'legacy-sops'"
} }
```

Never silent, never a stub that resembles a valid receipt.

---

## 7. Erasure vs. immutability

A tamper-evident log and a right-to-erasure obligation are in direct conflict, and the conflict is the first thing a privacy officer will raise. Handling it is a requirement, not an extension.

**Mechanism: cryptographic erasure via per-version salts.**

Each document version gets a random salt held in the customer's KMS. Leaves commit to `H(salt ‖ chunk_text)`, never to the text itself.

On an erasure request, the salt is destroyed. Consequences:

- The Merkle tree is **unchanged** — history stays intact, prior receipts still verify structurally, and no gap appears in the log
- The leaf becomes **unopenable** — no party, including us, can demonstrate what content it committed to
- Future verification of that chunk returns `ERASED`, a distinct outcome from `INVALID`

This satisfies the regulator's "the data is destroyed" and the auditor's "the log was not rewritten" at the same time. The log holds only roots and salted digests; it never held content to begin with.

---

## 8. Threat model

| Threat | Control | Component |
|---|---|---|
| Source altered after ingestion | Content hash in receipt; `--source` re-derivation fails | Verify |
| Citation fabricated post-hoc | Log entry timestamp precedes answer timestamp; ordering check | Verify |
| Vendor backdates a commitment | Append-only log with published signed tree heads; consistency proofs across STHs | Log |
| Vendor issues a receipt for text never ingested | Inclusion proof cannot be forged without the log's signing key | Verify |
| Log operator colludes with vendor | Customer-hosted log option; third-party witnessing of tree heads | Deployment |
| Answer is unsupported but receipt "looks valid" | `support.class` = `UNSUPPORTED`, `proven: false`; custody and support reported separately | Bind |
| Content leaks via the transparency log | Only salted digests and roots are submitted; nothing reconstructable | Anchor |
| Erasure request conflicts with immutable log | Salt destruction; `ERASED` verification outcome | §7 |
| Supply-chain compromise of the verifier | Reproducible builds; Sigstore-signed releases; SBOM; the verifier is small enough to audit by hand | Build |

---

## 9. Deployment

| Mode | What runs | Who holds the log |
|---|---|---|
| **Embedded** | Library in the ingestion job and the retrieval path. No service. | Public Sourcemark log or Rekor |
| **Sidecar** | Library plus a local submitter for batching and key custody | Customer-hosted Trillian |
| **Air-gapped** | Library plus a local log; tree heads exported on removable media | Customer, fully offline |

There is no mode in which Sourcemark holds customer documents. There is no migration to perform when adopting it and none when leaving.

---

## 10. What we deliberately do not build

Naming these is as important as naming the features, because each one is a door back to the v1 mistake.

- **A storage engine, index, or query planner.** The incumbent's is better and we would spend years matching it.
- **A document parser or OCR pipeline.** Solved by four good vendors.
- **An embedding model.** Commodity.
- **An application UI.** The proposal, legal, and pharma workflow vendors own their users; we are their feature.
- **A GRC platform.** Governance platforms collect evidence and cannot prove it. We are their evidence source, not their replacement.

---

## 11. Related documents

| Document | Purpose |
|---|---|
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Component, sequence, class, state, and deployment diagrams |
| [`USAGE.md`](USAGE.md) | How the four components are actually invoked |
| [`DISTRIBUTION.md`](DISTRIBUTION.md) | Licensing, repo split, growth loop |
| [`GLOSSARY.md`](GLOSSARY.md) | Terms of art |
| [`ECOSYSTEM.md`](ECOSYSTEM.md) | Who we ride on, who we feed, who acquires us |
| [`ROADMAP.md`](ROADMAP.md) | Phase 0 commit contract and what follows |
| [`PIVOT.md`](PIVOT.md) | What changed from ScaleDB v1 and the evidence behind it |
