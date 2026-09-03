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

**Per chunk, derive a salt, commit to the text, and build a leaf:**

```
salt       = HKDF-Expand(version_key, CBOR(["sourcemark.salt.v1", dv_id, chunk_id]), 32)
commitment = HMAC-SHA-256(key = salt, message = utf8(chunk_text))
leaf       = SHA-256(0x00 ‖ CBOR(["sourcemark.leaf.v1", dv_id, chunk_id,
                                  page, bbox, byte_range, commitment]))
```

Three choices there are load-bearing. [`spec/canonicalization.md`](../spec/canonicalization.md) clause 3 is normative for all of them and argues each at the point it is made.

- **HMAC rather than `H(salt ‖ chunk_text)`.** SHA-256 is length-extendable. Given one published commitment and its length, a forger can extend it to cover text nobody ingested — without ever learning the salt. HMAC is not susceptible and costs the same.
- **A CBOR array rather than concatenation.** Joining variable-length fields destroys their boundaries: `("dv_c3e2881", "chk_88a1c")` and `("dv_c3e28", "81chk_88a1c")` flatten to identical bytes, and so to an identical leaf. CBOR makes every boundary explicit for about one byte per field.
- **One salt per chunk rather than one per document version.** A receipt discloses its own chunk's salt (§4.3), so a per-version salt would open every other chunk in that document version. Because the salt is *derived* rather than stored, per-chunk costs nothing but one HMAC at ingest.

**Per document version, build a Merkle tree** over its chunk leaves → `doc_root`.
**Per batch window, build a corpus tree** over document leaves → `corpus_root`.
**Submit `corpus_root`** to an RFC 6962 transparency log (customer-hosted Trillian, Sigstore Rekor, or a Sourcemark-operated public log). Nothing else is submitted.

The log then folds that submission into a tree of its own, and *that* tree is what a signed tree head covers. A receipt therefore carries **three inclusion proofs, not one**:

```
chunk leaf  ──document path──▶  doc_root
doc leaf    ──corpus path  ──▶  corpus_root
log leaf    ──log path     ──▶  root_hash, signed by the tree head
```

Stopping after two folds would leave `corpus_root` unattached to anything anybody signed — which is the whole reason it was submitted.

**Write back** into the customer's own store, as ordinary metadata alongside the chunk: `leaf_hash`, the document and corpus paths with their tree sizes, `log_entry_id`, and `salt_ref` — the KMS handle of the **version key**, not of the salt. Roughly 300–600 bytes per chunk, in columns the store already supports.

The per-chunk salt is never stored. It is re-derived from the version key at emit time, which is precisely why destroying that one key erases every chunk in the version at once — see §7.

### 4.2 Emit — sign at query time

A thin wrapper around the customer's retriever. It does not re-rank, re-embed, or otherwise touch retrieval quality; it reads the metadata Anchor wrote and assembles a receipt.

Delivered three ways, all from the same code path:
- **SDK** — the receipt is a field on the result object
- **HTTP** — a `Sourcemark-Receipt` header or an envelope field
- **MCP** — carried in the resource-link annotations that MCP already defines for provenance metadata, so any MCP host gets receipts without integrating anything

### 4.3 Verify — check offline

```
sourcemark verify receipt.cbor --log-key public.pem --text chunk.txt [--source original.pdf]
```

Six checks, all local, run **in a fixed order in which the first failure is the answer**. That order is normative — [`spec/verification.md`](../spec/verification.md) §3 pins it so that two conforming verifiers handed the same broken receipt report the same failure rather than two defensible ones.

| # | Check | Verdict on failure |
|---|---|---|
| 0 | Parse strictly; reject anything outside the canonical encoding profile | `MALFORMED` |
| 1 | The supplied key hashes to `log_id`; the tree head's signature verifies | `UNSIGNED` |
| 2 | The entry index falls inside this tree head's tree size | `PENDING` |
| 3 | Rebuild the leaf; fold all three paths through to the signed root | `FORGED` |
| 4 | Recompute `HMAC-SHA-256(salt, chunk_text)`; compare to the commitment | `TAMPERED`, or `ERASED` |
| 5 | The commitment's timestamp precedes the answer's | `BACKDATED` |
| — | everything passed | `VERIFIED` |

`MALFORMED` sits deliberately outside the seven outcomes of [`ARCHITECTURE.md` §7](ARCHITECTURE.md), which describe verification of a *well-formed* receipt. Reporting `FORGED` for a truncated download would label a network failure an attack.

Two properties of that table are the ones to argue about.

**`--text` is required, not optional.** Without the cited text, check 4 cannot run, and everything remaining proves only that *some* leaf is in the tree — not that it is the leaf backing the sentence the auditor is reading. A verifier handed no text must refuse by name rather than downgrade, because a weaker verdict rendered in a terminal is read as a pass.

**The salt travels in the receipt.** The launch gate hands a stranger an answer, a receipt and a PDF, offline. That stranger has no KMS access, so a receipt carrying only `salt_ref` would make check 4 — the only check binding the proof to actual text — unrunnable by the exact party the format exists to serve.

With `--source`, a further check re-derives the chunk from the original file at the recorded byte range, confirms byte identity, and runs check 4 against *those* bytes rather than against text handed in on the command line. This is the check an auditor actually wants: *the document I am holding contains this text at this location, and your system committed to that before it answered.* A verifier must report which of the two it performed; "verified against text you supplied" and "verified against the document itself" are different claims.

Ships as a static CLI binary, a WASM module for in-browser verification, and a GitHub Action, out of [`advisely/sourcemark-verify`](https://github.com/advisely/sourcemark-verify) — a separate repository so that "a second implementer can write this from `spec/` alone" is a boundary rather than a promise.

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

**This section is illustrative. [`spec/`](../spec/) is normative** — [`receipt.cddl`](../spec/receipt.cddl) for the shape, [`canonicalization.md`](../spec/canonicalization.md) for the bytes. Both are needed and neither is sufficient: a schema says which fields exist, not what a verifier hashes, and two implementations can satisfy the grammar while disagreeing on every digest in the receipt.

Canonical form is **COSE_Sign1 over deterministic CBOR** (RFC 9052 §4.2, RFC 8949 §4.2.1), profiled as a **C2PA assertion for unstructured text** (C2PA v2.3, December 2025, which added manifests for unstructured text specifically to cover LLM outputs). Emitting a C2PA manifest rather than a bespoke envelope means existing C2PA verifiers already parse the outer structure. We define an assertion, not a format.

A JSON projection exists for debugging and human reading; the CBOR is normative and is what gets signed. The projection is lossy in one direction that matters: timestamps are **integer milliseconds** in CBOR and RFC 3339 strings here. The ordering check in §4.3 is the most security-critical comparison in the system, and making it an integer comparison removes timezone offsets, leap seconds, variable fractional precision, and the entire surface on which two verifiers can disagree about which of two instants came first.

```json
{
  "receipt_version": "0.1",
  "kind": "sourcemark.retrieval.receipt",
  "custody": {
    "source": {
      "document_id": "doc_2f8a91e",
      "document_version_id": "dv_c3e2881",
      "source_uri": "s3://policies/2026/SOP-114.pdf",
      "content_hash": "sha256:648b79dd…ea7c",
      "committed_at": "2026-03-14T09:22:11.000Z"
    },
    "location": {
      "page": 47,
      "paragraph": "p-14",
      "bbox": [
        72,
        318,
        540,
        402
      ],
      "byte_range": [
        98211,
        98644
      ]
    },
    "derivation": {
      "chunk_id": "chk_88a1c",
      "parser": "docling@2.3.1",
      "salt_ref": "kms://tenant-acme/salt/dv_c3e2881",
      "content_commitment": "sha256:2b57d02d…0122",
      "opening": {
        "salt": "base16:c92ab309…e8c9"
      }
    },
    "proof": {
      "leaf_hash": "sha256:c5222dc9…cff3",
      "document": {
        "leaf_index": 7,
        "tree_size": 12,
        "path": [
          "sha256:6cee2da4…49d8",
          "sha256:70173645…9ae4",
          "… 2 more"
        ],
        "doc_root": "sha256:89f5f845…3dce"
      },
      "corpus": {
        "leaf_index": 2,
        "tree_size": 5,
        "path": [
          "sha256:137bb5aa…5fe5",
          "sha256:9b918739…4f22",
          "… 1 more"
        ],
        "corpus_root": "sha256:3644bc90…9f92"
      },
      "log": {
        "url": "https://log.sourcemark.dev/2026",
        "log_id": "sha256:9e7fffb0…b249",
        "entry_profile": "sourcemark.corpus.v1",
        "entry_id": "0x3f21a5c0",
        "leaf_index": 4093,
        "tree_size": 4096,
        "path": [
          "sha256:2fd1b1dc…a86b",
          "sha256:c9df390d…092a",
          "… 10 more"
        ],
        "root_hash": "sha256:7dbb00eb…75c0",
        "signed_tree_head": "base16:d2844da2…5e09"
      }
    }
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
    "retrieved_at": "2026-09-02T14:02:44.000Z",
    "policy_ref": "pol_dec_4421"
  }
}
```

Every value above is real, taken from [`spec/examples/receipt.json`](../spec/examples/receipt.json) and abbreviated for reading. That file and its CBOR sibling regenerate byte-for-byte from `spec/examples/build.py`, and `spec/examples/derivation.txt` records every intermediate value from chunk text to signature.

Three fields carry more weight than their size suggests.

**`derivation.opening`** is a two-branch union — `{salt}` or `{erased: true}` — not an optional `salt`. With an optional field, "this chunk was erased" and "the emitter forgot to include the salt" are the same bytes, and §3's fifth principle forbids a missing thing from resembling a passing one. A tombstone has to be stated.

**`proof`** carries three folds, not one path. `document` reaches `doc_root`, `corpus` reaches `corpus_root`, and `log` reaches a root that a tree head actually signed. Note what `log` does *not* contain: the bytes hashed into the log leaf. A verifier recomputes those from `corpus_root` and `committed_at`, because a receipt that supplies them is supplying an input to the check that is meant to constrain it.

**`support.proven`** is typed as the literal `false`, not as a boolean. A schema permitting `true` permits a structurally valid receipt asserting that a statistical score is a proof. Making that case ungrammatical enforces the honesty constraint in §5 at the parser rather than at code review.

### 6.1 When a receipt cannot be issued

```json
{ "receipt_unavailable": {
    "reason": "chunk predates anchoring (ingested 2025-11-02, anchoring enabled 2026-01-15)",
    "remedy": "re-anchor corpus segment 'legacy-sops'",
    "state": "NOT_ANCHORED"
} }
```

Never silent, never a stub that resembles a valid receipt. `state` is drawn from a closed set so a caller can branch on it without parsing `reason`, which is prose for a human. The test for whether a condition earns its own name is whether it needs a different response:

| `state` | Meaning | What the caller should do |
|---|---|---|
| `PENDING` | Anchored, not yet inside a logged root | Retry shortly |
| `NOT_ANCHORED` | No anchoring record for this chunk | Re-anchor that corpus segment |
| `ERASED` | The version key was destroyed | Nothing — terminal, and correct |
| `LOG_UNREACHABLE` | The log could not be reached | Retry; nothing is broken |
| `TEXT_MISMATCH` | The retrieved text is not what was anchored | Investigate the store — retrying will keep refusing |
| `KEY_UNAVAILABLE` | The version key is absent but **not** erased | Fix the KMS access, then retry |

The last two are worth their own names. `TEXT_MISMATCH` is the emitter refusing to sign a receipt over text that has drifted from what was committed: the receipt would be internally valid and would verify as `TAMPERED` at an auditor's desk months later, blaming the wrong party. The emitter knows at query time, so it says so at query time. `KEY_UNAVAILABLE` is separated from `ERASED` because `ERASED` is a correct terminal state and a missing key is an outage — collapsing them would let a KMS misconfiguration be reported to a regulator as a completed deletion.

---

## 7. Erasure vs. immutability

A tamper-evident log and a right-to-erasure obligation are in direct conflict, and the conflict is the first thing a privacy officer will raise. Handling it is a requirement, not an extension.

**Mechanism: cryptographic erasure by destroying a per-version key.**

Each document version gets a 32-byte **version key** held in the customer's KMS and identified in the receipt by `salt_ref`. Every chunk's salt is derived from it by HKDF (§4.1); leaves commit to `HMAC-SHA-256(salt, chunk_text)`, never to the text itself. The version key never appears in a receipt.

On an erasure request, the version key is destroyed. Consequences:

- The Merkle tree is **unchanged** — history stays intact, prior receipts still fold to the same roots, and no gap appears in the log
- No new opening can be produced for any chunk in that version, because the salts are no longer derivable
- Verification of that chunk returns `ERASED`, a distinct outcome from a custody failure — the proof still verifies, the content simply cannot be shown

`spec/examples/receipt-erased.cbor` is the worked example after erasure. Its `leaf_hash`, all three paths, both roots and the signed tree head are byte-identical to the live receipt. Only the opening differs.

This satisfies the regulator's "the data is destroyed" and the auditor's "the log was not rewritten" simultaneously. The log holds only roots and salted digests; it never held content to begin with.

**What erasure does not do, stated plainly:** it does not reach into receipts already issued and handed to third parties. Those carry their own opening and stay openable by whoever holds them. Erasure prevents *future* openings and leaves the log itself revealing nothing. Per-chunk derivation is what confines an already-issued opening to its one chunk instead of its whole document version.

That limitation is real, and any material describing this property must state it. Describing cryptographic erasure as retroactive would be false, and false in the direction a privacy officer is specifically checking for.

---

## 8. Threat model

| Threat | Control | Component |
|---|---|---|
| Source altered after ingestion | Content hash in receipt; `--source` re-derivation fails | Verify |
| Citation fabricated post-hoc | Log entry timestamp precedes answer timestamp; ordering check | Verify |
| Vendor backdates a commitment | Append-only log with published signed tree heads; consistency proofs across STHs | Log |
| Vendor issues a receipt for text never ingested | Inclusion proof cannot be forged without the log's signing key | Verify |
| Commitment extended to cover text never ingested | HMAC-SHA-256, not `H(salt ‖ text)`; length extension does not apply | Anchor |
| Two different chunks made to share one leaf | CBOR-array preimage; every field boundary explicit in the bytes | Anchor |
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
| [`spec/`](../spec/) | **Normative.** The CDDL, the canonical encoding, and the verification procedure |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Component, sequence, class, state, and deployment diagrams |
| [`USAGE.md`](USAGE.md) | How the four components are actually invoked |
| [`DISTRIBUTION.md`](DISTRIBUTION.md) | Licensing, repo split, growth loop |
| [`GLOSSARY.md`](GLOSSARY.md) | Terms of art |
| [`ECOSYSTEM.md`](ECOSYSTEM.md) | Who we ride on, who we feed, who acquires us |
| [`ROADMAP.md`](ROADMAP.md) | Phase 0 commit contract and what follows |
| [`PIVOT.md`](PIVOT.md) | What changed from ScaleDB v1 and the evidence behind it |
