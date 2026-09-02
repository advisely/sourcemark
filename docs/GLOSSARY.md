# Glossary

Terms of art, in the sense Sourcemark uses them. Where a term has a looser meaning elsewhere, the difference is called out — the looseness is usually where a trust argument goes wrong.

---

### Anchor
The ingest-time component. Hashes each chunk with its coordinates, builds the Merkle tree, submits the root to the transparency log, and writes the proof back into the customer's own store. Also used as a verb: a chunk is *anchored* once its root is logged.

### Backdated
A verification outcome. The inclusion proof is structurally valid, but the log entry's timestamp is **later** than the answer it supposedly supports — the signature of a citation attached after the fact. Distinct from `FORGED`.

### Bind
The optional fourth component. Scores whether a generated sentence actually follows from the cited chunk. Produces a `SupportClass`, never a proof.

### Chunk
A retrieval unit derived from a document version — a paragraph, a section, a table segment, a bounded layout region. The thing that gets embedded, retrieved, and anchored.

### Coordinates
The location of a chunk inside its source: `page`, `paragraph`, `bbox`, `byte_range`. Produced by the parser, not by us. Coordinates are what make a receipt an answer to *"where exactly?"* rather than *"which file?"*

### Corpus root
The Merkle root over a batch of document roots, computed per batch window. The **only** value ever submitted to the transparency log. Thirty-two bytes, from which nothing can be reconstructed.

### Custody
Layer 1 of a receipt. The claim that a piece of text is byte-identical to what was ingested from a given source at given coordinates, committed at a given time. **Cryptographic and binary.** Mandatory in every receipt.

### Cryptographic erasure
Satisfying a deletion obligation by destroying a key rather than a record. Leaves commit to `H(salt ‖ text)`; destroying the salt makes the leaf unopenable while the Merkle tree stays intact. Resolves the conflict between right-to-erasure and tamper-evidence without rewriting history. See `SPEC.md §7`.

### Document version
An immutable, content-addressed ingestion of a source document. Re-ingesting a changed file creates a new version rather than overwriting the old one — the property most retrieval stacks lack, and the reason "which version?" is normally unanswerable.

### Emit
The query-time component. Wraps an existing retriever, reads back what Anchor wrote, and assembles and signs the receipt. Does **not** re-rank, re-embed or filter; ranking is bit-identical to the wrapped retriever.

### Erased
A verification outcome, and deliberately not a failure. The salt was destroyed under an erasure request; the tree is intact and unmodified. Distinct from `INVALID`, which would imply someone tampered.

### Forged
A verification outcome. The inclusion path does not fold to the claimed corpus root — the receipt asserts membership in a tree that does not contain it. Points at the receipt issuer.

### Inclusion path
The sibling hashes needed to fold a leaf up to the corpus root. About twenty hashes at a million chunks, since the count is logarithmic. Stored beside the chunk in the customer's store, not held by us.

### Leaf
The Merkle tree's bottom node for one chunk: `H(ids ‖ coordinates ‖ H(salt ‖ text))`. Binding the coordinates *into* the leaf is what prevents a valid proof being replayed against a different location in the same document.

### Proof bundle
The v1 term for what is now called a **receipt**. Retained only in `PIVOT.md`. The rename is not cosmetic: "bundle" described a container, "receipt" describes an artifact that travels to someone else.

### Receipt
The signed object returned alongside a retrieved chunk. Carries `custody` (mandatory), `support` (optional), and `context`. Canonical form is COSE-signed CBOR, profiled as a C2PA assertion for unstructured text.

### `receipt_unavailable`
The explicit response when a result cannot carry a receipt — with a machine-readable reason and a remedy. Never a stub that resembles a valid receipt. An absence of evidence must never be renderable as evidence.

### Salt
A per-document-version random value held in the customer's KMS. Leaves commit to salted text hashes, which keeps content out of the log and makes cryptographic erasure possible.

### Signed tree head · STH
The log's signed statement of its root and size at a point in time. Published, and verifiable with a public key alone. The anchor of trust the whole scheme reduces to.

### Support
Layer 2 of a receipt. The claim that a generated sentence follows from the cited chunk. **Statistical and scored.** Optional, and always carries `proven: false`.

### SupportClass
`QUOTED` · `SUPPORTED` · `INFERRED` · `UNSUPPORTED`. Only `QUOTED` — a verbatim substring match — is decided rather than estimated.

### Tampered
A verification outcome. The content hash does not match; the document being held is not the document that was cited. Points at the storage layer or at whoever handled the file since.

### Transparency log
An append-only, tamper-evident log in the RFC 6962 lineage — the same construction behind Certificate Transparency. Trillian, `transparency.dev`, or Sigstore's Rekor. Holds only roots.

### Tree size
The number of entries in the log when a given root was published. Together with the root, it lets a verifier check consistency against any later signed tree head.

### Verify
The offline verifier, and the point of the exercise. Open source, dependency-light, no network calls. Ships as CLI, WASM and a GitHub Action. If it required contacting us, the product would prove nothing.

---

## Terms deliberately not used

| Avoided | Why |
|---|---|
| "Proves the answer is correct" | Custody proves origin. Nothing here proves a conclusion. |
| "Trusted retrieval" | The design goal is the removal of trust, not its assertion. |
| "Immutable database" | No database is immutable. A log is append-only and *tamper-evident*, which is a weaker and honest claim. |
| "Blockchain" | An RFC 6962 log is not one, needs no consensus, and no token. |
| "Hallucination-proof" | Signing a hallucination produces a signed hallucination. |
