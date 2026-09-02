# Sourcemark

**Makes an AI answer's citation into evidence.**

When your retrieval system returns a chunk of text, Sourcemark returns a signed receipt alongside it — proving that this exact text came from that exact place (page, paragraph, bounding box, byte range) in that exact version of that document, and that the commitment was made *before* the answer was generated.

Anyone can check that receipt offline. No account, no network call to us, no trust in us. The verifier is open source and keeps working if this company disappears.

```
$ sourcemark verify receipt.cbor --log-key public.pem --source SOP-114.pdf

  CUSTODY VERIFIED
  ├─ tree head signature  ok   log.sourcemark.dev/2026 · log_id sha256:9e7fffb0…b249
  ├─ entry covered        ok   log entry 4093 of tree_size 4096
  ├─ leaf reconstruction  ok   page 47, bbox [72,318,540,402]
  ├─ inclusion proof      ok   chunk → doc_root → corpus_root → signed root
  ├─ content binding      ok   HMAC over bytes re-read from SOP-114.pdf
  ├─ ordering             ok   committed 2026-03-14, answered 2026-09-02
  └─ source re-derivation ok   bytes 98211-98644 match SOP-114.pdf

  SUPPORT  SUPPORTED (0.91, bge-reranker-v2@1.0)   proven: false — statistical estimate
```

---

## It is not a database

Sourcemark stores no documents, serves no queries, and owns no data plane. It rides on the retrieval stack you already run — Postgres/pgvector, Qdrant, Weaviate, Elasticsearch, MongoDB Atlas, Azure AI Search. Your content never leaves your boundary; the only thing that leaves is a 32-byte Merkle root.

It doesn't parse documents either. It consumes the coordinates Docling, Reducto, Unstructured, LlamaParse and Azure Document Intelligence already produce.

Everything on that list is a partner. See [`docs/ECOSYSTEM.md`](docs/ECOSYSTEM.md).

---

## The one idea

A receipt carries two claims, and they are never collapsed:

| | **Custody** | **Support** |
|---|---|---|
| Claim | This text is byte-identical to what was ingested from that source at those coordinates | This sentence follows from that text |
| Nature | Cryptographic | Statistical |
| Result | Binary — true or false | A score against a threshold |
| Verifiable by | Anyone, offline, forever | Only reproducibly, same scorer and version |
| Field | `custody` | `support`, with `proven: false` |

Every receipt product surveyed signs the model's *output* and lets the buyer infer the output is trustworthy. Signing a hallucination produces a cryptographically impeccable hallucination. Sourcemark refuses that inference in the data model: a receipt whose custody verifies and whose support is `UNSUPPORTED` is a correctly functioning receipt reporting a failed answer.

---

## Documents

| Document | Purpose |
|---|---|
| [`docs/SPEC.md`](docs/SPEC.md) | Canonical specification — components, receipt format, threat model, erasure |
| [`docs/USAGE.md`](docs/USAGE.md) | How you actually use it — four steps, three of them one line |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Component, sequence, class, state and deployment diagrams |
| [`docs/ECOSYSTEM.md`](docs/ECOSYSTEM.md) | Who we ride on, who we feed, who acquires us |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Phase 0 commit contract — 8 weeks, one gate |
| [`docs/DISTRIBUTION.md`](docs/DISTRIBUTION.md) | Licensing, public/private repo split, and the growth loop |
| [`docs/GLOSSARY.md`](docs/GLOSSARY.md) | Terms of art — custody, leaf, inclusion path, tree head |
| [`docs/PIVOT.md`](docs/PIVOT.md) | What changed from ScaleDB v1, and the evidence |

The ScaleDB v1 document set was removed from the working tree during the restructure and is retained
in the private repository of record. [`docs/PIVOT.md`](docs/PIVOT.md) records what it got right and
where it went wrong.

---

## Repository layout

```
spec/          Receipt schema, C2PA assertion profile, canonical serialization   CC0
conformance/   Test vectors any independent implementer runs                     CC0
sourcemark/    Anchor, Emit, store and parser adapters                           Apache-2.0
mcp/           MCP server — receipts via resource-link annotations               Apache-2.0
docs/          Specification and supporting documents
```

Each directory carries a README naming its Phase 0 deliverable and acceptance criterion.

This repository is **derived**. It is generated from a private repository of record by an
allowlist and an audit that fails closed, and its history begins here — see
[`docs/DISTRIBUTION.md`](docs/DISTRIBUTION.md) §3. Send pull requests here; they are merged upstream.

**The verifier lives in its own repository:** [`advisely/sourcemark-verify`](https://github.com/advisely/sourcemark-verify), Apache-2.0.
It is split out so that its history, releases and dependency list are its own — the artifact whose
pitch is *"you do not have to trust the issuer"* should not require trusting a monorepo it shares
with the issuer's own tooling. The separation also makes this repository's acceptance criterion
structural rather than aspirational: a second implementer must be able to write a verifier from
`spec/` alone, and now literally cannot read ours by accident.

Nothing technical is private — see [`docs/DISTRIBUTION.md`](docs/DISTRIBUTION.md) §3.

---

## Status

Draft specification. Phase 0 not started. Looking for one design partner with a real regulated corpus and a real auditor.

The Phase 0 gate is a single test: *a person with no access to our code, our infrastructure or our design partner's systems is handed an answer, a receipt and the original PDF, and determines offline in under a minute that the cited text is genuinely at page 47 and that the commitment predates the answer.*

**Contact:** yassine@boumiza.com

---

*"Sourcemark" is a working name and appears as a single token throughout. Swap it if a better one lands.*
