# Sourcemark — How you actually use it

Four steps. Three of them are one line each. The fourth is done by someone who has never heard of us.

---

## 0. Install

```bash
pip install sourcemark          # Python
npm install -g @sourcemark/cli  # CLI + verifier
```

The verifier is a separate, dependency-light package on purpose. A recipient installs `@sourcemark/verify` and nothing else — see §4.

---

## 1. Anchor — one line in your existing ingest

You already parse, chunk, embed and insert. Add one call.

```python
from sourcemark import Anchor
from sourcemark.adapters import PgVector, Docling

anchor = Anchor(
    store=PgVector(conn),
    log="https://log.sourcemark.dev/2026",   # or your own Trillian
    keyring="kms://acme/sourcemark",
)

for doc in corpus:
    parsed = docling.convert(doc)              # already yours
    chunks = Docling.chunks(parsed)            # already yours
    embed_and_insert(chunks)                   # already yours
    anchor.commit(doc.version_id, chunks)      # ← the only new line
```

`commit()` derives a salt per chunk, commits to the text with HMAC, folds the chunks into a document tree and the documents into a corpus tree, submits that one root, and writes five metadata fields back beside your chunks. One migration, once:

```sql
ALTER TABLE chunks
  ADD COLUMN sm_leaf          bytea,   -- this chunk's leaf hash
  ADD COLUMN sm_doc_proof     jsonb,   -- index, size, path: chunk → doc_root
  ADD COLUMN sm_corpus_proof  jsonb,   -- index, size, path: document → corpus_root
  ADD COLUMN sm_log_entry     text,    -- the log entry that corpus root landed in
  ADD COLUMN sm_salt_ref      text;    -- KMS handle to the version key
```

That is the entire schema footprint. No new service, no new store.

Note what is *not* in that table: the salt. It is re-derived from the version key at emit time, which is what makes erasure a single key deletion rather than a scan over every row — and what stops a database dump from being an opening for every chunk in it.

---

## 2. Emit — wrap the retriever you already have

```python
from sourcemark import Emit

retriever = Emit(your_retriever, store=PgVector(conn))

results = retriever.search(
    "What is the escalation path for a Class II deviation?", k=5
)

for r in results:
    print(r.text)                       # unchanged — same ranking, same results
    r.receipt.save(f"receipt-{r.chunk_id}.cbor")
```

`Emit` does not re-rank, re-embed or filter. It reads back what `Anchor` wrote and signs it. Ranking behaviour is bit-identical to the retriever you passed in — that is a test in the suite, not a promise.

### Or via MCP, with no code at all

```json
{
  "mcpServers": {
    "sourcemark": {
      "command": "sourcemark",
      "args": ["mcp", "--store", "pgvector://localhost/corpus"]
    }
  }
}
```

Any MCP host — Claude Code, Claude Desktop, Cursor — now receives receipts inside the resource-link annotations it already parses. Nothing else to integrate.

---

## 3. The receipt travels

A receipt is a file. Attach it to the answer, put it in the review packet, email it to the contracting officer, hand it to the auditor, produce it in discovery.

This is the step that makes Sourcemark different from an audit log: **the evidence leaves the building.**

---

## 4. Anyone verifies — the whole point

The recipient has no account, no access to your systems, and no reason to trust you.

```console
$ sourcemark verify receipt.cbor --log-key public.pem --source SOP-114.pdf

  CUSTODY VERIFIED
  ├─ tree head signature  ok   log.sourcemark.dev/2026 · log_id sha256:9e7fffb0…b249
  ├─ entry covered        ok   log entry 4093 of tree_size 4096
  ├─ leaf reconstruction  ok   page 47, bbox [72,318,540,402]
  ├─ inclusion proof      ok   chunk → doc_root → corpus_root → signed root
  ├─ content binding      ok   HMAC over bytes re-read from SOP-114.pdf
  ├─ ordering             ok   committed 2026-03-14, answered 2026-09-02
  └─ source re-derivation ok   bytes 98211-98644 match SOP-114.pdf
```

The order is not cosmetic. [`spec/verification.md`](../spec/verification.md) §3 fixes it, first failure wins, so that two conforming verifiers handed the same broken receipt name the same culprit. Nothing downstream of a tree head runs before that tree head is established as trustworthy.

`--source` is what upgrades the run: without it the verifier needs `--text` and reports *verified against text you supplied*; with it, the content binding is recomputed over bytes re-read from the document itself. Those are different claims and the tool must not render them identically.

Auditors do not use a terminal. So the same verifier ships as WASM at `verify.sourcemark.dev` — drag the receipt and the PDF onto the page, get a verdict. Nothing uploads; the check runs in the tab. That page is the single most important surface we ship, because it is the one used by people who are not our customers.

---

## 5. The demo that explains the product in fifteen seconds

```console
$ sed -i 's/30 days/90 days/' SOP-114.pdf     # someone edits the source

$ sourcemark verify receipt.cbor --log-key public.pem --source SOP-114.pdf

  ✗ TAMPERED — content binding failed
      committed  sha256:2b57d02d…0122
      recomputed sha256:b18f4c07…772e

  The inclusion proof still folds. The tree head still verifies.
  Only the bytes changed — which is exactly what the receipt is for.

  The document you are holding is not the document that was cited.
```

Anchor a well-known public corpus, alter one source file, watch the verifier turn red. No slides.

---

## 6. What it does not change

- Your retrieval quality — `Emit` is a pass-through
- Your storage — five columns beside chunks you already store
- Your latency — one Ed25519 signature, under 2 ms p95; no network call on the query path
- Your privacy posture — a 32-byte root leaves the boundary, nothing else
- Your exit — stop calling `commit()` and everything keeps working. Existing receipts keep verifying forever, because they verify against a public log rather than against us.

---

## 7. Migration and rollback

**Adopting.** Anchor forward from today; backfill historical corpus segments in the background. Chunks that predate anchoring return an explicit `receipt_unavailable` with the reason and the remedy — never a stub that resembles a valid receipt.

**Leaving.** Drop the five columns. Retrieval is untouched. Receipts already issued remain verifiable by anyone, permanently, with no involvement from us or from you. A trust product whose artifacts die when the customer churns has not earned the word.
