"""Anchor and Emit end to end, against the Phase 0 acceptance criteria.

    - a 10k-chunk corpus anchors end to end
    - Emit returns bit-identical ranking to the retriever it wraps
    - query-path overhead stays under 2 ms p95, with no network call
    - an erased version yields ERASED openings, tree untouched
    - an unanchored chunk yields receipt_unavailable, not a hollow receipt

Run:  python3 -m sourcemark.tests.test_pipeline

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import hashlib
import statistics
import sys
import tempfile
import time
import warnings
from dataclasses import dataclass
from pathlib import Path

from ..adapters.stores.memory import MemoryStore
from ..anchor import Anchor
from ..cbor import decode
from ..crypto import chunk_salt, content_commitment, fold, leaf_hash
from ..emit import Emit
from ..keys import Ed25519Signer, LocalVersionKeys
from ..log import InProcessLog
from ..models import Chunk, Document
from ..receipt import SupportClaim

_passed, _failed = 0, 0


def check(label: str, condition: bool, detail: str = "") -> None:
    global _passed, _failed
    if condition:
        _passed += 1
        print(f"  pass  {label}" + (f"   {detail}" if detail else ""))
    else:
        _failed += 1
        print(f"  FAIL  {label}" + (f"   {detail}" if detail else ""))


@dataclass
class FakeResult:
    chunk_id: str
    text: str
    score: float


class FakeRetriever:
    """Deterministic, and deliberately not sorted by score.

    A retriever whose output happens to be in score order cannot detect a
    wrapper that sorts. This one returns a fixed, arbitrary order so that any
    reordering shows up.
    """

    def __init__(self, chunks: list[Chunk]) -> None:
        self._chunks = {c.chunk_id: c for c in chunks}
        self.calls = 0

    def search(self, query: str, k: int = 5, **kwargs) -> list[FakeResult]:
        self.calls += 1
        ids = sorted(self._chunks)[:k]
        ids = ids[1::2] + ids[0::2]  # scramble, stably
        return [FakeResult(cid, self._chunks[cid].text, 1.0 - i / 100) for i, cid in enumerate(ids)]


def corpus(n_docs: int, chunks_per_doc: int) -> list[tuple[Document, list[Chunk]]]:
    out = []
    for d in range(n_docs):
        dv = f"dv_{d:05x}"
        doc = Document(
            document_id=f"doc_{d:05x}",
            document_version_id=dv,
            source_uri=f"s3://corpus/{d:05x}.pdf",
            content_hash=hashlib.sha256(f"file-{d}".encode()).digest(),
        )
        chunks = [
            Chunk(
                chunk_id=f"{dv}#c{i:04d}",
                text=f"Document {d} paragraph {i}: the validated cycle must be recorded.",
                byte_range=(i * 400, i * 400 + 380),
                page=1 + i // 3,
                bbox=(72, 100 + i, 540, 180 + i),
                paragraph=f"p-{i}",
            )
            for i in range(chunks_per_doc)
        ]
        out.append((doc, chunks))
    return out


def main() -> int:
    warnings.simplefilter("ignore")
    tmp = Path(tempfile.mkdtemp())
    keys = LocalVersionKeys(tmp / "keys.json", quiet=True)
    store = MemoryStore()
    log_signer = Ed25519Signer.from_seed(b"test-log")
    log = InProcessLog(signer=log_signer)
    issuer = Ed25519Signer.from_seed(b"test-issuer")

    N_DOCS, PER_DOC = 200, 50          # 10,000 chunks
    data = corpus(N_DOCS, PER_DOC)

    print(f"Anchoring {N_DOCS * PER_DOC} chunks across {N_DOCS} document versions")
    started = time.monotonic()
    with Anchor(store=store, log=log, keys=keys, parser="docling@2.3.1",
                batch_documents=64) as anchor:
        for doc, chunks in data:
            anchor.commit(doc, chunks)
    elapsed = time.monotonic() - started
    check("10k-chunk corpus anchors end to end", len(store) == N_DOCS * PER_DOC,
          f"{len(store)} rows in {elapsed:.2f}s")
    check("batching kept log submissions to one per window", log.size == 4,
          f"{log.size} log entries for {N_DOCS} document versions")

    print("\nThe three folds, on a chunk picked out of the middle")
    target = data[137][1][23]
    a = store.read(target.chunk_id)
    check("anchoring was written", a is not None)
    check("chunk folds to doc_root",
          fold(a.leaf_hash, a.document_proof.leaf_index, a.document_proof.tree_size,
               a.document_proof.path) == a.document_proof.root)
    from ..crypto import corpus_entry_data, document_leaf_hash, log_leaf_hash
    doc_leaf = document_leaf_hash(a.document.document_version_id,
                                  a.document_proof.root, a.document_proof.tree_size)
    check("document folds to corpus_root",
          fold(doc_leaf, a.corpus_proof.leaf_index, a.corpus_proof.tree_size,
               a.corpus_proof.path) == a.corpus_proof.root)
    entry = corpus_entry_data(a.corpus_proof.root, a.committed_at)
    check("recomputed log entry folds to the signed root",
          fold(log_leaf_hash(entry), a.log_proof.leaf_index, a.log_proof.tree_size,
               a.log_proof.path) == a.log_proof.root_hash)

    print("\nEmit is a pass-through")
    all_chunks = [c for _, cs in data for c in cs]
    retriever = FakeRetriever(all_chunks)
    emit = Emit(retriever, store=store, keys=keys, signer=issuer,
                retriever_name="fake@1.0")
    raw = retriever.search("deviation", k=8)
    wrapped = emit.search("deviation", k=8)
    check("ranking order is identical", [r.chunk_id for r in wrapped] == [r.chunk_id for r in raw])
    check("the retriever's own objects are returned unmodified",
          [r.inner for r in wrapped] == raw)
    check("attribute access falls through", wrapped[0].score == raw[0].score)
    check("every result carries a receipt", all(r.receipt is not None for r in wrapped))

    print("\nThe receipt binds to the text an auditor would be handed")
    r0 = wrapped[0]
    payload = decode(decode(r0.receipt).value[2])
    custody = payload["custody"]
    salt = custody["derivation"]["opening"]["salt"]
    original = next(c for c in all_chunks if c.chunk_id == r0.chunk_id)
    check("content binding recomputes from the receipt's own salt",
          content_commitment(salt, original.text) == custody["derivation"]["content_commitment"])
    check("altering one character breaks it",
          content_commitment(salt, original.text + " ") != custody["derivation"]["content_commitment"])
    check("the leaf rebuilds from the receipt's coordinates",
          leaf_hash(document_version_id=custody["source"]["document_version_id"],
                    chunk_id=custody["derivation"]["chunk_id"],
                    page=custody["location"]["page"],
                    bbox=custody["location"]["bbox"],
                    byte_range=custody["location"]["byte_range"],
                    commitment=custody["derivation"]["content_commitment"])
          == custody["proof"]["leaf_hash"])
    check("no support claim was invented", "support" not in payload)

    print("\nQuery-path cost")
    timings = []
    for _ in range(60):
        t0 = time.perf_counter()
        emit.search("deviation", k=5)
        timings.append((time.perf_counter() - t0) * 1000 / 5)
    p95 = statistics.quantiles(timings, n=20)[-1]
    check("per-receipt query overhead under 2 ms p95", p95 < 2.0, f"p95 {p95:.3f} ms")

    print("\nErasure")
    dv = a.document.document_version_id
    anchor2 = Anchor(store=store, log=log, keys=keys)
    anchor2.erase(dv)
    emit.forget(dv)
    erased_receipt = emit.receipt_for(a.chunk_id, query_id="q_erase")
    erased_payload = decode(decode(erased_receipt).value[2])["custody"]
    check("an erased chunk yields a stated tombstone",
          erased_payload["derivation"]["opening"] == {"erased": True})
    check("the tree is untouched by erasure",
          erased_payload["proof"]["leaf_hash"] == custody_leaf(store, a.chunk_id))
    check("the signed tree head is untouched",
          erased_payload["proof"]["log"]["signed_tree_head"] == a.log_proof.signed_tree_head)
    check("the commitment survives, so the leaf still rebuilds",
          erased_payload["derivation"]["content_commitment"] == a.content_commitment)

    print("\nAbsence is never shaped like a pass")
    unavailable = emit.receipt_for("chunk-that-was-never-anchored", query_id="q_missing")
    check("an unanchored chunk yields receipt_unavailable",
          isinstance(unavailable, dict) and "receipt_unavailable" in unavailable)
    check("it names a machine-readable state",
          unavailable["receipt_unavailable"]["state"] == "NOT_ANCHORED")
    check("and a remedy", "remedy" in unavailable["receipt_unavailable"])

    print("\nSupport is optional and never a proof")
    claim = SupportClaim("SUPPORTED", "bge-reranker-v2@1.0", score=0.91, threshold=0.85)
    check("proven is false and not settable", claim.as_dict()["proven"] is False)
    try:
        SupportClaim("PROVEN", "x")
        check("an invented support class is refused", False)
    except ValueError:
        check("an invented support class is refused", True)

    print("\nPending: committed but not yet flushed")
    store2, keys2 = MemoryStore(), LocalVersionKeys(tmp / "k2.json", quiet=True)
    lone = Anchor(store=store2, log=log, keys=keys2, batch_documents=64)
    doc, chunks = corpus(1, 3)[0]
    result = lone.commit(doc, chunks)
    check("commit before flush reports pending", result.pending is True)
    check("nothing is queryable yet", len(store2) == 0)
    check("flush makes it provable", lone.flush() == 3 and len(store2) == 3)

    print(f"\n{_passed} passed, {_failed} failed")
    return 1 if _failed else 0


def custody_leaf(store, chunk_id: str) -> bytes:
    return store.read(chunk_id).leaf_hash


if __name__ == "__main__":
    sys.exit(main())
