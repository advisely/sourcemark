"""The pgvector adapter against a real Postgres.

Skips, loudly, when psycopg or a database is missing -- a test that silently
passes because it could not run is worse than no test, so the skip prints and
the reason is named.

    SOURCEMARK_TEST_DSN=postgresql:///sourcemark_test python3 -m sourcemark.tests.test_pgvector

The table it creates stands in for a customer's own chunk table: it has an id
and a text column and knows nothing about Sourcemark, which is the whole
claim being tested. Everything Sourcemark adds is additive, and the teardown
asserts that dropping it leaves the original table intact.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import hashlib
import os
import pathlib
import sys
import tempfile
import warnings

_passed, _failed = 0, 0


def check(label: str, condition: bool, detail: str = "") -> None:
    global _passed, _failed
    if condition:
        _passed += 1
        print(f"  pass  {label}" + (f"   {detail}" if detail else ""))
    else:
        _failed += 1
        print(f"  FAIL  {label}" + (f"   {detail}" if detail else ""))


def main() -> int:
    warnings.simplefilter("ignore")
    try:
        import psycopg
    except ImportError:
        print("  SKIP  psycopg is not installed; `pip install 'sourcemark[pgvector]'`")
        return 0

    dsn = os.environ.get("SOURCEMARK_TEST_DSN", "postgresql:///sourcemark_test")
    try:
        conn = psycopg.connect(dsn)
    except Exception as exc:  # noqa: BLE001 - any connection failure is a skip
        print(f"  SKIP  no database at {dsn}: {exc}")
        return 0

    from ..adapters.stores.pgvector import PgVector
    from ..anchor import Anchor
    from ..cbor import decode
    from ..crypto import (
        content_commitment, corpus_entry_data, document_leaf_hash, fold, log_leaf_hash,
    )
    from ..emit import Emit
    from ..keys import Ed25519Signer, LocalVersionKeys
    from ..log import InProcessLog
    from ..models import Chunk, Document

    print(f"Connected: {conn.execute('select version()').fetchone()[0].split(',')[0]}")

    with conn.cursor() as cur:
        cur.execute("DROP TABLE IF EXISTS chunks, sourcemark_versions, sourcemark_batches")
        cur.execute("""
            CREATE TABLE chunks (
              chunk_id  text PRIMARY KEY,
              text      text NOT NULL,
              embedding bytea
            )
        """)
    conn.commit()

    tmp = pathlib.Path(tempfile.mkdtemp())
    store = PgVector(conn, chunks_table="chunks", chunk_id_column="chunk_id", text_column="text")
    store.migrate()
    check("migrate() runs on a table that knows nothing about Sourcemark", True)

    with conn.cursor() as cur:
        cur.execute("""
            SELECT column_name FROM information_schema.columns
             WHERE table_name = 'chunks' ORDER BY ordinal_position
        """)
        columns = [r[0] for r in cur.fetchall()]
    check("the original columns are untouched",
          columns[:3] == ["chunk_id", "text", "embedding"], str(columns[:3]))
    check("exactly five columns were added", len(columns) == 8, f"{len(columns)} total")
    with conn.cursor() as cur:
        cur.execute("SELECT to_regclass('sourcemark_versions'), to_regclass('sourcemark_batches')")
        check("two side tables exist", all(cur.fetchone()))

    # A corpus the customer inserted themselves, before Sourcemark existed.
    N_DOCS, PER_DOC = 12, 40
    docs = []
    for d in range(N_DOCS):
        dv = f"dv_{d:04x}"
        document = Document(f"doc_{d:04x}", dv, f"s3://corpus/{d:04x}.pdf",
                            hashlib.sha256(f"file-{d}".encode()).digest())
        chunks = [
            Chunk(chunk_id=f"{dv}#c{i:03d}",
                  text=f"Document {d} paragraph {i}: deviations must be recorded.",
                  byte_range=(i * 400, i * 400 + 380), page=1 + i // 3,
                  bbox=(72, 100 + i, 540, 180 + i), paragraph=f"p-{i}")
            for i in range(PER_DOC)
        ]
        docs.append((document, chunks))
    with conn.cursor() as cur:
        cur.executemany("INSERT INTO chunks (chunk_id, text) VALUES (%s, %s)",
                        [(c.chunk_id, c.text) for _, cs in docs for c in cs])
    conn.commit()

    keys = LocalVersionKeys(tmp / "keys.json", quiet=True)
    log = InProcessLog(signer=Ed25519Signer.from_seed(b"pg-log"))
    issuer = Ed25519Signer.from_seed(b"pg-issuer")

    with Anchor(store=store, log=log, keys=keys, parser="docling@2.3.1",
                batch_documents=8) as anchor:
        for document, chunks in docs:
            anchor.commit(document, chunks)

    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM chunks WHERE sm_leaf IS NOT NULL")
        anchored = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM sourcemark_versions")
        versions = cur.fetchone()[0]
        cur.execute("SELECT count(*) FROM sourcemark_batches")
        batches = cur.fetchone()[0]
    check("every chunk was written back", anchored == N_DOCS * PER_DOC, f"{anchored} rows")
    check("one row per document version", versions == N_DOCS)
    check("the log proof is stored once per batch, not per chunk", batches == 2,
          f"{batches} batches for {anchored} chunks")

    print("\nRead back through the adapter and check the folds")
    target = docs[7][1][23]
    a = store.read(target.chunk_id)
    check("read() reconstructs an Anchoring", a is not None and a.chunk_id == target.chunk_id)
    check("coordinates survive the round trip",
          (a.page, a.bbox, a.byte_range, a.paragraph)
          == (target.page, tuple(target.bbox), tuple(target.byte_range), target.paragraph))
    check("chunk folds to doc_root",
          fold(a.leaf_hash, a.document_proof.leaf_index, a.document_proof.tree_size,
               a.document_proof.path) == a.document_proof.root)
    doc_leaf = document_leaf_hash(a.document.document_version_id,
                                  a.document_proof.root, a.document_proof.tree_size)
    check("document folds to corpus_root",
          fold(doc_leaf, a.corpus_proof.leaf_index, a.corpus_proof.tree_size,
               a.corpus_proof.path) == a.corpus_proof.root)
    check("recomputed log entry folds to the signed root",
          fold(log_leaf_hash(corpus_entry_data(a.corpus_proof.root, a.committed_at)),
               a.log_proof.leaf_index, a.log_proof.tree_size, a.log_proof.path)
          == a.log_proof.root_hash)

    print("\nEmit against the database")
    class PgRetriever:
        def search(self, query: str, k: int = 5):
            with conn.cursor() as cur:
                cur.execute("SELECT chunk_id, text FROM chunks ORDER BY chunk_id LIMIT %s", (k,))
                return [type("Row", (), {"chunk_id": r[0], "text": r[1]})() for r in cur.fetchall()]

    emit = Emit(PgRetriever(), store=store, keys=keys, signer=issuer,
                retriever_name="pgvector@0.8.1")
    results = emit.search("deviation", k=6)
    check("every result carries a receipt", all(r.receipt is not None for r in results),
          f"{sum(r.receipt is not None for r in results)}/{len(results)}")
    payload = decode(decode(results[0].receipt).value[2])["custody"]
    row_text = next(c.text for _, cs in docs for c in cs if c.chunk_id == results[0].chunk_id)
    check("the receipt's commitment binds the row's own text",
          content_commitment(payload["derivation"]["opening"]["salt"], row_text)
          == payload["derivation"]["content_commitment"])

    print("\nAn UPDATE straight into the table is caught at emit time")
    victim = results[0].chunk_id
    with conn.cursor() as cur:
        cur.execute("UPDATE chunks SET text = %s WHERE chunk_id = %s",
                    ("deviations may be recorded later", victim))
    conn.commit()
    emit.forget()
    after = emit.search("deviation", k=6)
    edited = next(r for r in after if r.chunk_id == victim)
    check("no receipt is issued over the edited row", edited.receipt is None)
    check("and the refusal names TEXT_MISMATCH",
          (edited.unavailable or {}).get("receipt_unavailable", {}).get("state") == "TEXT_MISMATCH")
    check("its neighbours are unaffected",
          all(r.receipt is not None for r in after if r.chunk_id != victim))

    print("\nLeaving takes one DROP and leaves retrieval untouched")
    with conn.cursor() as cur:
        cur.execute("""
            ALTER TABLE chunks
              DROP COLUMN sm_leaf, DROP COLUMN sm_commitment, DROP COLUMN sm_doc_proof,
              DROP COLUMN sm_dv, DROP COLUMN sm_location
        """)
        cur.execute("DROP TABLE sourcemark_versions, sourcemark_batches")
        cur.execute("SELECT count(*) FROM chunks")
        remaining = cur.fetchone()[0]
        cur.execute("""
            SELECT column_name FROM information_schema.columns
             WHERE table_name = 'chunks' ORDER BY ordinal_position
        """)
        left = [r[0] for r in cur.fetchall()]
    conn.commit()
    check("the customer's rows are all still there", remaining == N_DOCS * PER_DOC)
    check("and the table is exactly what it was", left == ["chunk_id", "text", "embedding"])

    with conn.cursor() as cur:
        cur.execute("DROP TABLE chunks")
    conn.commit()
    conn.close()

    print(f"\n{_passed} passed, {_failed} failed")
    return 1 if _failed else 0


if __name__ == "__main__":
    sys.exit(main())
