"""pgvector / Postgres AnchorStore.

Five columns beside the chunks you already store, plus two small side tables.
The side tables are not a compromise on the "five columns" promise, they are
what makes it true.

A log proof -- a signed tree head plus a path of ~20 digests -- is identical
for every chunk in a batch, and a corpus proof is identical for every chunk
in a document version. Denormalizing them onto the chunk row would cost
roughly 900 bytes per chunk of exact duplicates and put the per-chunk
overhead an order of magnitude above the 300-600 bytes `docs/SPEC.md` claims.
Storing each proof at the level it actually varies keeps the claim honest:

    chunks                  per chunk       leaf, commitment, document path
    sourcemark_versions     per doc version corpus path, salt_ref, source
    sourcemark_batches      per batch       log proof, signed tree head

The migration is additive. There is no rewrite of your chunk table, no new
index, and dropping the five columns and two tables removes Sourcemark
completely -- receipts already issued keep verifying, because they verify
against a public log rather than against this database.

psycopg is imported lazily, so `import sourcemark` costs nothing on a machine
that never talks to Postgres.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import json
from typing import Any, Iterable

from ...models import Anchoring, Document, LogProof, MerkleProof

__all__ = ["PgVector", "MIGRATION"]

MIGRATION = """
ALTER TABLE {chunks}
  ADD COLUMN IF NOT EXISTS sm_leaf        bytea,
  ADD COLUMN IF NOT EXISTS sm_commitment  bytea,
  ADD COLUMN IF NOT EXISTS sm_doc_proof   jsonb,
  ADD COLUMN IF NOT EXISTS sm_dv          text,
  ADD COLUMN IF NOT EXISTS sm_location    jsonb;

CREATE TABLE IF NOT EXISTS sourcemark_versions (
  document_version_id text PRIMARY KEY,
  document_id         text        NOT NULL,
  source_uri          text        NOT NULL,
  content_hash        bytea       NOT NULL,
  salt_ref            text        NOT NULL,
  parser              text        NOT NULL,
  corpus_proof        jsonb       NOT NULL,
  batch_id            text        NOT NULL
);

CREATE TABLE IF NOT EXISTS sourcemark_batches (
  batch_id     text PRIMARY KEY,
  committed_at bigint NOT NULL,
  log_proof    jsonb  NOT NULL
);

CREATE INDEX IF NOT EXISTS sourcemark_versions_batch ON sourcemark_versions (batch_id);
"""


def _proof_json(p: MerkleProof) -> str:
    return json.dumps({
        "leaf_index": p.leaf_index,
        "tree_size": p.tree_size,
        "path": [h.hex() for h in p.path],
        "root": p.root.hex(),
    })


def _proof_from_json(raw: Any) -> MerkleProof:
    d = raw if isinstance(raw, dict) else json.loads(raw)
    return MerkleProof(
        leaf_index=d["leaf_index"],
        tree_size=d["tree_size"],
        path=[bytes.fromhex(h) for h in d["path"]],
        root=bytes.fromhex(d["root"]),
    )


def _log_json(p: LogProof) -> str:
    return json.dumps({
        "url": p.url,
        "log_id": p.log_id.hex(),
        "entry_id": p.entry_id,
        "entry_profile": p.entry_profile,
        "leaf_index": p.leaf_index,
        "tree_size": p.tree_size,
        "path": [h.hex() for h in p.path],
        "root_hash": p.root_hash.hex(),
        "signed_tree_head": p.signed_tree_head.hex(),
    })


def _log_from_json(raw: Any) -> LogProof:
    d = raw if isinstance(raw, dict) else json.loads(raw)
    return LogProof(
        url=d["url"],
        log_id=bytes.fromhex(d["log_id"]),
        entry_id=d["entry_id"],
        entry_profile=d["entry_profile"],
        leaf_index=d["leaf_index"],
        tree_size=d["tree_size"],
        path=[bytes.fromhex(h) for h in d["path"]],
        root_hash=bytes.fromhex(d["root_hash"]),
        signed_tree_head=bytes.fromhex(d["signed_tree_head"]),
    )


class PgVector:
    """
    ```python
    store = PgVector(conn, chunks_table="chunks", chunk_id_column="id")
    store.migrate()          # once; additive, no rewrite
    ```
    """

    def __init__(
        self,
        connection: Any,
        *,
        chunks_table: str = "chunks",
        chunk_id_column: str = "chunk_id",
        text_column: str = "text",
    ) -> None:
        self._conn = connection
        # Identifiers are not parameterizable in SQL, so they are validated
        # rather than escaped. A table name arriving from configuration is
        # still a place a string can turn into a statement.
        for name in (chunks_table, chunk_id_column, text_column):
            if not name.replace("_", "").isalnum():
                raise ValueError(f"{name!r} is not a plain SQL identifier")
        self.chunks_table = chunks_table
        self.chunk_id_column = chunk_id_column
        self.text_column = text_column

    def migrate(self) -> None:
        with self._conn.cursor() as cur:
            cur.execute(MIGRATION.format(chunks=self.chunks_table))
        self._conn.commit()

    # -- write -------------------------------------------------------------

    def write(self, anchorings: list[Anchoring]) -> None:
        if not anchorings:
            return
        first = anchorings[0]
        batch_id = f"{first.log_proof.url}#{first.log_proof.entry_id}"
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sourcemark_batches (batch_id, committed_at, log_proof) "
                "VALUES (%s, %s, %s) ON CONFLICT (batch_id) DO NOTHING",
                (batch_id, first.committed_at, _log_json(first.log_proof)),
            )
            cur.execute(
                "INSERT INTO sourcemark_versions "
                "(document_version_id, document_id, source_uri, content_hash, salt_ref, "
                " parser, corpus_proof, batch_id) VALUES (%s,%s,%s,%s,%s,%s,%s,%s) "
                "ON CONFLICT (document_version_id) DO UPDATE SET "
                "corpus_proof = EXCLUDED.corpus_proof, batch_id = EXCLUDED.batch_id",
                (
                    first.document.document_version_id,
                    first.document.document_id,
                    first.document.source_uri,
                    first.document.content_hash,
                    first.salt_ref,
                    first.parser,
                    _proof_json(first.corpus_proof),
                    batch_id,
                ),
            )
            cur.executemany(
                f"UPDATE {self.chunks_table} SET sm_leaf = %s, sm_commitment = %s, "
                f"sm_doc_proof = %s, sm_dv = %s, sm_location = %s "
                f"WHERE {self.chunk_id_column} = %s",
                [
                    (
                        a.leaf_hash,
                        a.content_commitment,
                        _proof_json(a.document_proof),
                        a.document.document_version_id,
                        json.dumps({
                            "byte_range": list(a.byte_range),
                            "page": a.page,
                            "bbox": list(a.bbox) if a.bbox else None,
                            "paragraph": a.paragraph,
                        }),
                        a.chunk_id,
                    )
                    for a in anchorings
                ],
            )
        self._conn.commit()

    # -- read --------------------------------------------------------------

    _SELECT = """
        SELECT c.{id_col}, c.{text_col}, c.sm_leaf, c.sm_commitment, c.sm_doc_proof,
               c.sm_location, v.document_version_id, v.document_id, v.source_uri,
               v.content_hash, v.salt_ref, v.parser, v.corpus_proof,
               b.committed_at, b.log_proof
          FROM {chunks} c
          JOIN sourcemark_versions v ON v.document_version_id = c.sm_dv
          JOIN sourcemark_batches  b ON b.batch_id = v.batch_id
         WHERE c.{id_col} = ANY(%s) AND c.sm_leaf IS NOT NULL
    """

    def read_many(self, chunk_ids: Iterable[str]) -> dict[str, Anchoring]:
        ids = list(chunk_ids)
        if not ids:
            return {}
        sql = self._SELECT.format(
            chunks=self.chunks_table, id_col=self.chunk_id_column, text_col=self.text_column
        )
        with self._conn.cursor() as cur:
            cur.execute(sql, (ids,))
            rows = cur.fetchall()
        return {row[0]: self._row_to_anchoring(row) for row in rows}

    def read(self, chunk_id: str) -> Anchoring | None:
        return self.read_many([chunk_id]).get(chunk_id)

    @staticmethod
    def _row_to_anchoring(row: tuple) -> Anchoring:
        (chunk_id, text, leaf, commitment, doc_proof, location, dv, doc_id,
         source_uri, content_hash, salt_ref, parser, corpus_proof,
         committed_at, log_proof) = row
        loc = location if isinstance(location, dict) else json.loads(location)
        return Anchoring(
            document=Document(doc_id, dv, source_uri, bytes(content_hash)),
            chunk_id=chunk_id,
            text=text,
            byte_range=tuple(loc["byte_range"]),
            page=loc.get("page"),
            bbox=tuple(loc["bbox"]) if loc.get("bbox") else None,
            paragraph=loc.get("paragraph"),
            parser=parser,
            salt_ref=salt_ref,
            content_commitment=bytes(commitment),
            leaf_hash=bytes(leaf),
            document_proof=_proof_from_json(doc_proof),
            corpus_proof=_proof_from_json(corpus_proof),
            log_proof=_log_from_json(log_proof),
            committed_at=committed_at,
        )
