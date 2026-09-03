"""Anchor -- commit at ingest.

One call added to an ingestion job that already parses, chunks, embeds and
inserts. It derives a salt per chunk, commits to the text, folds the chunks
into a document tree and the documents into a corpus tree, submits that one
root to a transparency log, and writes the resulting proofs back beside the
chunks the caller already stored.

**Batching is not an optimization.** The corpus tree exists so that a batch
window costs one log submission rather than one per document version. A log
that receives one entry per document is a log whose cost and whose tree depth
both scale with the corpus, and neither needs to.

The consequence is stated rather than hidden: between `commit()` and the
flush that logs the batch, a chunk is anchored but not yet provable. That is
the `PENDING` state in `spec/verification.md` §3, and Emit reports it as a
`receipt_unavailable` rather than as a receipt with empty proofs.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Iterable, Protocol

from .crypto import (
    MerkleTree,
    chunk_salt,
    content_commitment,
    corpus_entry_data,
    document_leaf_hash,
    leaf_hash,
)
from .keys import VersionKeys
from .log import TransparencyLog
from .models import Anchoring, Chunk, Document, LogProof, MerkleProof

__all__ = ["Anchor", "AnchorStore", "CommitResult", "StagedDocument", "WritebackError"]


class AnchorStore(Protocol):
    """Where anchoring metadata is written, beside the caller's own chunks."""

    def write(self, anchorings: list[Anchoring]) -> None: ...

    def read(self, chunk_id: str) -> Anchoring | None: ...

    def read_many(self, chunk_ids: Iterable[str]) -> dict[str, Anchoring]: ...


class WritebackError(RuntimeError):
    """The root was logged, but not every chunk got told about it.

    This is the one genuinely awkward failure in the pipeline, because the
    log submission is not retractable: the corpus root is in an append-only
    tree whether or not the database write that follows it succeeds. Losing
    the batch here is fail-safe -- the affected chunks report NOT_ANCHORED
    rather than producing a bad receipt -- but it is still data loss, and the
    work needed to recover it is already in memory.

    So the un-written anchorings are kept on the Anchor and `retry_writeback`
    finishes the job against the SAME log entry. Re-running `flush` instead
    would submit a second root for the same batch and leave the log carrying
    a duplicate nobody can explain later.
    """

    def __init__(self, message: str, *, written: int, pending: int) -> None:
        super().__init__(message)
        self.written, self.pending = written, pending


@dataclass(frozen=True)
class CommitResult:
    document_version_id: str
    chunk_count: int
    doc_root: bytes
    pending: bool


@dataclass
class StagedDocument:
    """A document version hashed but not yet logged."""

    document: Document
    chunks: list[Chunk]
    leaves: list[bytes]
    commitments: list[bytes]
    salt_ref: str
    doc_tree: MerkleTree


class Anchor:
    """
    ```python
    with Anchor(store=..., log=..., keys=..., parser="docling@2.3.1") as anchor:
        for doc in corpus:
            anchor.commit(document, chunks)
    ```

    The context manager matters. Leaving a batch unflushed leaves every chunk
    in it anchored-but-unprovable, and a silent unflushed batch at process
    exit is indistinguishable from a corpus that was never anchored.
    """

    def __init__(
        self,
        *,
        store: AnchorStore,
        log: TransparencyLog,
        keys: VersionKeys,
        parser: str = "unknown@0",
        batch_documents: int = 64,
    ) -> None:
        if batch_documents < 1:
            raise ValueError("batch_documents must be at least 1")
        self.store, self.log, self.keys = store, log, keys
        self.parser = parser
        self.batch_documents = batch_documents
        self._staged: list[StagedDocument] = []
        self._unwritten: list[list[Anchoring]] = []

    # -- the one line a caller adds ----------------------------------------

    def commit(self, document: Document, chunks: list[Chunk]) -> CommitResult:
        """Hash a document version and stage it for the next batch."""
        if not chunks:
            raise ValueError(f"{document.document_version_id}: nothing to anchor")
        seen: set[str] = set()
        for c in chunks:
            if c.chunk_id in seen:
                raise ValueError(f"duplicate chunk_id {c.chunk_id!r} in one document version")
            seen.add(c.chunk_id)

        dv = document.document_version_id
        if any(s.document.document_version_id == dv for s in self._staged):
            # Two leaves for one document version in a single corpus tree is
            # not an error the tree can express -- both fold, both verify, and
            # a verifier has no way to tell which one the chunk belongs to.
            # Refusing is the only outcome that cannot produce a receipt that
            # is valid and wrong.
            raise ValueError(
                f"{dv} is already staged in this batch; flush() before committing "
                f"it again, or the corpus tree gets two leaves for one document version"
            )
        salt_ref = self.keys.create(dv)
        version_key = self.keys.key(dv)

        commitments, leaves = [], []
        for c in chunks:
            salt = chunk_salt(version_key, dv, c.chunk_id)
            commitment = content_commitment(salt, c.text)
            commitments.append(commitment)
            leaves.append(
                leaf_hash(
                    document_version_id=dv,
                    chunk_id=c.chunk_id,
                    page=c.page,
                    bbox=list(c.bbox) if c.bbox else None,
                    byte_range=list(c.byte_range),
                    commitment=commitment,
                )
            )

        tree = MerkleTree(leaves)
        self._staged.append(
            StagedDocument(document, list(chunks), leaves, commitments, salt_ref, tree)
        )
        if len(self._staged) >= self.batch_documents:
            self.flush()
            return CommitResult(dv, len(chunks), tree.root, pending=False)
        return CommitResult(dv, len(chunks), tree.root, pending=True)

    # -- the batch ---------------------------------------------------------

    def flush(self) -> int:
        """Build the corpus tree, submit its root, write every proof back.

        Returns the number of chunks made provable. Zero is not an error --
        flushing an empty batch is what a well-behaved shutdown does.
        """
        if self._unwritten:
            raise WritebackError(
                f"{sum(len(b) for b in self._unwritten)} anchoring(s) from the previous "
                f"batch are still unwritten; call retry_writeback() before flushing again, "
                f"or the log gets a second root for work it already covers",
                written=0, pending=sum(len(b) for b in self._unwritten),
            )
        if not self._staged:
            return 0
        staged = self._staged

        corpus_leaves = [
            document_leaf_hash(s.document.document_version_id, s.doc_tree.root, s.doc_tree.size)
            for s in staged
        ]
        corpus_tree = MerkleTree(corpus_leaves)
        committed_at = int(time.time() * 1000)
        # The batch stays staged until the submission succeeds. A log that is
        # unreachable should leave the caller able to retry, not holding a
        # tree that was hashed and then dropped.
        entry = self.log.submit(corpus_entry_data(corpus_tree.root, committed_at))
        self._staged = []

        log_proof = LogProof(
            url=entry.url,
            log_id=entry.log_id,
            entry_id=entry.entry_id,
            leaf_index=entry.leaf_index,
            tree_size=entry.tree_size,
            path=list(entry.path),
            root_hash=entry.root_hash,
            signed_tree_head=entry.signed_tree_head,
            entry_profile=entry.entry_profile,
            head_format=entry.head_format,
            entry_body=entry.entry_body,
        )

        batches: list[list[Anchoring]] = []
        for doc_index, s in enumerate(staged):
            corpus_proof = MerkleProof(
                leaf_index=doc_index,
                tree_size=corpus_tree.size,
                path=corpus_tree.path(doc_index),
                root=corpus_tree.root,
            )
            anchorings = [
                Anchoring(
                    document=s.document,
                    chunk_id=c.chunk_id,
                    text=c.text,
                    byte_range=tuple(c.byte_range),
                    page=c.page,
                    bbox=tuple(c.bbox) if c.bbox else None,
                    paragraph=c.paragraph,
                    parser=self.parser,
                    salt_ref=s.salt_ref,
                    content_commitment=s.commitments[i],
                    leaf_hash=s.leaves[i],
                    document_proof=MerkleProof(
                        leaf_index=i,
                        tree_size=s.doc_tree.size,
                        path=s.doc_tree.path(i),
                        root=s.doc_tree.root,
                    ),
                    corpus_proof=corpus_proof,
                    log_proof=log_proof,
                    committed_at=committed_at,
                )
                for i, c in enumerate(s.chunks)
            ]
            batches.append(anchorings)

        # Everything above is pure computation. Only this loop touches the
        # store, so a failure has an exact boundary and an exact remainder.
        written = 0
        for i, anchorings in enumerate(batches):
            try:
                self.store.write(anchorings)
            except Exception as exc:
                self._unwritten = batches[i:]
                pending = sum(len(b) for b in self._unwritten)
                raise WritebackError(
                    f"log entry {entry.entry_id} is committed, but write-back failed "
                    f"after {written} of {written + pending} chunks: {exc}. "
                    f"Call retry_writeback(); do NOT flush, which would log a second root.",
                    written=written, pending=pending,
                ) from exc
            written += len(anchorings)
        return written

    def retry_writeback(self) -> int:
        """Finish a flush that failed part way, against the same log entry."""
        written = 0
        while self._unwritten:
            self.store.write(self._unwritten[0])
            written += len(self._unwritten.pop(0))
        return written

    # -- erasure -----------------------------------------------------------

    def erase(self, document_version_id: str) -> None:
        """Destroy the version key. The tree is untouched.

        After this, no new opening can be produced for any chunk in the
        version, the inclusion proofs still fold, and the log has no gap.
        Receipts already issued and handed to third parties carry their own
        opening and stay openable -- erasure is forward-acting, and any
        material claiming otherwise is wrong.
        """
        self.keys.destroy(document_version_id)

    # -- lifecycle ---------------------------------------------------------

    @property
    def pending_documents(self) -> int:
        return len(self._staged)

    @property
    def unwritten_chunks(self) -> int:
        return sum(len(b) for b in self._unwritten)

    def __enter__(self) -> "Anchor":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if exc_type is None:
            self.flush()
