"""The values that cross Anchor, the store, and Emit.

`Anchoring` is the important one. It is everything Emit needs to assemble a
receipt without touching the network, the KMS, or the log -- which is what
makes "no network call on the query path" a property of the data model
rather than a promise about the implementation. If a field is not in here,
Emit cannot use it, and the check that would have needed it cannot silently
become an online check later.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = ["Chunk", "Document", "MerkleProof", "LogProof", "Anchoring", "Opening"]


@dataclass(frozen=True)
class Chunk:
    """One retrievable span, as a parser hands it over.

    `byte_range` is the only mandatory coordinate. It is the one an auditor
    can re-derive from the original file with no parser at all; page and bbox
    are rendering aids, and a scanned or reflowable source may have neither.
    """

    chunk_id: str
    text: str
    byte_range: tuple[int, int]
    page: int | None = None
    bbox: tuple[int, int, int, int] | None = None
    paragraph: str | None = None

    def __post_init__(self) -> None:
        start, end = self.byte_range
        if start < 0 or end < start:
            raise ValueError(f"{self.chunk_id}: byte_range {self.byte_range} is not a range")
        if self.bbox is not None and len(self.bbox) != 4:
            raise ValueError(f"{self.chunk_id}: bbox must have four values")
        if self.page is not None and self.page < 1:
            raise ValueError(f"{self.chunk_id}: page is 1-based, got {self.page}")


@dataclass(frozen=True)
class Document:
    """The source a document version came from."""

    document_id: str
    document_version_id: str
    source_uri: str
    content_hash: bytes

    def __post_init__(self) -> None:
        if len(self.content_hash) != 32:
            raise ValueError("content_hash must be a 32-byte SHA-256 digest")


@dataclass(frozen=True)
class MerkleProof:
    leaf_index: int
    tree_size: int
    path: list[bytes]
    root: bytes


@dataclass(frozen=True)
class LogProof:
    url: str
    log_id: bytes
    entry_id: str
    leaf_index: int
    tree_size: int
    path: list[bytes]
    root_hash: bytes
    signed_tree_head: bytes
    entry_profile: str = "sourcemark.corpus.v1"


@dataclass(frozen=True)
class Opening:
    """Either a salt, or a stated tombstone. Never an absent field.

    An optional salt makes "erased" and "the emitter forgot" the same bytes,
    and `docs/SPEC.md` §3 forbids a missing thing from resembling a passing
    one. The union is the enforcement.
    """

    salt: bytes | None = None
    erased: bool = False
    erased_at: int | None = None

    def __post_init__(self) -> None:
        if self.erased and self.salt is not None:
            raise ValueError("an erased opening cannot carry a salt")
        if not self.erased and self.salt is None:
            raise ValueError("a live opening must carry a salt")


@dataclass(frozen=True)
class Anchoring:
    """One chunk's committed state -- everything a receipt needs.

    This is what Anchor writes to the store and Emit reads back. Nothing here
    is recomputed at query time: recomputing the commitment would need the
    version key, and needing the version key at query time would mean an
    erased document version could no longer answer queries at all.
    """

    document: Document
    chunk_id: str
    text: str
    byte_range: tuple[int, int]
    page: int | None
    bbox: tuple[int, int, int, int] | None
    paragraph: str | None
    parser: str
    salt_ref: str
    content_commitment: bytes
    leaf_hash: bytes
    document_proof: MerkleProof
    corpus_proof: MerkleProof
    log_proof: LogProof
    committed_at: int
    extra: dict = field(default_factory=dict, repr=False)
