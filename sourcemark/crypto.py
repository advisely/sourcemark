"""Hashing, Merkle trees, and COSE signing.

Implements `spec/canonicalization.md` clauses 3, 4 and 5. Every construction
here has a test in `tests/test_conformance.py` asserting it reproduces the
worked example in `spec/examples/derivation.txt` byte for byte. That file is
the contract; this module is one implementation of it.

Where this differs from `spec/examples/reference.py`, it differs only in
shape, never in output. The reference recomputes subtree roots on every call
because that is how the RFC reads and readability is its job. Anchoring a
10k-chunk corpus needs every leaf's path, and paying O(n log n) per path
means O(n^2 log n) for the corpus -- roughly four hours where the level-wise
build takes under a second. `test_merkle_matches_reference` pins the two
together over every tree size up to 64.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Protocol

from .cbor import Tagged, encode

__all__ = [
    "LEAF_PREFIX", "NODE_PREFIX", "ALG_ES256", "ALG_EDDSA", "COSE_SIGN1_TAG",
    "sha256", "hkdf_expand", "chunk_salt", "content_commitment",
    "leaf_hash", "document_leaf_hash", "corpus_entry_data", "log_leaf_hash",
    "MerkleTree", "fold", "Signer", "sig_structure", "cose_sign1",
]

LEAF_PREFIX = b"\x00"  # RFC 6962 2.1
NODE_PREFIX = b"\x01"

ALG_ES256 = -7
ALG_EDDSA = -8
COSE_SIGN1_TAG = 18


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# --------------------------------------------------------------------------
# Clause 3 -- hashing
# --------------------------------------------------------------------------


def hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-Expand, RFC 5869 2.3.

    Extract is skipped because the version key is already a uniformly random
    KMS secret: there is no entropy to concentrate, and running Extract over
    a uniform key would only add a step two implementations could differ on.
    """
    if length > 255 * 32:
        raise ValueError("HKDF-Expand cannot produce more than 255 blocks")
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def chunk_salt(version_key: bytes, document_version_id: str, chunk_id: str) -> bytes:
    """Per-chunk salt (clause 3.1).

    Per chunk rather than per document version, so that disclosing one
    chunk's opening in a receipt does not open every sibling chunk, and so
    that the blast radius of a leaked receipt is one chunk.
    """
    if len(version_key) != 32:
        raise ValueError(f"version key must be 32 bytes, got {len(version_key)}")
    info = encode(["sourcemark.salt.v1", document_version_id, chunk_id])
    return hkdf_expand(version_key, info, 32)


def content_commitment(salt: bytes, chunk_text: str) -> bytes:
    """Commitment to the chunk text (clause 3.2).

    HMAC rather than H(salt || text): SHA-256 is length-extendable, so the
    naive form lets a forger extend a published commitment to cover text
    nobody ingested without ever learning the salt.

    The text is committed as UTF-8 with no normalization. Normalizing here
    would silently change what was committed to; a pipeline that needs
    normalized text must normalize before Anchor sees it, so that the
    normalized form is what the source file is later checked against.
    """
    return hmac.new(salt, chunk_text.encode("utf-8"), hashlib.sha256).digest()


def leaf_hash(
    *,
    document_version_id: str,
    chunk_id: str,
    page: int | None,
    bbox: list[int] | None,
    byte_range: list[int],
    commitment: bytes,
) -> bytes:
    """Chunk leaf (clause 3.3). The preimage is a CBOR array, not a
    concatenation: concatenating variable-length fields lets two different
    chunks collide onto one leaf."""
    preimage = encode([
        "sourcemark.leaf.v1",
        document_version_id,
        chunk_id,
        page,
        bbox,
        byte_range,
        commitment,
    ])
    return sha256(LEAF_PREFIX + preimage)


def document_leaf_hash(document_version_id: str, doc_root: bytes, doc_tree_size: int) -> bytes:
    """Leaf of the corpus tree: one whole document version (clause 3.4).

    doc_tree_size is bound in so that a document root cannot be replayed
    under a different claimed chunk count.
    """
    preimage = encode(["sourcemark.doc.v1", document_version_id, doc_root, doc_tree_size])
    return sha256(LEAF_PREFIX + preimage)


def corpus_entry_data(corpus_root: bytes, committed_at_ms: int) -> bytes:
    """The bytes submitted to the transparency log (clause 5.1).

    A receipt never carries these. A verifier recomputes them from
    corpus_root and committed_at, because a receipt that supplies them is
    supplying an input to the check meant to constrain it.
    """
    return encode(["sourcemark.corpus.v1", corpus_root, committed_at_ms])


def log_leaf_hash(entry_data: bytes) -> bytes:
    return sha256(LEAF_PREFIX + entry_data)


# --------------------------------------------------------------------------
# Clause 4 -- Merkle trees
# --------------------------------------------------------------------------


class MerkleTree:
    """An RFC 6962 tree built once, so that every path is O(log n) to read.

    Built level-wise: pair adjacent nodes, carry an unpaired trailing node up
    unchanged. That is equivalent to the RFC's recursive split at the largest
    power of two below n, and the equivalence is asserted exhaustively in the
    tests rather than assumed.
    """

    __slots__ = ("_levels",)

    def __init__(self, leaves: list[bytes]) -> None:
        for i, leaf in enumerate(leaves):
            if len(leaf) != 32:
                raise ValueError(f"leaf {i} is {len(leaf)} bytes, expected 32")
        levels = [list(leaves)]
        while len(levels[-1]) > 1:
            below = levels[-1]
            above = [
                sha256(NODE_PREFIX + below[i] + below[i + 1])
                for i in range(0, len(below) - 1, 2)
            ]
            if len(below) % 2:
                above.append(below[-1])
            levels.append(above)
        self._levels = levels

    @property
    def size(self) -> int:
        return len(self._levels[0])

    @property
    def root(self) -> bytes:
        if self.size == 0:
            return sha256(b"")
        return self._levels[-1][0]

    def path(self, index: int) -> list[bytes]:
        """Bottom-up sibling path for `index` (RFC 6962 2.1.1)."""
        if not 0 <= index < self.size:
            raise IndexError(f"leaf index {index} outside a tree of size {self.size}")
        out: list[bytes] = []
        for level in self._levels[:-1]:
            sibling = index ^ 1
            if sibling < len(level):
                out.append(level[sibling])
            # An unpaired trailing node has no sibling at this level and is
            # carried up unchanged, contributing nothing to the path.
            index >>= 1
        return out


def fold(leaf: bytes, index: int, tree_size: int, path: list[bytes]) -> bytes:
    """Fold an inclusion path into a root -- RFC 6962 2.1.1, verbatim.

    Written as the RFC writes it, with fn and sn, because this is the
    function an auditor reimplements from the document. A cleverer form that
    happens to agree on the sizes we tested is worth nothing here.
    """
    if not 0 <= index < tree_size:
        raise ValueError(f"leaf index {index} outside a tree of size {tree_size}")
    fn, sn, r = index, tree_size - 1, leaf
    for sibling in path:
        if sn == 0:
            raise ValueError("inclusion path is longer than the tree is deep")
        if fn & 1 or fn == sn:
            r = sha256(NODE_PREFIX + sibling + r)
            while fn and not (fn & 1):
                fn >>= 1
                sn >>= 1
        else:
            r = sha256(NODE_PREFIX + r + sibling)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise ValueError("inclusion path is shorter than the tree is deep")
    return r


# --------------------------------------------------------------------------
# Clause 5 -- COSE_Sign1
# --------------------------------------------------------------------------


class Signer(Protocol):
    """Whatever holds the private key. Anchor and Emit never see key bytes."""

    @property
    def alg(self) -> int: ...

    @property
    def kid(self) -> bytes: ...

    def sign(self, message: bytes) -> bytes: ...


def sig_structure(protected: bytes, payload: bytes) -> bytes:
    """RFC 9052 4.4. external_aad is empty and stays empty: it is context that
    travels outside the receipt, and a receipt whose verification depends on
    context the auditor was not handed is not offline-verifiable."""
    return encode(["Signature1", protected, b"", payload])


def cose_sign1(payload: bytes, protected_map: dict, signer: Signer) -> bytes:
    """A tagged COSE_Sign1 carrying `payload` as an embedded byte string.

    The payload is carried as bytes rather than as a parsed structure so that
    a verifier signs and checks the bytes it received, never a re-encoding of
    its own parse of them.
    """
    protected = encode(protected_map)
    signature = signer.sign(sig_structure(protected, payload))
    return encode(Tagged(COSE_SIGN1_TAG, [protected, {}, payload, signature]))
