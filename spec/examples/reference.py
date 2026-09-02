#!/usr/bin/env python3
"""Sourcemark receipt v0.1 — reference implementation of the normative rules.

This file is the executable form of ../canonicalization.md. Every function
here corresponds to a numbered clause in that document, cited in its
docstring. If the two ever disagree, canonicalization.md is normative and
this file is the bug.

Dependencies: Python standard library, plus `cryptography` for Ed25519 and
ECDSA P-256 only. The CBOR encoder is deliberately written out rather than
imported: a canonicalization rule that delegates to a third-party library
specifies that library's behaviour, not the format's.

SPDX-License-Identifier: CC0-1.0
"""

import hashlib
import hmac
from typing import Any

# ---------------------------------------------------------------------------
# 1. Deterministic CBOR encoding  (canonicalization.md 2)
# ---------------------------------------------------------------------------


def _head(major: int, n: int) -> bytes:
    """Major type + argument, in the shortest form that fits (clause 2.2)."""
    if n < 24:
        return bytes([(major << 5) | n])
    if n < 0x100:
        return bytes([(major << 5) | 24, n])
    if n < 0x10000:
        return bytes([(major << 5) | 25]) + n.to_bytes(2, "big")
    if n < 0x100000000:
        return bytes([(major << 5) | 26]) + n.to_bytes(4, "big")
    if n < 0x10000000000000000:
        return bytes([(major << 5) | 27]) + n.to_bytes(8, "big")
    raise ValueError("argument exceeds 64 bits")


def encode(value: Any) -> bytes:
    """Encode `value` per the Sourcemark deterministic profile (clause 2).

    Accepts: bool, None, int, bytes, str, list, dict, float.
    Rejects everything else, loudly. There is no "best effort" encoding;
    an unencodable value is a bug in the caller, not a shape to guess at.
    """
    if value is True:
        return b"\xf5"
    if value is False:
        return b"\xf4"
    if value is None:
        return b"\xf6"

    if isinstance(value, int):  # bool is handled above
        if value >= 0:
            return _head(0, value)
        return _head(1, -1 - value)

    if isinstance(value, float):
        # Clause 2.6: always float64. RFC 8949 core determinism would shrink
        # this to the smallest form that round-trips; we forbid that, because
        # "smallest form that round-trips" is a property of the encoder's
        # float printer and has produced cross-language divergence before.
        import struct

        return b"\xfb" + struct.pack(">d", value)

    if isinstance(value, bytes):
        return _head(2, len(value)) + value

    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _head(3, len(raw)) + raw

    if isinstance(value, list):
        return _head(4, len(value)) + b"".join(encode(v) for v in value)

    if isinstance(value, dict):
        # Clause 2.5: sort by the bytewise lexicographic order of the ENCODED
        # key, not by the key's own string order. For the text keys used by
        # this format the two coincide only until a key exceeds 23 bytes, at
        # which point the length prefix grows and the orders diverge.
        items = [(encode(k), encode(v)) for k, v in value.items()]
        items.sort(key=lambda kv: kv[0])
        if len({k for k, _ in items}) != len(items):
            raise ValueError("duplicate map key after encoding")
        return _head(5, len(items)) + b"".join(k + v for k, v in items)

    raise TypeError(f"not encodable under the Sourcemark profile: {type(value).__name__}")


# ---------------------------------------------------------------------------
# 2. Hashing primitives  (canonicalization.md 3)
# ---------------------------------------------------------------------------

LEAF_PREFIX = b"\x00"  # RFC 6962 3.1
NODE_PREFIX = b"\x01"


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-Expand, RFC 5869 2.3. Extract is skipped: the version key is
    already a uniformly random 32-byte KMS secret, so there is nothing to
    extract entropy from."""
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def chunk_salt(version_key: bytes, document_version_id: str, chunk_id: str) -> bytes:
    """Per-chunk salt (clause 3.1).

    docs/SPEC.md 4.1 puts one salt on the whole document version. That is too
    coarse in both directions: disclosing one chunk's opening in one receipt
    would open every other chunk in the version, and erasure could not be
    finer-grained than a whole document. Deriving per chunk costs one HMAC.
    """
    info = encode(["sourcemark.salt.v1", document_version_id, chunk_id])
    return hkdf_expand(version_key, info, 32)


def content_commitment(salt: bytes, chunk_text: str) -> bytes:
    """Commitment to the chunk text (clause 3.2).

    HMAC, not H(salt || text). SHA-256 is a Merkle-Damgard hash, so
    H(salt || text) leaks a usable state: an attacker who knows the digest
    and the length can compute H(salt || text || padding || suffix) without
    ever learning the salt, and forge a leaf for text nobody ingested.
    HMAC is immune and costs the same.
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
    """Chunk leaf (clause 3.3).

    docs/SPEC.md 4.1 writes this as a `||` concatenation of the fields. That
    is not a construction, it is an ambiguity: ("dv_c3e2881", "chk_88a1c")
    and ("dv_c3e28", "81chk_88a1c") concatenate to identical bytes, so two
    different chunks can be given the same leaf. Encoding the preimage as a
    CBOR array makes every field boundary explicit in the bytes.
    """
    preimage = encode(
        [
            "sourcemark.leaf.v1",
            document_version_id,
            chunk_id,
            page,
            bbox,
            byte_range,
            commitment,
        ]
    )
    return sha256(LEAF_PREFIX + preimage)


def document_leaf_hash(document_version_id: str, doc_root: bytes, doc_tree_size: int) -> bytes:
    """Leaf of the corpus tree: a whole document version (clause 3.4).

    Binding doc_tree_size here stops a document root from being replayed
    under a different claimed size.
    """
    preimage = encode(
        ["sourcemark.doc.v1", document_version_id, doc_root, doc_tree_size]
    )
    return sha256(LEAF_PREFIX + preimage)


# ---------------------------------------------------------------------------
# 3. Merkle tree — RFC 6962 shape  (canonicalization.md 4)
# ---------------------------------------------------------------------------


def _split(n: int) -> int:
    """Largest power of two strictly less than n (RFC 6962 2.1)."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def merkle_root(leaves: list[bytes]) -> bytes:
    """Root over already-hashed leaves. Empty tree is SHA-256 of nothing."""
    if not leaves:
        return sha256(b"")
    if len(leaves) == 1:
        return leaves[0]
    k = _split(len(leaves))
    return sha256(NODE_PREFIX + merkle_root(leaves[:k]) + merkle_root(leaves[k:]))


def inclusion_path(leaves: list[bytes], index: int) -> list[bytes]:
    """Audit path for `index`, bottom-up (RFC 6962 2.1.1)."""
    if len(leaves) <= 1:
        return []
    k = _split(len(leaves))
    if index < k:
        return inclusion_path(leaves[:k], index) + [merkle_root(leaves[k:])]
    return inclusion_path(leaves[k:], index - k) + [merkle_root(leaves[:k])]


def fold(leaf: bytes, index: int, tree_size: int, path: list[bytes]) -> bytes:
    """Fold an audit path back to a root (clause 4.3).

    This is RFC 6962 2.1.1 verbatim, in its `fn`/`sn` formulation. Direction
    is derived from (index, tree_size) and never stored in the receipt: a
    stored direction bit is an attacker-controlled input to the one check
    that is supposed to be unforgeable.
    """
    if index >= tree_size:
        raise ValueError("leaf_index out of range for tree_size")
    fn, sn = index, tree_size - 1
    node = leaf
    for sibling in path:
        if sn == 0:
            raise ValueError("inclusion path longer than the tree is deep")
        if fn & 1 or fn == sn:
            node = sha256(NODE_PREFIX + sibling + node)
            while fn != 0 and not fn & 1:
                fn >>= 1
                sn >>= 1
        else:
            node = sha256(NODE_PREFIX + node + sibling)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise ValueError("inclusion path shorter than the tree is deep")
    return node


# ---------------------------------------------------------------------------
# 4. COSE_Sign1  (canonicalization.md 5)
# ---------------------------------------------------------------------------

ALG_ES256 = -7
ALG_EDDSA = -8

COSE_SIGN1_TAG = 18


def sig_structure(protected: bytes, payload: bytes) -> bytes:
    """RFC 9052 4.4. external_aad is always empty in this profile."""
    return encode(["Signature1", protected, b"", payload])


def cose_sign1(payload: bytes, protected_map: dict, sign) -> bytes:
    protected = encode(protected_map)
    signature = sign(sig_structure(protected, payload))
    body = encode([protected, {}, payload, signature])
    # Tag 18, encoded as major type 6 with argument 18.
    return _head(6, COSE_SIGN1_TAG) + body


def _parse_sign1(tagged: bytes):
    """Minimal COSE_Sign1 reader, enough to re-verify our own output.

    Deliberately not a general CBOR parser: it accepts only the exact shape
    this profile emits and raises on anything else. A permissive parser in a
    verifier is a place for a forged receipt to hide.
    """
    if tagged[0] != 0xD2:  # tag(18)
        raise ValueError("not a tagged COSE_Sign1")
    buf = memoryview(tagged)[1:]

    def read(b):
        ib = b[0]
        major, ai = ib >> 5, ib & 0x1F
        if ai < 24:
            n, rest = ai, b[1:]
        elif ai == 24:
            n, rest = b[1], b[2:]
        elif ai == 25:
            n, rest = int.from_bytes(b[1:3], "big"), b[3:]
        elif ai == 26:
            n, rest = int.from_bytes(b[1:5], "big"), b[5:]
        elif ai == 27:
            n, rest = int.from_bytes(b[1:9], "big"), b[9:]
        else:
            raise ValueError("indefinite length is forbidden by this profile")
        if major in (2, 3):
            return bytes(rest[:n]), rest[n:]
        if major == 4:
            out, cur = [], rest
            for _ in range(n):
                item, cur = read(cur)
                out.append(item)
            return out, cur
        if major == 5:
            if n != 0:
                raise ValueError("only an empty unprotected header is emitted")
            return {}, rest
        raise ValueError(f"unexpected major type {major}")

    body, tail = read(buf)
    if tail:
        raise ValueError("trailing bytes after COSE_Sign1")
    if not isinstance(body, list) or len(body) != 4:
        raise ValueError("COSE_Sign1 must be a 4-element array")
    return body[0], body[1], body[2], body[3]


# ---------------------------------------------------------------------------
# 5. ES256 signature malleability  (canonicalization.md 5)
# ---------------------------------------------------------------------------

P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _der_read_int(buf: bytes, off: int) -> tuple[int, int]:
    if buf[off] != 0x02:
        raise ValueError("expected DER INTEGER")
    length = buf[off + 1]
    if length & 0x80:
        raise ValueError("long-form DER length is not emitted by ES256")
    return int.from_bytes(buf[off + 2 : off + 2 + length], "big"), off + 2 + length


def es256_is_low_s(signature: bytes) -> bool:
    """True when the ECDSA signature's s value is in the lower half of the order.

    (r, s) and (r, n - s) both verify, so an ES256 signature has two valid
    encodings unless one is ruled out. Any component that deduplicates,
    caches, or logs receipts by signature bytes can be shown two receipts it
    believes are distinct. Requiring low-s makes the encoding unique.
    """
    if not signature or signature[0] != 0x30:
        raise ValueError("expected a DER SEQUENCE")
    _, off = _der_read_int(signature, 2)
    s, _ = _der_read_int(signature, off)
    return s <= P256_ORDER // 2
