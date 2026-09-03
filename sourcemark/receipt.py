"""Receipt assembly, signing, and the JSON projection.

`spec/receipt.cddl` is the authority on shape and `spec/canonicalization.md`
clause 6 on the projection. This module builds structures that satisfy both;
`tests/test_conformance.py` asserts the result is byte-identical to the
worked example rather than merely similar to it.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from .cbor import decode, encode
from .crypto import Signer, cose_sign1, sig_structure
from .models import Anchoring, Opening

__all__ = [
    "RECEIPT_VERSION", "CONTENT_TYPE",
    "build", "sign", "unavailable", "project", "SupportClaim",
]

RECEIPT_VERSION = "0.1"
CONTENT_TYPE = "application/vnd.sourcemark.receipt+cbor"

# Clause 6.2: a byte string projects to "<label>:<hex>". The label is
# "sha256" only where the CDDL types the field as a digest. The salt is 32
# bytes and is not a hash of anything; labelling it "sha256:" would invite a
# reader to try to reverse it.
DIGEST_FIELDS = frozenset({
    "content_hash", "content_commitment", "leaf_hash",
    "doc_root", "corpus_root", "root_hash", "log_id",
})
TIMESTAMP_FIELDS = frozenset({"committed_at", "retrieved_at", "erased_at", "timestamp"})


class SupportClaim:
    """A support score, which is never a proof.

    `proven` is not a parameter. The CDDL types it as the literal `false`, so
    a receipt asserting that a statistical score is a proof is ungrammatical
    rather than merely discouraged, and this class has no way to express one.
    """

    __slots__ = ("cls", "scorer", "score", "threshold", "note")

    CLASSES = ("QUOTED", "SUPPORTED", "INFERRED", "UNSUPPORTED")

    def __init__(
        self,
        cls: str,
        scorer: str,
        *,
        score: float | None = None,
        threshold: float | None = None,
        note: str | None = None,
    ) -> None:
        if cls not in self.CLASSES:
            raise ValueError(f"support class must be one of {self.CLASSES}, got {cls!r}")
        self.cls, self.scorer = cls, scorer
        self.score, self.threshold, self.note = score, threshold, note

    def as_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"class": self.cls, "scorer": self.scorer, "proven": False}
        if self.score is not None:
            out["score"] = float(self.score)
        if self.threshold is not None:
            out["threshold"] = float(self.threshold)
        if self.note is not None:
            out["note"] = self.note
        return out


def build(
    anchoring: Anchoring,
    opening: Opening,
    *,
    query_id: str,
    retriever: str,
    retrieved_at: int,
    policy_ref: str | None = None,
    support: SupportClaim | None = None,
) -> dict[str, Any]:
    """Assemble a receipt structure. No signing, no I/O."""
    location: dict[str, Any] = {"byte_range": list(anchoring.byte_range)}
    if anchoring.page is not None:
        location["page"] = anchoring.page
    if anchoring.paragraph is not None:
        location["paragraph"] = anchoring.paragraph
    if anchoring.bbox is not None:
        location["bbox"] = list(anchoring.bbox)

    if opening.erased:
        opening_map: dict[str, Any] = {"erased": True}
        if opening.erased_at is not None:
            opening_map["erased_at"] = opening.erased_at
    else:
        opening_map = {"salt": opening.salt}

    receipt: dict[str, Any] = {
        "receipt_version": RECEIPT_VERSION,
        "kind": "sourcemark.retrieval.receipt",
        "custody": {
            "source": {
                "document_id": anchoring.document.document_id,
                "document_version_id": anchoring.document.document_version_id,
                "source_uri": anchoring.document.source_uri,
                "content_hash": anchoring.document.content_hash,
                "committed_at": anchoring.committed_at,
            },
            "location": location,
            "derivation": {
                "chunk_id": anchoring.chunk_id,
                "parser": anchoring.parser,
                "salt_ref": anchoring.salt_ref,
                "content_commitment": anchoring.content_commitment,
                "opening": opening_map,
            },
            "proof": {
                "leaf_hash": anchoring.leaf_hash,
                "document": {
                    "leaf_index": anchoring.document_proof.leaf_index,
                    "tree_size": anchoring.document_proof.tree_size,
                    "path": list(anchoring.document_proof.path),
                    "doc_root": anchoring.document_proof.root,
                },
                "corpus": {
                    "leaf_index": anchoring.corpus_proof.leaf_index,
                    "tree_size": anchoring.corpus_proof.tree_size,
                    "path": list(anchoring.corpus_proof.path),
                    "corpus_root": anchoring.corpus_proof.root,
                },
                "log": {
                    "url": anchoring.log_proof.url,
                    "log_id": anchoring.log_proof.log_id,
                    "entry_profile": anchoring.log_proof.entry_profile,
                    "entry_id": anchoring.log_proof.entry_id,
                    "leaf_index": anchoring.log_proof.leaf_index,
                    "tree_size": anchoring.log_proof.tree_size,
                    "path": list(anchoring.log_proof.path),
                    "root_hash": anchoring.log_proof.root_hash,
                    "signed_tree_head": anchoring.log_proof.signed_tree_head,
                },
            },
        },
        "context": {
            "query_id": query_id,
            "retriever": retriever,
            "retrieved_at": retrieved_at,
        },
    }
    if policy_ref is not None:
        receipt["context"]["policy_ref"] = policy_ref
    if support is not None:
        receipt["support"] = support.as_dict()
    return receipt


def sign(receipt: dict[str, Any], signer: Signer) -> bytes:
    """Encode, sign, and verify our own output before returning it.

    The self-check is not paranoia about the signing library. It catches the
    case where the encoder and the decoder in this package have drifted
    apart, which surfaces as a receipt that verifies here and fails in front
    of an auditor months later, with no way left to tell which side moved.
    """
    payload = encode(receipt)
    signed = cose_sign1(payload, {1: signer.alg, 3: CONTENT_TYPE, 4: signer.kid}, signer)

    tagged = decode(signed)
    protected, unprotected, embedded, signature = tagged.value
    if embedded != payload:
        raise RuntimeError("round-trip changed the payload; encoder and decoder disagree")
    if unprotected != {}:
        raise RuntimeError("unprotected header must be empty")
    if decode(protected)[1] != signer.alg:
        raise RuntimeError("protected header does not name the signing algorithm")
    verify = getattr(signer, "public_key", None)
    if verify is not None:
        verify().verify(signature, sig_structure(protected, embedded))
    return signed


def unavailable(reason: str, *, remedy: str | None = None, state: str | None = None) -> dict:
    """The response when no receipt can be issued.

    Deliberately not a receipt with empty fields. A missing receipt that is
    shaped like a passing one is worse than no receipt at all, because the
    thing reading it will not notice.
    """
    states = {"PENDING", "NOT_ANCHORED", "ERASED", "LOG_UNREACHABLE"}
    if state is not None and state not in states:
        raise ValueError(f"state must be one of {sorted(states)}, got {state!r}")
    body: dict[str, Any] = {"reason": reason}
    if remedy is not None:
        body["remedy"] = remedy
    if state is not None:
        body["state"] = state
    return {"receipt_unavailable": body}


def project(value: Any, field: str | None = None) -> Any:
    """The JSON projection of clause 6. Non-normative, for humans."""
    if isinstance(value, bytes):
        label = "sha256" if field in DIGEST_FIELDS else "base16"
        return f"{label}:{value.hex()}"
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and field in TIMESTAMP_FIELDS:
        return (
            dt.datetime.fromtimestamp(value / 1000, dt.timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )
    if isinstance(value, dict):
        return {k: project(v, k) for k, v in value.items()}
    if isinstance(value, list):
        # Every array of byte strings in this format is an array of digests.
        return [project(v, "leaf_hash" if isinstance(v, bytes) else field) for v in value]
    return value
