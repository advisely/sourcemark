#!/usr/bin/env python3
"""Generate the conformance vectors, deterministically.

    python3 conformance/build.py

Each vector is a directory holding a receipt, the text it cites, and the
outcome a conforming verifier MUST reach. The outcomes come from
`spec/verification.md` §3, and the ordering there is what makes them
testable: a doubly-broken receipt has more than one true answer, so the spec
fixes which one is reported and these vectors pin that decision.

Every vector is built from published seeds and no key material is committed.

**Eleven of the fifteen are byte-reproducible; the four `rekor-*` are not.**
They mirror Rekor exactly, which means ECDSA, and ECDSA draws a fresh nonce
per signature -- so their bytes change on every regeneration while remaining
equally valid. That is `canonicalization.md` clause 2.7 in the wild:
canonicalization fixes what gets signed, not what a signature looks like. The
committed bytes are the fixtures; regenerate them only on purpose. The
`reproducible` flag in the manifest says which is which.

**These are adversarial by construction.** Several are receipts that this
repository's own `Emit` would refuse to issue -- it checks the commitment
against the text before signing. That refusal is a property of our emitter,
not of the format, and a verifier that assumes every receipt was produced by
a well-behaved emitter is a verifier that fails exactly when it matters.

SPDX-License-Identifier: CC0-1.0
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from cryptography.hazmat.primitives import hashes, serialization       # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec               # noqa: E402

from sourcemark.cbor import Tagged, decode, encode                     # noqa: E402
from sourcemark.crypto import (                                        # noqa: E402
    MerkleTree, chunk_salt, content_commitment, corpus_entry_data, cose_sign1,
    document_leaf_hash, leaf_hash, log_leaf_hash, sha256,
)
from sourcemark.keys import Ed25519Signer, Es256Signer                 # noqa: E402
from sourcemark.models import (                                        # noqa: E402
    Anchoring, Document, LogProof, MerkleProof, Opening,
)
from sourcemark.receipt import SupportClaim, build, sign               # noqa: E402

HERE = pathlib.Path(__file__).resolve().parent
VECTORS = HERE / "vectors"

LOG_SIGNER = Ed25519Signer.from_seed(b"sourcemark/conformance/v0.1/log-key", kid=b"conf-log")
ISSUER = Ed25519Signer.from_seed(b"sourcemark/conformance/v0.1/issuer-key", kid=b"conf-emit")
OTHER_LOG = Ed25519Signer.from_seed(b"sourcemark/conformance/v0.1/other-log", kid=b"other-log")
LOG_ID = sha256(LOG_SIGNER.public_spki_der())
VERSION_KEY = hashlib.sha256(b"sourcemark/conformance/v0.1/version-key").digest()

DOC = Document("doc_c0nf", "dv_c0nf01", "s3://conformance/SOP-114.pdf",
               hashlib.sha256(b"<the whole source file>").digest())
CHUNK_ID = "chk_c0nf7"
TEXT = ("Any deviation from the validated cleaning cycle must be recorded on Form "
        "QA-114b and reviewed by the Qualified Person before the affected batch is "
        "released.")
PAGE, PARA, BBOX = 47, "p-14", (72, 318, 540, 402)

# The byte range must be exactly as long as the text it points at, or the
# strongest check in the format -- re-deriving the chunk from the original
# file -- can never pass, and a "valid" vector that cannot be verified the
# best way is not a valid vector. An earlier draft of this file had a 433-byte
# range around 156 bytes of text and looked entirely fine until something
# tried to use it.
SOURCE_OFFSET = 98211
BYTE_RANGE = (SOURCE_OFFSET, SOURCE_OFFSET + len(TEXT.encode("utf-8")))

# A stand-in for the original document: the cited text at the recorded
# offset, surrounded by other content. Shipping it makes the launch gate
# runnable from this directory -- an answer, a receipt, and the source file.
_PREAMBLE = b"%PDF-1.7 (conformance stand-in, not a real PDF)\n"
SOURCE_BYTES = (
    _PREAMBLE
    + b"\x00" * (SOURCE_OFFSET - len(_PREAMBLE))
    + TEXT.encode("utf-8")
    + b"\n\nsubsequent content that the receipt does not cite\n"
)
assert SOURCE_BYTES[BYTE_RANGE[0]:BYTE_RANGE[1]] == TEXT.encode("utf-8")
DOC_CHUNKS, DOC_INDEX = 16, 9
CORPUS_DOCS, CORPUS_INDEX = 6, 3
LOG_SIZE, LOG_INDEX = 1024, 811

COMMITTED_AT = 1773480131000          # 2026-03-14T09:22:11Z
STH_TIMESTAMP = COMMITTED_AT + 4000
RETRIEVED_AT = 1788357764000          # 2026-09-02T14:02:44Z


def anchoring() -> Anchoring:
    salt = chunk_salt(VERSION_KEY, DOC.document_version_id, CHUNK_ID)
    commitment = content_commitment(salt, TEXT)
    ours = leaf_hash(document_version_id=DOC.document_version_id, chunk_id=CHUNK_ID,
                     page=PAGE, bbox=list(BBOX), byte_range=list(BYTE_RANGE),
                     commitment=commitment)

    doc_leaves = [
        leaf_hash(document_version_id=DOC.document_version_id, chunk_id=f"chk_f{i:04x}",
                  page=1 + i, bbox=[72, 100 + i, 540, 180 + i],
                  byte_range=[900 * i, 900 * i + 500],
                  commitment=content_commitment(
                      chunk_salt(VERSION_KEY, DOC.document_version_id, f"chk_f{i:04x}"),
                      f"sibling chunk {i}"))
        for i in range(DOC_CHUNKS)
    ]
    doc_leaves[DOC_INDEX] = ours
    doc_tree = MerkleTree(doc_leaves)

    corpus_leaves = [
        document_leaf_hash(f"dv_f{i:04x}", sha256(f"docroot{i}".encode()), 10 + i)
        for i in range(CORPUS_DOCS)
    ]
    corpus_leaves[CORPUS_INDEX] = document_leaf_hash(
        DOC.document_version_id, doc_tree.root, doc_tree.size)
    corpus_tree = MerkleTree(corpus_leaves)

    log_leaves = [sha256(b"\x00" + encode(["conformance-filler", i])) for i in range(LOG_SIZE)]
    log_leaves[LOG_INDEX] = log_leaf_hash(corpus_entry_data(corpus_tree.root, COMMITTED_AT))
    log_tree = MerkleTree(log_leaves)

    sth = cose_sign1(
        encode({"log_id": LOG_ID, "tree_size": LOG_SIZE,
                "root_hash": log_tree.root, "timestamp": STH_TIMESTAMP}),
        {1: LOG_SIGNER.alg, 4: LOG_SIGNER.kid}, LOG_SIGNER)

    return Anchoring(
        document=DOC, chunk_id=CHUNK_ID, text=TEXT, byte_range=BYTE_RANGE,
        page=PAGE, bbox=BBOX, paragraph=PARA, parser="docling@2.3.1",
        salt_ref="kms://tenant-conf/salt/dv_c0nf01",
        content_commitment=content_commitment(salt, TEXT), leaf_hash=ours,
        document_proof=MerkleProof(DOC_INDEX, DOC_CHUNKS,
                                   doc_tree.path(DOC_INDEX), doc_tree.root),
        corpus_proof=MerkleProof(CORPUS_INDEX, CORPUS_DOCS,
                                 corpus_tree.path(CORPUS_INDEX), corpus_tree.root),
        log_proof=LogProof(url="https://log.sourcemark.dev/conformance", log_id=LOG_ID,
                           entry_id="0x0000032b", leaf_index=LOG_INDEX, tree_size=LOG_SIZE,
                           path=log_tree.path(LOG_INDEX), root_hash=log_tree.root,
                           signed_tree_head=sth),
        committed_at=COMMITTED_AT,
        extra={"salt": salt},
    )


A = anchoring()


def receipt_structure(*, opening: Opening | None = None, retrieved_at: int = RETRIEVED_AT,
                      anchor: Anchoring = A) -> dict:
    return build(
        anchor, opening or Opening(salt=A.extra["salt"]),
        query_id="q_conf01", retriever="pgvector@0.8.1", retrieved_at=retrieved_at,
        support=SupportClaim("SUPPORTED", "bge-reranker-v2@1.0", score=0.91, threshold=0.85,
                             note="Statistical estimate. Not a cryptographic claim."),
    )


def resign(structure: dict) -> bytes:
    return sign(structure, ISSUER)


# ---------------------------------------------------------------------------
# The vectors
# ---------------------------------------------------------------------------

def v_valid() -> tuple[bytes, str, dict]:
    return resign(receipt_structure()), TEXT, {
        "outcome": "VERIFIED", "exit_status": 0,
        "why": "Every check in verification.md 4 passes against the cited text.",
    }


def v_erased() -> tuple[bytes, str, dict]:
    s = receipt_structure(opening=Opening(erased=True, erased_at=COMMITTED_AT + 86_400_000))
    return resign(s), TEXT, {
        "outcome": "ERASED", "exit_status": 4,
        "why": ("The version key was destroyed. Every proof still folds and the signed "
                "tree head is byte-identical to the valid vector; only the opening "
                "differs. A verifier reporting TAMPERED or FORGED here is wrong: "
                "nothing was tampered with, and the log has no gap."),
    }


def v_tampered() -> tuple[bytes, str, dict]:
    altered = TEXT.replace("Qualified Person", "Shift Supervisor")
    return resign(receipt_structure()), altered, {
        "outcome": "TAMPERED", "exit_status": 1,
        "why": ("The receipt is internally perfect. The cited text is not what the "
                "commitment covers, which is the only way to notice that a source "
                "was edited after it was anchored."),
    }


def v_forged() -> tuple[bytes, str, dict]:
    s = receipt_structure()
    path = s["custody"]["proof"]["document"]["path"]
    path[0] = sha256(b"a sibling that was never in this tree")
    return resign(s), TEXT, {
        "outcome": "FORGED", "exit_status": 1,
        "why": ("One sibling in the document path was replaced, so the chunk no longer "
                "folds to doc_root. The receipt is signed by a valid issuer key, which "
                "is exactly why an issuer signature is the weaker claim."),
    }


def v_backdated() -> tuple[bytes, str, dict]:
    s = receipt_structure(retrieved_at=COMMITTED_AT - 60_000)
    return resign(s), TEXT, {
        "outcome": "BACKDATED", "exit_status": 1,
        "why": ("The answer is dated a minute BEFORE the commitment it cites. This is "
                "the check that separates a citation attached before an answer from "
                "one invented after it."),
    }


def v_pending() -> tuple[bytes, str, dict]:
    s = receipt_structure()
    s["custody"]["proof"]["log"]["leaf_index"] = LOG_SIZE      # one past the end
    return resign(s), TEXT, {
        "outcome": "PENDING", "exit_status": 3,
        "why": ("The entry index is not covered by this tree head's tree size. Not a "
                "failure: the root has been submitted and this tree head predates it. "
                "Retry with a fresher head. Reporting FORGED here would call a race "
                "condition an attack."),
    }


def v_unsigned_bad_signature() -> tuple[bytes, str, dict]:
    s = receipt_structure()
    sth = bytearray(s["custody"]["proof"]["log"]["signed_tree_head"])
    sth[-1] ^= 0x01
    s["custody"]["proof"]["log"]["signed_tree_head"] = bytes(sth)
    return resign(s), TEXT, {
        "outcome": "UNSIGNED", "exit_status": 1,
        "why": "One bit of the tree head's signature was flipped.",
    }


def v_unsigned_wrong_log() -> tuple[bytes, str, dict]:
    """The receipt names a log the auditor never agreed to trust."""
    s = receipt_structure()
    other_id = sha256(OTHER_LOG.public_spki_der())
    sth = cose_sign1(
        encode({"log_id": other_id, "tree_size": LOG_SIZE,
                "root_hash": A.log_proof.root_hash, "timestamp": STH_TIMESTAMP}),
        {1: OTHER_LOG.alg, 4: OTHER_LOG.kid}, OTHER_LOG)
    s["custody"]["proof"]["log"]["log_id"] = other_id
    s["custody"]["proof"]["log"]["signed_tree_head"] = sth
    return resign(s), TEXT, {
        "outcome": "UNSIGNED", "exit_status": 1,
        "why": ("Internally consistent and signed by a real key -- just not the log's. "
                "A verifier that checks the tree head against whichever key travels "
                "with the receipt, rather than against log_id and the key the auditor "
                "supplied, reports VERIFIED here. That is the whole attack."),
    }


def v_malformed_truncated() -> tuple[bytes, str, dict]:
    full, _, _ = v_valid()
    return full[: len(full) // 2], TEXT, {
        "outcome": "MALFORMED", "exit_status": 2,
        "why": ("A truncated download. Distinct from FORGED, which would label a "
                "network failure an attack, and from a bare error the caller might "
                "read as absence."),
    }


def v_malformed_indefinite() -> tuple[bytes, str, dict]:
    """Valid RFC 8949, outside the clause 2 profile."""
    tagged = decode(v_valid()[0])
    protected, _, payload, signature = tagged.value
    body = (b"\x9f" + encode(protected) + encode({}) + encode(payload)
            + encode(signature) + b"\xff")
    return b"\xd2" + body, TEXT, {
        "outcome": "MALFORMED", "exit_status": 2,
        "why": ("The COSE array uses an indefinite length. It parses under a permissive "
                "CBOR reader and is forbidden by canonicalization.md clause 2.3, "
                "because two encodings of one structure mean two digests and a "
                "signature that covers whichever one you happened to build."),
    }


def v_malformed_trailing() -> tuple[bytes, str, dict]:
    full, _, _ = v_valid()
    return full + b"\x00", TEXT, {
        "outcome": "MALFORMED", "exit_status": 2,
        "why": ("One byte appended. A decoder that stops at the end of the first value "
                "lets a signed payload carry an unsigned appendix."),
    }


# ---------------------------------------------------------------------------
# The external-log profile: Rekor
# ---------------------------------------------------------------------------
#
# Synthetic, and deliberately so. Building these against the public Rekor
# would mean writing test data into somebody else's permanent append-only log
# to make our test suite green, which is not a trade anyone should make. The
# FORMAT is checked against production separately and read-only, by
# sourcemark/tests/test_rekor_live.py, which fetches a real entry and confirms
# that its leaf folds and its checkpoint verifies. These vectors check our
# handling of that format; that test checks that the format is what we think.

REKOR_SUBMITTER = Es256Signer.from_seed(b"sourcemark/conformance/v0.1/rekor-submitter")
REKOR_LOG = Es256Signer.from_seed(b"sourcemark/conformance/v0.1/rekor-log")
REKOR_ORIGIN = "conformance.sourcemark.dev - 7203344561120099327"
REKOR_LOG_ID = sha256(REKOR_LOG.public_spki_der())
REKOR_SIZE, REKOR_INDEX = 512, 377


def submitter_certificate() -> bytes:
    """A self-signed X.509 certificate wrapping the submitter's public key.

    Almost every hashedrekord in the production log carries a certificate here
    rather than a bare public key, because Fulcio issues one for the signing
    identity. A verifier that only parses the bare form passes every synthetic
    fixture and fails against the real log -- which is how this vector came to
    exist: `sourcemark/tests/test_rekor_live.py` found exactly that.

    Self-signed and never chain-validated. It attests who submitted, and who
    submitted is reported rather than required.
    """
    import datetime as _dt

    from cryptography import x509
    from cryptography.x509.oid import NameOID

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "conformance-submitter")])
    # Fixed validity window, so the certificate bytes do not change per run for
    # any reason other than the ECDSA signature over them.
    not_before = _dt.datetime(2026, 1, 1, tzinfo=_dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(REKOR_SUBMITTER.public_key())
        .serial_number(0x50FFEE)
        .not_valid_before(not_before)
        .not_valid_after(not_before + _dt.timedelta(days=3650))
        .sign(REKOR_SUBMITTER._key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def hashedrekord_body(artifact_digest: bytes, *, as_certificate: bool = False) -> bytes:
    """Rekor's canonicalized hashedrekord entry. These are the bytes it hashes."""
    signature = REKOR_SUBMITTER.sign_raw_der(artifact_digest)
    key_pem = submitter_certificate() if as_certificate else REKOR_SUBMITTER.public_pem()
    return json.dumps({
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {
            "data": {"hash": {"algorithm": "sha256", "value": artifact_digest.hex()}},
            "signature": {
                "content": base64.b64encode(signature).decode(),
                "publicKey": {"content": base64.b64encode(key_pem).decode()},
            },
        },
    }, sort_keys=True, separators=(",", ":")).encode()


def signed_note(origin: str, size: int, root: bytes, signer) -> bytes:
    """A Go-checksum-database signed note, as Rekor emits.

    The signature covers the body up to and including the newline that ends
    the last body line -- not the blank separator that follows it. Getting
    that boundary wrong produces a note that looks right and verifies nowhere.
    """
    body = f"{origin}\n{size}\n{base64.b64encode(root).decode()}\n"
    signature = signer._key.sign(body.encode(), ec.ECDSA(hashes.SHA256()))
    hint = sha256(origin.encode())[:4]
    line = f"\u2014 {origin.split(' ')[0]} {base64.b64encode(hint + signature).decode()}\n"
    return (body + "\n" + line).encode()


def rekor_proof(entry_data: bytes, *, pin_to: bytes | None = None,
                checkpoint_size: int | None = None,
                as_certificate: bool = False) -> LogProof:
    body = hashedrekord_body(sha256(pin_to if pin_to is not None else entry_data),
                             as_certificate=as_certificate)
    leaf = sha256(b"\x00" + body)
    leaves = [sha256(b"\x00" + encode(["rekor-filler", i])) for i in range(REKOR_SIZE)]
    leaves[REKOR_INDEX] = leaf
    tree = MerkleTree(leaves)
    note = signed_note(REKOR_ORIGIN, checkpoint_size or REKOR_SIZE, tree.root, REKOR_LOG)
    return LogProof(
        url="https://rekor.sigstore.dev", log_id=REKOR_LOG_ID,
        entry_id="24296fb24b8ad77a" + "0" * 16, leaf_index=REKOR_INDEX, tree_size=REKOR_SIZE,
        path=tree.path(REKOR_INDEX), root_hash=tree.root,
        signed_tree_head=note, entry_profile="rekor.hashedrekord.v0.0.1",
        head_format="note.checkpoint.v1", entry_body=body,
    )


def _rekor_anchoring(**kw) -> Anchoring:
    import dataclasses
    entry_data = corpus_entry_data(A.corpus_proof.root, COMMITTED_AT)
    return dataclasses.replace(A, log_proof=rekor_proof(entry_data, **kw))


def v_rekor_valid() -> tuple[bytes, str, dict]:
    s = receipt_structure(anchor=_rekor_anchoring())
    return resign(s), TEXT, {
        "outcome": "VERIFIED", "exit_status": 0,
        "why": ("The same corpus root, anchored to a log that hashes its own leaf format "
                "and signs a note instead of a COSE tree head. Everything below the log "
                "is identical to the valid vector; only the last hop differs."),
    }


def v_rekor_unpinned_body() -> tuple[bytes, str, dict]:
    """The vector that matters. entry_body attests a DIFFERENT corpus root."""
    s = receipt_structure(anchor=_rekor_anchoring(pin_to=b"an entirely different entry"))
    return resign(s), TEXT, {
        "outcome": "FORGED", "exit_status": 1,
        "why": ("The log entry is real, its inclusion proof folds, its checkpoint signs "
                "the right tree, and the submitter signature verifies -- but the "
                "artefact digest inside entry_body is not the digest of THIS receipt's "
                "corpus root. A verifier that folds the proof without performing "
                "canonicalization.md 5.2 step 3 reports VERIFIED here, and has just "
                "certified a chunk against somebody else's log entry."),
    }


def v_rekor_certificate_submitter() -> tuple[bytes, str, dict]:
    """The production shape: an X.509 certificate where a key is expected."""
    s = receipt_structure(anchor=_rekor_anchoring(as_certificate=True))
    return resign(s), TEXT, {
        "outcome": "VERIFIED", "exit_status": 0,
        "why": ("Identical to rekor-valid except that publicKey.content holds a "
                "certificate rather than a bare public key, which is what the "
                "production log almost always contains. A verifier that only parses "
                "the bare form reports MALFORMED or FORGED here while passing every "
                "other vector in this directory."),
    }


def v_rekor_checkpoint_mismatch() -> tuple[bytes, str, dict]:
    s = receipt_structure(anchor=_rekor_anchoring(checkpoint_size=REKOR_SIZE + 9))
    return resign(s), TEXT, {
        "outcome": "UNSIGNED", "exit_status": 1,
        "why": ("The checkpoint's signature is valid and covers a different tree size "
                "than the proof claims. Checking a signature without checking what it "
                "signed verifies nothing."),
    }


def v_internal_with_entry_body() -> tuple[bytes, str, dict]:
    """A receipt supplying the leaf bytes it is not allowed to choose."""
    s = receipt_structure()
    s["custody"]["proof"]["log"]["entry_body"] = b"whatever the issuer would prefer"
    return resign(s), TEXT, {
        "outcome": "MALFORMED", "exit_status": 2,
        "why": ("Under sourcemark.corpus.v1 the verifier recomputes the leaf, so "
                "entry_body is forbidden outright rather than merely ignored. Ignoring "
                "an unexpected field is how an input the issuer chose gets read by the "
                "next version of the verifier."),
    }


VECTOR_SET = [
    ("valid", v_valid),
    ("erased", v_erased),
    ("tampered", v_tampered),
    ("forged", v_forged),
    ("backdated", v_backdated),
    ("pending", v_pending),
    ("unsigned-bad-signature", v_unsigned_bad_signature),
    ("unsigned-wrong-log", v_unsigned_wrong_log),
    ("malformed-truncated", v_malformed_truncated),
    ("malformed-indefinite-length", v_malformed_indefinite),
    ("malformed-trailing-bytes", v_malformed_trailing),
    ("rekor-valid", v_rekor_valid),
    ("rekor-unpinned-body", v_rekor_unpinned_body),
    ("rekor-certificate-submitter", v_rekor_certificate_submitter),
    ("rekor-checkpoint-mismatch", v_rekor_checkpoint_mismatch),
    ("internal-with-entry-body", v_internal_with_entry_body),
]


def main() -> int:
    if VECTORS.exists():
        for child in sorted(VECTORS.rglob("*"), reverse=True):
            child.unlink() if child.is_file() else child.rmdir()
        VECTORS.rmdir()
    VECTORS.mkdir(parents=True)

    (HERE / "log-public-key.der").write_bytes(LOG_SIGNER.public_spki_der())
    (HERE / "issuer-public-key.der").write_bytes(ISSUER.public_spki_der())
    (HERE / "rekor-log-public-key.der").write_bytes(REKOR_LOG.public_spki_der())
    (HERE / "source.bin").write_bytes(SOURCE_BYTES)
    manifest = {
        "spec_version": "0.1",
        "log_public_key": "log-public-key.der",
        "log_id": "sha256:" + LOG_ID.hex(),
        "issuer_public_key": "issuer-public-key.der",
        "rekor_log_public_key": "rekor-log-public-key.der",
        "source": "source.bin",
        "source_note": ("Every vector's byte_range points into source.bin, so the "
                        "--source path is exercisable from this directory. The vectors "
                        "whose text was altered will not re-derive from it, which is "
                        "the point."),
        "note": ("Every vector is verified against log-public-key.der. Vectors are "
                 "adversarial: several would be refused by a well-behaved emitter, "
                 "which is precisely why a verifier must not assume one."),
        "vectors": [],
    }
    for name, fn in VECTOR_SET:
        receipt, text, expected = fn()
        d = VECTORS / name
        d.mkdir()
        (d / "receipt.cbor").write_bytes(receipt)
        (d / "text.txt").write_text(text)
        (d / "expected.json").write_text(json.dumps(expected, indent=2) + "\n")
        manifest["vectors"].append({
            "name": name, "outcome": expected["outcome"],
            "exit_status": expected["exit_status"],
            "receipt": f"vectors/{name}/receipt.cbor",
            "text": f"vectors/{name}/text.txt",
            "source_verifiable": expected["outcome"] in ("VERIFIED", "ERASED"),
            "log_public_key": ("rekor-log-public-key.der" if name.startswith("rekor-")
                               else "log-public-key.der"),
            "reproducible": not name.startswith("rekor-"),
        })
        print(f"  {expected['outcome']:<10} {name}  ({len(receipt)} bytes)")

    (HERE / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    outcomes = {v["outcome"] for v in manifest["vectors"]}
    required = {"VERIFIED", "ERASED", "TAMPERED", "FORGED", "BACKDATED", "PENDING",
                "UNSIGNED", "MALFORMED"}
    missing = required - outcomes
    if missing:
        print(f"\nincomplete: no vector produces {sorted(missing)}")
        return 1
    unstable = [v["name"] for v in manifest["vectors"] if not v["reproducible"]]
    print(f"\n{len(VECTOR_SET)} vectors covering all {len(required)} outcomes")
    print(f"{len(VECTOR_SET) - len(unstable)} byte-reproducible; "
          f"{len(unstable)} ECDSA-signed and therefore not: {', '.join(unstable)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
