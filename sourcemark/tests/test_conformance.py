"""This package against the spec's published vectors.

`spec/examples/derivation.txt` records every intermediate value in the worked
example, from chunk text to signature. This file recomputes all of them with
`sourcemark.crypto` and `sourcemark.cbor` -- a separate implementation from
the one that produced them -- and asserts byte equality.

That is the acceptance criterion in `spec/README.md` pointed inward. If these
pass, the vectors are reproducible by something other than the script that
wrote them, which is the whole claim the spec makes about itself.

Run:  python3 -m sourcemark.tests.test_conformance

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import hashlib
import pathlib
import sys

from ..cbor import decode, encode
from ..crypto import (
    LEAF_PREFIX,
    MerkleTree,
    chunk_salt,
    content_commitment,
    corpus_entry_data,
    document_leaf_hash,
    fold,
    leaf_hash,
    log_leaf_hash,
    sha256,
)
from ..keys import Ed25519Signer
from ..models import Anchoring, Document, LogProof, MerkleProof, Opening
from ..receipt import SupportClaim, build, project, sign

SPEC = pathlib.Path(__file__).resolve().parents[2] / "spec" / "examples"

# The scenario, restated from spec/examples/build.py. Restated rather than
# imported: importing it would test build.py against itself.
DOC_ID, DV_ID = "doc_2f8a91e", "dv_c3e2881"
SOURCE_URI = "s3://policies/2026/SOP-114.pdf"
CHUNK_ID, PARSER = "chk_88a1c", "docling@2.3.1"
SALT_REF = "kms://tenant-acme/salt/dv_c3e2881"
COMMITTED_AT, RETRIEVED_AT = 1773480131000, 1788357764000
CHUNK_TEXT = (
    "Any deviation from the validated cleaning cycle must be recorded on Form "
    "QA-114b and reviewed by the Qualified Person before the affected batch is "
    "released."
)
PAGE, PARA = 47, "p-14"
BBOX, BYTE_RANGE = [72, 318, 540, 402], [98211, 98644]
DOC_CHUNKS, DOC_INDEX = 12, 7
CORPUS_DOCS, CORPUS_INDEX = 5, 2
LOG_INDEX, LOG_TREE_SIZE = 4093, 4096
VERSION_KEY = hashlib.sha256(b"sourcemark/spec/v0.1/example/version-key").digest()
LOG_SEED = b"sourcemark/spec/v0.1/example/log-key"
ISSUER_SEED = b"sourcemark/spec/v0.1/example/issuer-key"
ISSUER_KID = b"acme-emit-01"   # the fixture's own key label
ERASED_AT = 1795172700000        # 2026-11-20T11:05:00Z

_passed, _failed = 0, 0


def check(label: str, got, want) -> None:
    global _passed, _failed
    if got == want:
        _passed += 1
        print(f"  pass  {label}")
    else:
        _failed += 1
        print(f"  FAIL  {label}\n          got  {got!r}\n          want {want!r}")


def derivation() -> dict[str, str]:
    """Parse derivation.txt into label -> value, on the two-space split."""
    out: dict[str, str] = {}
    for line in (SPEC / "derivation.txt").read_text().splitlines():
        if not line or line.startswith(" ") or "  " not in line:
            continue
        label, _, value = line.partition("  ")
        out[label.strip()] = value.strip()
    return out


def build_example() -> dict:
    """Reproduce every level of the worked example."""
    salt = chunk_salt(VERSION_KEY, DV_ID, CHUNK_ID)
    commitment = content_commitment(salt, CHUNK_TEXT)
    our_leaf = leaf_hash(
        document_version_id=DV_ID, chunk_id=CHUNK_ID, page=PAGE,
        bbox=BBOX, byte_range=BYTE_RANGE, commitment=commitment,
    )

    doc_leaves = [
        leaf_hash(
            document_version_id=DV_ID, chunk_id=f"chk_{i:05x}", page=1 + i * 4,
            bbox=[72, 100 + i, 540, 180 + i], byte_range=[1000 * i, 1000 * i + 400],
            commitment=content_commitment(
                chunk_salt(VERSION_KEY, DV_ID, f"chk_{i:05x}"), f"filler chunk {i}"
            ),
        )
        for i in range(DOC_CHUNKS)
    ]
    doc_leaves[DOC_INDEX] = our_leaf
    doc_tree = MerkleTree(doc_leaves)

    our_doc_leaf = document_leaf_hash(DV_ID, doc_tree.root, DOC_CHUNKS)
    corpus_leaves = [
        document_leaf_hash(f"dv_filler{i:04x}", sha256(f"root{i}".encode()), 8 + i)
        for i in range(CORPUS_DOCS)
    ]
    corpus_leaves[CORPUS_INDEX] = our_doc_leaf
    corpus_tree = MerkleTree(corpus_leaves)

    entry_data = corpus_entry_data(corpus_tree.root, COMMITTED_AT)
    log_leaves = [sha256(LEAF_PREFIX + encode(["log-filler", i])) for i in range(LOG_TREE_SIZE)]
    log_leaves[LOG_INDEX] = log_leaf_hash(entry_data)
    log_tree = MerkleTree(log_leaves)

    log_signer = Ed25519Signer.from_seed(LOG_SEED)
    from ..crypto import cose_sign1

    sth = cose_sign1(
        encode({
            "log_id": sha256(log_signer.public_spki_der()),
            "tree_size": LOG_TREE_SIZE,
            "root_hash": log_tree.root,
            "timestamp": COMMITTED_AT + 4000,
        }),
        {1: log_signer.alg, 4: b"log-2026"},
        log_signer,
    )

    return {
        "salt": salt, "commitment": commitment, "leaf": our_leaf,
        "doc_tree": doc_tree, "doc_leaf": our_doc_leaf, "corpus_tree": corpus_tree,
        "entry_data": entry_data, "log_leaf": log_leaves[LOG_INDEX],
        "log_tree": log_tree, "log_id": sha256(log_signer.public_spki_der()), "sth": sth,
    }


def main() -> int:
    d = derivation()
    ex = build_example()

    print("Level 1 -- chunk leaf and document tree")
    check("salt matches derivation.txt", ex["salt"].hex(), d["salt = HKDF(version_key,...)"])
    check("commitment matches", ex["commitment"].hex(), d["commitment = HMAC(salt, text)"])
    check("leaf_hash matches", ex["leaf"].hex(), d["leaf_hash"])
    check("doc_root matches", ex["doc_tree"].root.hex(), d["doc_root"])
    check("document path length matches", str(len(ex["doc_tree"].path(DOC_INDEX))),
          d["document.path length"])

    print("\nLevel 2 -- document leaf and corpus tree")
    check("document_leaf_hash matches", ex["doc_leaf"].hex(), d["document_leaf_hash"])
    check("corpus_root matches", ex["corpus_tree"].root.hex(), d["corpus_root"])
    check("corpus path length matches", str(len(ex["corpus_tree"].path(CORPUS_INDEX))),
          d["corpus.path length"])

    print("\nLevel 3 -- log entry, log tree, signed tree head")
    check("recomputed entry_data matches", ex["entry_data"].hex(), d["entry_data (recomputed)"])
    check("log_leaf matches", ex["log_leaf"].hex(), d["log_leaf"])
    check("log_root matches", ex["log_tree"].root.hex(), d["log_root"])
    check("log path length matches", str(len(ex["log_tree"].path(LOG_INDEX))), d["log.path length"])
    check("log_id matches", ex["log_id"].hex(), d["log_id = SHA-256(SPKI DER)"])
    check("signed tree head length matches", str(len(ex["sth"])), d["signed_tree_head (COSE_Sign1)"])

    print("\nThe three folds")
    check("chunk folds to doc_root",
          fold(ex["leaf"], DOC_INDEX, DOC_CHUNKS, ex["doc_tree"].path(DOC_INDEX)),
          ex["doc_tree"].root)
    check("document folds to corpus_root",
          fold(ex["doc_leaf"], CORPUS_INDEX, CORPUS_DOCS, ex["corpus_tree"].path(CORPUS_INDEX)),
          ex["corpus_tree"].root)
    check("log entry folds to the signed root",
          fold(ex["log_leaf"], LOG_INDEX, LOG_TREE_SIZE, ex["log_tree"].path(LOG_INDEX)),
          ex["log_tree"].root)

    print("\nThe receipt, assembled by sourcemark.receipt")
    anchoring = Anchoring(
        document=Document(DOC_ID, DV_ID, SOURCE_URI,
                          sha256(b"<the full SOP-114.pdf bytes>")),
        chunk_id=CHUNK_ID, text=CHUNK_TEXT, byte_range=tuple(BYTE_RANGE),
        page=PAGE, bbox=tuple(BBOX), paragraph=PARA, parser=PARSER, salt_ref=SALT_REF,
        content_commitment=ex["commitment"], leaf_hash=ex["leaf"],
        document_proof=MerkleProof(DOC_INDEX, DOC_CHUNKS,
                                   ex["doc_tree"].path(DOC_INDEX), ex["doc_tree"].root),
        corpus_proof=MerkleProof(CORPUS_INDEX, CORPUS_DOCS,
                                 ex["corpus_tree"].path(CORPUS_INDEX), ex["corpus_tree"].root),
        log_proof=LogProof(
            url="https://log.sourcemark.dev/2026", log_id=ex["log_id"],
            entry_id="0x3f21a5c0", leaf_index=LOG_INDEX, tree_size=LOG_TREE_SIZE,
            path=ex["log_tree"].path(LOG_INDEX), root_hash=ex["log_tree"].root,
            signed_tree_head=ex["sth"],
        ),
        committed_at=COMMITTED_AT,
    )
    structure = build(
        anchoring, Opening(salt=ex["salt"]),
        query_id="q_a8c01", retriever="pgvector@0.8.1", retrieved_at=RETRIEVED_AT,
        policy_ref="pol_dec_4421",
        support=SupportClaim("SUPPORTED", "bge-reranker-v2@1.0", score=0.91,
                             threshold=0.85,
                             note="Statistical estimate. Not a cryptographic claim."),
    )
    payload = encode(structure)
    check("payload is byte-identical to receipt.payload.cbor",
          payload, (SPEC / "receipt.payload.cbor").read_bytes())
    check("payload digest matches derivation.txt", sha256(payload).hex(), d["payload SHA-256"])

    issuer = Ed25519Signer.from_seed(ISSUER_SEED, kid=ISSUER_KID)
    signed = sign(structure, issuer)
    check("signed receipt is byte-identical to receipt.cbor",
          signed, (SPEC / "receipt.cbor").read_bytes())

    print("\nThe erased vector")
    erased_structure = build(
        anchoring, Opening(erased=True, erased_at=ERASED_AT),
        query_id="q_a8c01", retriever="pgvector@0.8.1", retrieved_at=RETRIEVED_AT,
        policy_ref="pol_dec_4421",
        support=SupportClaim("SUPPORTED", "bge-reranker-v2@1.0", score=0.91,
                             threshold=0.85,
                             note="Statistical estimate. Not a cryptographic claim."),
    )
    check("erased receipt is byte-identical to receipt-erased.cbor",
          sign(erased_structure, issuer), (SPEC / "receipt-erased.cbor").read_bytes())
    live, erased = structure["custody"], erased_structure["custody"]
    check("erasure leaves leaf_hash untouched", live["proof"]["leaf_hash"],
          erased["proof"]["leaf_hash"])
    check("erasure leaves the signed tree head untouched",
          live["proof"]["log"]["signed_tree_head"], erased["proof"]["log"]["signed_tree_head"])
    check("erasure keeps the commitment", "content_commitment" in erased["derivation"], True)
    check("erasure states a tombstone", erased["derivation"]["opening"]["erased"], True)

    print("\nThe strict decoder against the published bytes")
    tagged = decode((SPEC / "receipt.cbor").read_bytes())
    check("receipt.cbor is a tagged COSE_Sign1", tagged.tag, 18)
    check("its embedded payload round-trips", tagged.value[2], payload)
    check("its unprotected header is empty", tagged.value[1], {})

    print("\nThe JSON projection")
    import json

    check("projection matches receipt.json",
          project(structure), json.loads((SPEC / "receipt.json").read_text()))

    print(f"\n{_passed} passed, {_failed} failed")
    return 1 if _failed else 0


if __name__ == "__main__":
    sys.exit(main())
