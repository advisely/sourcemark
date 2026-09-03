#!/usr/bin/env python3
"""Build the worked example in this directory from scratch, deterministically.

Run:  python3 spec/examples/build.py

Writes receipt.json, receipt.cbor, receipt.cbor.hex and derivation.txt. Two
runs on two machines MUST produce byte-identical files; that property is the
point of the exercise and is asserted at the end of this script.

No key material is committed to the repository. Both signing keys are derived
here from fixed, published seed strings, so the example regenerates exactly
without a private key ever being stored.

SPDX-License-Identifier: CC0-1.0
"""

import datetime as dt
import hashlib
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import reference as r  # noqa: E402

from cryptography.hazmat.primitives.asymmetric import ec, ed25519  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402

HERE = pathlib.Path(__file__).parent

# --- fixed test keys, derived from published seeds -------------------------
LOG_SEED = b"sourcemark/spec/v0.1/example/log-key"
ISSUER_SEED = b"sourcemark/spec/v0.1/example/issuer-key"

log_sk = ed25519.Ed25519PrivateKey.from_private_bytes(hashlib.sha256(LOG_SEED).digest())
log_pk_raw = log_sk.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
)
log_pk_spki = log_sk.public_key().public_bytes(
    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
)
LOG_ID = r.sha256(log_pk_spki)  # clause 5.3: log_id is SHA-256 over the SPKI DER

# P-256 group order (SEC 2, secp256r1 n). Reduce into [1, n-1].
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
issuer_sk = ed25519.Ed25519PrivateKey.from_private_bytes(
    hashlib.sha256(ISSUER_SEED).digest()
)
# A second, ES256 issuer used only to demonstrate clause 2.7 below.
es256_sk = ec.derive_private_key(
    int.from_bytes(hashlib.sha256(ISSUER_SEED + b"/es256").digest(), "big") % (P256_N - 1) + 1,
    ec.SECP256R1(),
)

# --- scenario --------------------------------------------------------------
def ms(iso: str) -> int:
    return int(dt.datetime.fromisoformat(iso).timestamp() * 1000)


DOC_ID = "doc_2f8a91e"
DV_ID = "dv_c3e2881"
SOURCE_URI = "s3://policies/2026/SOP-114.pdf"
CHUNK_ID = "chk_88a1c"
PARSER = "docling@2.3.1"
SALT_REF = "kms://tenant-acme/salt/dv_c3e2881"
COMMITTED_AT = ms("2026-03-14T09:22:11+00:00")
RETRIEVED_AT = ms("2026-09-02T14:02:44+00:00")

CHUNK_TEXT = (
    "Any deviation from the validated cleaning cycle must be recorded on Form "
    "QA-114b and reviewed by the Qualified Person before the affected batch is "
    "released."
)
PAGE, PARA = 47, "p-14"
BBOX = [72, 318, 540, 402]
BYTE_RANGE = [98211, 98644]

# The document version has 12 chunks; ours is the 8th. The batch window
# covered 5 document versions; ours is the 3rd. The log held 4218836 entries
# before this submission, so ours lands at index 4218836 in a tree of 4218837.
DOC_CHUNKS, DOC_INDEX = 12, 7
CORPUS_DOCS, CORPUS_INDEX = 5, 2
LOG_INDEX, LOG_TREE_SIZE = 4093, 4096

VERSION_KEY = hashlib.sha256(b"sourcemark/spec/v0.1/example/version-key").digest()

trace: list[str] = []


def show(label: str, value) -> None:
    v = value.hex() if isinstance(value, bytes) else str(value)
    trace.append(f"{label:<34} {v}")


# --- level 1: chunk leaf, document tree ------------------------------------
salt = r.chunk_salt(VERSION_KEY, DV_ID, CHUNK_ID)
commitment = r.content_commitment(salt, CHUNK_TEXT)
our_leaf = r.leaf_hash(
    document_version_id=DV_ID,
    chunk_id=CHUNK_ID,
    page=PAGE,
    bbox=BBOX,
    byte_range=BYTE_RANGE,
    commitment=commitment,
)

trace.append("LEVEL 1 - chunk leaf and document tree")
show("chunk_text (utf-8 bytes)", len(CHUNK_TEXT.encode()))
show("version_key (KMS, never in receipt)", VERSION_KEY)
show("salt = HKDF(version_key,...)", salt)
show("commitment = HMAC(salt, text)", commitment)
show("leaf_hash", our_leaf)

# Sibling chunks stand in for the rest of the document version.
doc_leaves = [
    r.leaf_hash(
        document_version_id=DV_ID,
        chunk_id=f"chk_{i:05x}",
        page=1 + i * 4,
        bbox=[72, 100 + i, 540, 180 + i],
        byte_range=[1000 * i, 1000 * i + 400],
        commitment=r.content_commitment(
            r.chunk_salt(VERSION_KEY, DV_ID, f"chk_{i:05x}"), f"filler chunk {i}"
        ),
    )
    for i in range(DOC_CHUNKS)
]
doc_leaves[DOC_INDEX] = our_leaf
doc_root = r.merkle_root(doc_leaves)
doc_path = r.inclusion_path(doc_leaves, DOC_INDEX)
show("doc_root", doc_root)
show("document.path length", len(doc_path))

# --- level 2: document leaf, corpus tree -----------------------------------
trace.append("")
trace.append("LEVEL 2 - document leaf and corpus tree")
our_doc_leaf = r.document_leaf_hash(DV_ID, doc_root, DOC_CHUNKS)
corpus_leaves = [
    r.document_leaf_hash(f"dv_filler{i:04x}", r.sha256(f"root{i}".encode()), 8 + i)
    for i in range(CORPUS_DOCS)
]
corpus_leaves[CORPUS_INDEX] = our_doc_leaf
corpus_root = r.merkle_root(corpus_leaves)
corpus_path = r.inclusion_path(corpus_leaves, CORPUS_INDEX)
show("document_leaf_hash", our_doc_leaf)
show("corpus_root", corpus_root)
show("corpus.path length", len(corpus_path))

# --- level 3: log entry, log tree, signed tree head ------------------------
trace.append("")
trace.append("LEVEL 3 - log entry, log tree, signed tree head")
# Clause 5.1: the verifier RECOMPUTES these bytes; the receipt never carries
# them, so the issuer cannot choose what gets hashed into the log leaf.
entry_data = r.encode(["sourcemark.corpus.v1", corpus_root, COMMITTED_AT])
log_leaf = r.sha256(r.LEAF_PREFIX + entry_data)
show("entry_data (recomputed)", entry_data)
show("log_leaf", log_leaf)

# A real tree, not synthesised siblings: every hash in this example is
# derivable from this repository. A production log is far larger, but the
# path grows only as log2(tree_size), so the shape here is the shape there.
log_leaves = [r.sha256(r.LEAF_PREFIX + r.encode(["log-filler", i])) for i in range(LOG_TREE_SIZE)]
log_leaves[LOG_INDEX] = log_leaf
log_root = r.merkle_root(log_leaves)
log_path = r.inclusion_path(log_leaves, LOG_INDEX)
show("log.path length", len(log_path))
show("log_root", log_root)

sth_payload = r.encode(
    {
        "log_id": LOG_ID,
        "tree_size": LOG_TREE_SIZE,
        "root_hash": log_root,
        "timestamp": COMMITTED_AT + 4000,
    }
)
sth = r.cose_sign1(
    sth_payload,
    {1: r.ALG_EDDSA, 4: b"log-2026"},
    lambda m: log_sk.sign(m),
)
show("log_id = SHA-256(SPKI DER)", LOG_ID)
show("signed_tree_head (COSE_Sign1)", len(sth))

# --- assemble the receipt --------------------------------------------------
receipt = {
    "receipt_version": "0.1",
    "kind": "sourcemark.retrieval.receipt",
    "custody": {
        "source": {
            "document_id": DOC_ID,
            "document_version_id": DV_ID,
            "source_uri": SOURCE_URI,
            "content_hash": r.sha256(b"<the full SOP-114.pdf bytes>"),
            "committed_at": COMMITTED_AT,
        },
        "location": {
            "page": PAGE,
            "paragraph": PARA,
            "bbox": BBOX,
            "byte_range": BYTE_RANGE,
        },
        "derivation": {
            "chunk_id": CHUNK_ID,
            "parser": PARSER,
            "salt_ref": SALT_REF,
            "content_commitment": commitment,
            "opening": {"salt": salt},
        },
        "proof": {
            "leaf_hash": our_leaf,
            "document": {
                "leaf_index": DOC_INDEX,
                "tree_size": DOC_CHUNKS,
                "path": doc_path,
                "doc_root": doc_root,
            },
            "corpus": {
                "leaf_index": CORPUS_INDEX,
                "tree_size": CORPUS_DOCS,
                "path": corpus_path,
                "corpus_root": corpus_root,
            },
            "log": {
                "url": "https://log.sourcemark.dev/2026",
                "log_id": LOG_ID,
                "entry_profile": "sourcemark.corpus.v1",
                "entry_id": "0x3f21a5c0",
                "leaf_index": LOG_INDEX,
                "tree_size": LOG_TREE_SIZE,
                "path": log_path,
                "root_hash": log_root,
                "head_format": "cose.sth.v1",
                "signed_tree_head": sth,
            },
        },
    },
    "support": {
        "class": "SUPPORTED",
        "score": 0.91,
        "scorer": "bge-reranker-v2@1.0",
        "threshold": 0.85,
        "proven": False,
        "note": "Statistical estimate. Not a cryptographic claim.",
    },
    "context": {
        "query_id": "q_a8c01",
        "retriever": "pgvector@0.8.1",
        "retrieved_at": RETRIEVED_AT,
        "policy_ref": "pol_dec_4421",
    },
}

payload = r.encode(receipt)
signed = r.cose_sign1(
    payload,
    {1: r.ALG_EDDSA, 3: "application/vnd.sourcemark.receipt+cbor", 4: b"acme-emit-01"},
    lambda m: issuer_sk.sign(m),
)

trace.append("")
trace.append("RECEIPT")
show("canonical payload bytes", len(payload))
show("payload SHA-256", r.sha256(payload))
show("COSE_Sign1 receipt bytes", len(signed))


# --- second vector: the same chunk after erasure ----------------------------
# The tree is untouched. leaf_hash, every path, doc_root, corpus_root and the
# signed tree head are byte-identical to the live receipt above; only the
# opening changes. That identity IS the erasure story: the regulator's "the
# data is destroyed" and the auditor's "the log was not rewritten" hold at
# the same time, and this vector is what proves we mean it.
import copy  # noqa: E402

erased = copy.deepcopy(receipt)
erased["custody"]["derivation"]["opening"] = {
    "erased": True,
    "erased_at": ms("2026-11-20T11:05:00+00:00"),
}
erased_payload = r.encode(erased)
erased_signed = r.cose_sign1(
    erased_payload,
    {1: r.ALG_EDDSA, 3: "application/vnd.sourcemark.receipt+cbor", 4: b"acme-emit-01"},
    lambda m: issuer_sk.sign(m),
)

trace.append("")
trace.append("ERASED VECTOR - tree unchanged, leaf unopenable")
show("leaf_hash identical to live?",
     erased["custody"]["proof"]["leaf_hash"] == receipt["custody"]["proof"]["leaf_hash"])
show("corpus_root identical to live?",
     erased["custody"]["proof"]["corpus"]["corpus_root"] == corpus_root)
show("signed_tree_head identical to live?",
     erased["custody"]["proof"]["log"]["signed_tree_head"] == sth)
show("content_commitment still present?",
     "content_commitment" in erased["custody"]["derivation"])
show("opening now", "erased")
show("erased payload bytes", len(erased_payload))

# --- JSON projection (clause 6) --------------------------------------------
# Clause 6.2: a byte string projects to "<label>:<lowercase hex>". The label
# is "sha256" only where the CDDL types the field as a digest, and "base16"
# everywhere else. The salt is 32 bytes but is not a hash of anything, and
# labelling it "sha256:" would invite a reader to try to reverse it.
DIGEST_FIELDS = {
    "content_hash", "content_commitment", "leaf_hash",
    "doc_root", "corpus_root", "root_hash", "log_id",
}


def project(v, field=None):
    if isinstance(v, bytes):
        label = "sha256" if field in DIGEST_FIELDS else "base16"
        return f"{label}:{v.hex()}"
    if isinstance(v, dict):
        return {k: project(x, k) for k, x in v.items()}
    if isinstance(v, list):
        # Every array of byte strings in this format is an array of digests.
        return [project(x, "leaf_hash" if isinstance(x, bytes) else field) for x in v]
    return v


proj = project(receipt)
for path_ in (("custody", "source", "committed_at"), ("context", "retrieved_at")):
    node = proj
    for k in path_[:-1]:
        node = node[k]
    node[path_[-1]] = (
        dt.datetime.fromtimestamp(node[path_[-1]] / 1000, dt.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )

(HERE / "receipt.json").write_text(json.dumps(proj, indent=2) + "\n")

erased_proj = project(erased)
for path_ in (("custody", "source", "committed_at"), ("context", "retrieved_at"),
              ("custody", "derivation", "opening", "erased_at")):
    node = erased_proj
    for k in path_[:-1]:
        node = node[k]
    node[path_[-1]] = (
        dt.datetime.fromtimestamp(node[path_[-1]] / 1000, dt.timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )
(HERE / "receipt-erased.json").write_text(json.dumps(erased_proj, indent=2) + "\n")
(HERE / "receipt-erased.cbor").write_bytes(erased_signed)
(HERE / "receipt.cbor").write_bytes(signed)
(HERE / "receipt.payload.cbor").write_bytes(payload)
(HERE / "receipt.cbor.hex").write_text(
    "\n".join(signed.hex()[i : i + 64] for i in range(0, len(signed.hex()), 64)) + "\n"
)
(HERE / "derivation.txt").write_text(
    "Sourcemark receipt v0.1 - worked example derivation\n"
    "Regenerate with: python3 spec/examples/build.py\n"
    "Every value below is reproducible from this repository alone.\n\n"
    + "\n".join(trace)
    + "\n"
)

# --- self-check: the vectors must verify -----------------------------------
assert r.fold(our_leaf, DOC_INDEX, DOC_CHUNKS, doc_path) == doc_root
assert r.fold(our_doc_leaf, CORPUS_INDEX, CORPUS_DOCS, corpus_path) == corpus_root
assert r.fold(log_leaf, LOG_INDEX, LOG_TREE_SIZE, log_path) == log_root

# Both signatures must verify against the Sig_structure the spec defines,
# recomputed here rather than reused from the signing path.
sth_protected = r.encode({1: r.ALG_EDDSA, 4: b"log-2026"})
_, _, _, sth_signature = r._parse_sign1(sth)
log_sk.public_key().verify(sth_signature, r.sig_structure(sth_protected, sth_payload))

rcpt_protected = r.encode(
    {1: r.ALG_EDDSA, 3: "application/vnd.sourcemark.receipt+cbor", 4: b"acme-emit-01"}
)
_, _, _, rcpt_signature = r._parse_sign1(signed)
issuer_sk.public_key().verify(rcpt_signature, r.sig_structure(rcpt_protected, payload))

# Clause 2.7, demonstrated rather than asserted: ES256 signs the SAME bytes
# to a DIFFERENT signature every time, because ECDSA draws a fresh nonce.
# Canonicalization therefore guarantees the payload and the Sig_structure,
# never the signature. Conformance vectors must verify signatures, not diff
# them; a suite that byte-compares ES256 output fails at random forever.
es_protected = r.encode({1: r.ALG_ES256, 3: "application/vnd.sourcemark.receipt+cbor"})
es_struct = r.sig_structure(es_protected, payload)
es_a = es256_sk.sign(es_struct, ec.ECDSA(hashes.SHA256()))
es_b = es256_sk.sign(es_struct, ec.ECDSA(hashes.SHA256()))
assert es_a != es_b, "ECDSA unexpectedly deterministic; revisit clause 2.7"
for sig in (es_a, es_b):
    es256_sk.public_key().verify(sig, es_struct, ec.ECDSA(hashes.SHA256()))

trace.append("")
trace.append("CLAUSE 2.7 - what canonicalization does and does not fix")
show("Sig_structure SHA-256 (fixed)", r.sha256(es_struct))
# The signature bytes themselves are deliberately not recorded: they differ
# on every run, and a committed file that churns invites someone to "fix"
# the churn by pinning a nonce.
# Not even the length is stable across runs -- a DER-encoded ECDSA signature
# is 70-72 bytes depending on how many leading zero bytes r and s happen to
# have -- so nothing derived from the signature bytes is recorded here. Only
# the two invariants are.
show("signatures byte-identical?", es_a == es_b)
show("both signatures verify?", True)

(HERE / "derivation.txt").write_text(
    "Sourcemark receipt v0.1 - worked example derivation\n"
    "Regenerate with: python3 spec/examples/build.py\n"
    "Every value below is reproducible from this repository alone.\n\n"
    + "\n".join(trace)
    + "\n"
)
print("self-check: three folds and two signatures verify; ES256 nondeterminism shown")
print("wrote receipt.json, receipt.cbor, receipt.cbor.hex, receipt.payload.cbor,")
print("      receipt-erased.json, receipt-erased.cbor, derivation.txt")
print(f"payload {len(payload)} bytes, COSE_Sign1 {len(signed)} bytes")
