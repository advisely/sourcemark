# Canonicalization — Sourcemark receipt v0.1

**Licence:** CC0-1.0.
**Status:** Normative. Where this document and [`examples/reference.py`](examples/reference.py) disagree, this document wins and the code is the bug.

Two independent implementations must produce **the same bytes** for the same receipt. Not equivalent bytes, not bytes that compare equal after parsing — the same bytes, because those bytes are what gets hashed and signed. Everything below exists to make that achievable by someone who has never spoken to us.

The key words MUST, MUST NOT, SHOULD, and MAY are to be interpreted as in RFC 2119.

---

## 1. Why this document is separate from the schema

A schema says which fields exist. It does not say what a verifier hashes. Two implementations can both satisfy [`receipt.cddl`](receipt.cddl) and still disagree on every digest in the receipt, because CBOR permits an integer to be encoded five ways, a map to be ordered arbitrarily, and a string to be split into indefinite-length chunks. A format that stops at the schema has specified a data structure and left the security property undefined.

Clause 3 onward defines the preimages. Clause 2 defines the encoding those preimages are written in. Neither is optional.

---

## 2. Deterministic CBOR

The profile is RFC 8949 §4.2.1 Core Deterministic Encoding, with two restrictions added and one relaxation refused. Implemented in `reference.py` under the heading *1. Deterministic CBOR encoding*.

### 2.1 Permitted types

Only these major types appear in a Sourcemark receipt or preimage:

| Major | Type | Used for |
|---|---|---|
| 0 / 1 | unsigned / negative integer | sizes, indices, timestamps, COSE labels |
| 2 | byte string | digests, salts, signatures |
| 3 | text string | identifiers, URIs, enumerated values |
| 4 | array | paths, coordinate tuples, preimages, `Sig_structure` |
| 5 | map | the receipt and its sub-objects |
| 7 | `false` / `true` / `null` / float64 | `proven`, absent optional fields, scores |

Every other construct — tags other than the COSE tag in clause 5, indefinite-length items, `undefined`, simple values outside the above — MUST be rejected on parse. A verifier MUST NOT skip an item it does not recognise. Tolerating unknown structure is how a forged receipt smuggles bytes past a check.

### 2.2 Shortest-form arguments

Every head MUST use the shortest argument encoding that represents its value: values below 24 inline in the initial byte, then one, two, four, eight bytes. `1000` encodes as `19 03e8` and never as `1a 000003e8`.

### 2.3 Definite lengths only

Indefinite-length strings, arrays, and maps MUST NOT be emitted and MUST be rejected on parse.

### 2.4 Integers

Integers MUST use major type 0 when non-negative and major type 1 otherwise. No integer is ever encoded as a float. Timestamps are integers — see clause 6.3.

### 2.5 Map key ordering

Map entries MUST be sorted by the **bytewise lexicographic order of the encoded key**, not by the key's own character order.

For the text keys this format uses, the two orders coincide only while all keys are 23 bytes or shorter. At 24 bytes the head grows from one byte to two, the length prefix changes, and the orders diverge. An implementation that sorts the Python or JavaScript strings instead of their encodings will agree with this spec on every field currently defined and disagree the moment a longer key is added — the worst possible failure shape, because it passes today's tests.

Duplicate keys MUST NOT be emitted and MUST be rejected on parse.

### 2.6 Floats

RFC 8949 core determinism says to encode a float in the shortest form that round-trips. **This profile forbids that.** Any float MUST be encoded as float64 (`0xfb`), always.

The shortest-round-trip rule delegates a signed byte to the encoder's float printer, and float printers have historically differed across languages and versions. Fixing the width costs seven bytes on the two fields that use it and removes the divergence entirely.

Floats appear only in `support.score` and `support.threshold`. `NaN` and the infinities MUST NOT appear.

### 2.7 What canonicalization does not fix

Canonicalization guarantees byte-identity of the **payload** and of the **`Sig_structure`** — the bytes that are hashed. It does not, and cannot, guarantee byte-identity of a signature.

ECDSA (ES256) draws a fresh random nonce per signature, so signing identical bytes twice yields two different, equally valid signatures. Ed25519 is deterministic and does not. Both are conformant.

Two consequences, both load-bearing:

1. A conformance vector MUST pin the payload, or the payload's digest, and MUST **verify** the signature. It MUST NOT compare signature bytes. A suite that diffs an ES256 signature fails at random forever, and the obvious repair — pinning a nonce — destroys the key.
2. "Reproducible receipt" means reproducible payload. Reproducibility claims in marketing material MUST be phrased that way.

`examples/build.py` demonstrates this at the end of `examples/derivation.txt`: one fixed `Sig_structure` digest, two ES256 signatures, not byte-identical, both verifying.

---

## 3. Hashing

`H` denotes SHA-256. `‖` denotes concatenation of byte strings *whose boundaries are already unambiguous*, which in this document means concatenation of fixed-width digests and single-byte prefixes only. It is never used to join variable-length fields; clause 3.3 explains why.

### 3.1 Per-chunk salt

```
info  = encode([ "sourcemark.salt.v1", document_version_id, chunk_id ])
salt  = HKDF-Expand( PRK = version_key, info = info, L = 32 )     # RFC 5869 §2.3
```

`version_key` is a 32-byte secret held in the customer's KMS, one per document version, identified in the receipt by `derivation.salt_ref`. It never appears in a receipt.

HKDF-Extract is skipped: the version key is already a uniformly random KMS secret, so there is no entropy to concentrate.

`docs/SPEC.md` §4.1 placed a single salt on the whole document version until this clause was written; it now matches. The argument is kept because per-version salting is the obvious simplification and will be proposed again. One salt per version is too coarse in both directions. Disclosing a chunk's opening — which clause 3.2 requires — would open every other chunk in that version, and erasure could not be finer-grained than a whole document. Deriving per chunk costs one HMAC at ingest.

### 3.2 Content commitment

```
content_commitment = HMAC-SHA-256( key = salt, message = utf8(chunk_text) )
```

`docs/SPEC.md` §4.1 specified `H(salt ‖ chunk_text)` until this clause was written; it now matches. The reasoning is recorded here because the naive form looks equivalent and is not.

SHA-256 is a Merkle–Damgård construction. An attacker who learns `H(salt ‖ text)` and the length of `salt ‖ text` can compute `H(salt ‖ text ‖ padding ‖ suffix)` for a suffix of their choosing, without ever learning the salt — and thus produce a valid-looking commitment for text that was never ingested. HMAC is not susceptible. The cost is identical.

`chunk_text` MUST be encoded as UTF-8 with no byte-order mark and no normalization applied. Normalizing here would silently change what was committed to; if a pipeline needs normalized text, it must normalize before Anchor sees it, so that the normalized form is what the source is checked against.

### 3.3 Chunk leaf

```
preimage  = encode([
              "sourcemark.leaf.v1",
              document_version_id,      # tstr
              chunk_id,                 # tstr
              page,                     # uint or null
              bbox,                     # [4 * int] or null
              byte_range,               # [2 * uint]
              content_commitment        # bstr .size 32
            ])
leaf_hash = H( 0x00 ‖ preimage )
```

`docs/SPEC.md` §4.1 wrote the leaf as `H(doc_version_id ‖ chunk_id ‖ page ‖ bbox ‖ byte_range ‖ H(salt ‖ chunk_text))` until this clause was written; it now matches.

That form is not a construction, it is an ambiguity. Concatenating variable-length fields destroys their boundaries:

```
("dv_c3e2881", "chk_88a1c")  ->  64765f6333653238383163686b5f38386131633437
("dv_c3e28",  "81chk_88a1c") ->  64765f6333653238383163686b5f38386131633437
```

Two different chunks, one preimage, one leaf hash. Encoding the preimage as a CBOR array makes every boundary explicit in the bytes, at a cost of roughly one byte per field.

The leading `0x00` is the RFC 6962 §2.1 leaf prefix. It is what stops an interior node from being presented as a leaf.

### 3.4 Document leaf

The corpus tree's leaves are document versions.

```
preimage = encode([ "sourcemark.doc.v1", document_version_id, doc_root, doc_tree_size ])
leaf     = H( 0x00 ‖ preimage )
```

Binding `doc_tree_size` prevents a document root from being replayed under a different claimed chunk count.

### 3.5 Domain-separation tags

Every preimage in this document begins with a distinct tag string. The tags currently defined are `sourcemark.salt.v1`, `sourcemark.leaf.v1`, `sourcemark.doc.v1`, and `sourcemark.corpus.v1` (clause 5.1). A new preimage MUST introduce a new tag rather than reuse one, and the `.v1` suffix moves independently of the receipt version.

---

## 4. Merkle trees

All three trees — chunks within a document version, document versions within a batch, entries within the log — use the **RFC 6962 §2.1** shape, unmodified. Nothing here is Sourcemark-specific, which is the point: the algorithm has been implemented and attacked for a decade.

### 4.1 Node hashing

```
empty tree   MTH({})       = H( "" )
single leaf  MTH({d0})     = d0                       # already leaf-hashed per 3.3 / 3.4
n > 1        MTH(D[n])     = H( 0x01 ‖ MTH(D[0:k]) ‖ MTH(D[k:n]) )
```

where `k` is the largest power of two strictly less than `n`. The `0x01` prefix separates interior nodes from leaves.

### 4.2 Inclusion path

The audit path for leaf `i` is the list of sibling hashes from the leaf's level upward, bottom-first, as defined in RFC 6962 §2.1.1.

### 4.3 Folding a path

A verifier folds a path back to a root using the RFC 6962 `fn`/`sn` algorithm, reproduced in `reference.py` as `fold()`.

**Direction is derived from `(leaf_index, tree_size)` and MUST NOT be stored in the receipt.** A stored direction bit is an input the receipt's issuer controls, feeding the one check that exists to be unforgeable.

A verifier MUST reject, rather than silently accept:

- `leaf_index >= tree_size`
- a path longer than the tree is deep
- a path shorter than the tree is deep

All three are exercised in the reference implementation's tests. A fold that terminates early and returns the accumulated value will accept a truncated path, which is a forgery.

---

## 5. Signing

Both signatures use **COSE_Sign1** (RFC 9052 §4.2), tagged with CBOR tag 18, payload embedded (never detached).

`Sig_structure` is `encode([ "Signature1", protected, external_aad, payload ])`, where `external_aad` is always the zero-length byte string.

Algorithms: **Ed25519 (COSE `alg` = -8) is mandatory to implement.** **ES256 (COSE `alg` = -7) is also required**, because Rekor and most Trillian deployments sign tree heads with P-256 and every enterprise KMS and HSM offers it. A verifier that implements only one of the two is non-conforming. No other algorithm is permitted in v0.1.

An ES256 signature MUST be rejected unless its `s` value is in the lower half of the group order. Without that check the signature is malleable: `(r, s)` and `(r, n − s)` both verify, so the same receipt has two valid encodings and any system deduplicating on signature bytes can be made to see two.

### 5.1 Log entry bytes

```
entry_data = encode([ "sourcemark.corpus.v1", corpus_root, committed_at ])
log_leaf   = H( 0x00 ‖ entry_data )
```

**The verifier MUST recompute `entry_data` from `corpus_root` and `committed_at`. The receipt MUST NOT carry it and a verifier MUST NOT accept it if present.** Any byte the receipt supplies to the inclusion check is a byte the issuer chooses.

`proof.log.entry_profile` names the construction. `sourcemark.corpus.v1` is the only value defined in v0.1; a verifier MUST reject any other rather than fall back to trusting supplied bytes.

### 5.2 Signed tree head

The STH payload is a canonical CBOR map:

```
{ "log_id": bstr .size 32, "tree_size": uint, "root_hash": bstr .size 32, "timestamp": uint }
```

signed as COSE_Sign1 with protected header `{ 1: alg, 4: kid }`.

### 5.3 Log identity

```
log_id = H( SubjectPublicKeyInfo DER of the log's public key )
```

A verifier given a log public key MUST recompute `log_id` and compare it to `proof.log.log_id` **before** checking the STH signature. Without that comparison, a receipt naming a log the auditor did not intend to trust verifies cleanly against whichever key was supplied.

### 5.4 The receipt signature is the weaker claim

The receipt as a whole is signed by its issuer, with protected header `{ 1: alg, 3: "application/vnd.sourcemark.receipt+cbor", 4: kid }`.

This signature establishes **accountability**: who asserted this. It is not what makes custody verifiable. Custody rests on the inclusion proofs and the log's signature — parties outside the system under audit. A verifier MUST NOT report `VERIFIED` on the strength of the issuer signature alone, and an implementation that treats the two signatures as interchangeable has rebuilt the trust-me system this format exists to replace.

---

## 6. The JSON projection

[`receipt.schema.json`](receipt.schema.json) describes a projection for debugging and human reading. The CBOR is normative.

### 6.1 The projection is never a signing input

Signatures are computed over CBOR only. A verifier MUST NOT accept JSON as input to any check. The projection exists so that a person can read a receipt, and for no other purpose.

This is what defuses float round-tripping: `support.score` is a float64 in the signed bytes, and whether a JSON printer renders it `0.91` or `0.9100000000000001` affects nothing that is checked.

### 6.2 Byte strings

A byte string projects to `"<label>:<lowercase hex>"`.

The label is `sha256` where the CDDL types the field as `digest`, and `base16` everywhere else. The salt is 32 bytes and is not a digest of anything; labelling it `sha256:` would invite a reader to try to reverse it.

### 6.3 Timestamps

Timestamps are **integer milliseconds since the Unix epoch** in CBOR, and RFC 3339 UTC with exactly three fractional digits and a `Z` suffix in the projection.

The ordering check — did the commitment precede the answer — is the single most security-critical comparison in the system. Making it an integer comparison rather than a date-string parse removes timezone offsets, leap seconds, variable fractional precision, and the whole surface where two verifiers can disagree about which of two instants came first.

---

## 7. Verifying this document

```
python3 spec/examples/build.py
```

Rebuilds every file in `examples/` from scratch and asserts that three folds and two signatures verify. Two runs on two machines MUST produce byte-identical `receipt.payload.cbor`, `receipt.cbor`, `receipt.json`, and `derivation.txt`.

`examples/derivation.txt` records every intermediate value from chunk text to signature. If your implementation reaches a different `leaf_hash` for the example chunk, the divergence is above that line.

No key material is committed. Both example keys are derived from published seed strings in `build.py`, so the vectors regenerate exactly without a private key ever being stored.
