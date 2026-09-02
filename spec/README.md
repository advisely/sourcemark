# spec/ — the receipt format

**Licence:** CC0 / public domain. A format nobody may implement freely is not a standard.

## Contents

| File | Status | What it settles |
|---|---|---|
| [`receipt.cddl`](receipt.cddl) | normative | The shape of a receipt, in CDDL (RFC 8610) |
| [`canonicalization.md`](canonicalization.md) | normative | Byte-exact encoding and every hash preimage |
| [`verification.md`](verification.md) | normative | The seven outcomes as an ordered decision procedure |
| [`receipt.schema.json`](receipt.schema.json) | non-normative | JSON projection, for debugging and human reading |
| [`c2pa-profile.md`](c2pa-profile.md) | draft | The C2PA v2.3 assertion profile — open items in its §7 |
| [`examples/`](examples/) | — | A worked example, reproducible from this directory alone |

`receipt.cddl` and `canonicalization.md` are both normative and neither is sufficient. A schema says which fields exist; it does not say what a verifier hashes. Two implementations can satisfy the grammar and still disagree on every digest in the receipt.

## Running it

```bash
python3 spec/examples/build.py            # rebuild every vector from scratch
python3 spec/examples/test_reference.py   # 29 tests, one per MUST in canonicalization.md
python3 spec/examples/validate.py         # example vs JSON schema, 13 negative controls, CDDL drift
```

`build.py` is deterministic: two runs on two machines produce byte-identical output, and `examples/derivation.txt` records every intermediate value from chunk text to signature. No key material is committed — both example keys derive from published seed strings.

## Acceptance

A second implementer writes a working verifier **from this directory alone**, without reading the reference verifier. Until that is true, this is a product, not a format.

That verifier lives in a separate repository — [`advisely/sourcemark-verify`](https://github.com/advisely/sourcemark-verify) — so the criterion is a boundary rather than a promise.

That criterion is why `verification.md` exists: knowing the field layout does not tell you what to check, in what order, or what to conclude, and a verifier written without that is a verifier that disagrees with ours on the first broken receipt.

## Where this contradicts docs/SPEC.md

Three constructions in `docs/SPEC.md` §4 do not survive being written down precisely. Each deviation is argued at the point it is made, and `docs/SPEC.md` should be updated to match.

| `docs/SPEC.md` says | This directory says | Why |
|---|---|---|
| `leaf = H(a ‖ b ‖ c ‖ …)` | CBOR-array preimage | Concatenating variable-length fields is ambiguous — two different chunks can produce one leaf. Demonstrated in `canonicalization.md` 3.3 |
| `H(salt ‖ chunk_text)` | `HMAC-SHA-256(salt, chunk_text)` | SHA-256 is length-extendable; the naive form lets a forger commit to text nobody ingested, without the salt |
| one salt per document version, held only in KMS | per-chunk salt, disclosed in the receipt | The launch gate's auditor has no KMS access, so the content-binding check was unrunnable by the one party the format serves |
| a single flat `inclusion_path` (§6) vs. two trees (§4.1) | three folds: chunk → document → corpus → log | §4.1 and §6 contradict each other, and the log's own tree is a third hop that check 4 requires |

## Depends on

Nothing. This ships first — see [`docs/ROADMAP.md`](../docs/ROADMAP.md).
