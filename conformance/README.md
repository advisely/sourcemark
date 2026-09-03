# conformance/ — test vectors

**Licence:** CC0.

A format with two independent implementations is a standard. With one it is a product. This directory is what makes the second implementation possible — and what makes the first one falsifiable.

```bash
python3 conformance/build.py     # regenerate every vector
```

## What is here

| | |
|---|---|
| `manifest.json` | Every vector, its required outcome, its exit status, and which log key it must be checked against |
| `vectors/<name>/receipt.cbor` | The receipt |
| `vectors/<name>/text.txt` | The text it cites |
| `vectors/<name>/expected.json` | The outcome a conforming verifier MUST reach, and why |
| `log-public-key.der`, `rekor-log-public-key.der` | The log keys, SPKI DER |
| `issuer-public-key.der` | For the optional issuer check |
| `source.bin` | A stand-in original document, so the `--source` path is exercisable here |

## The sixteen vectors

| Vector | Outcome | What it is really testing |
|---|---|---|
| `valid` | `VERIFIED` | The happy path |
| `erased` | `ERASED` | Tree unchanged, proofs fold, opening is a tombstone. Reporting `TAMPERED` here is wrong |
| `tampered` | `TAMPERED` | A perfect receipt over text that was edited afterwards |
| `forged` | `FORGED` | One sibling replaced. Signed by a valid issuer key, which is why that signature is the weaker claim |
| `backdated` | `BACKDATED` | The answer predates the commitment it cites |
| `pending` | `PENDING` | Submitted, not yet in this tree head. Reporting `FORGED` calls a race condition an attack |
| `unsigned-bad-signature` | `UNSIGNED` | One flipped bit in the tree head's signature |
| `unsigned-wrong-log` | `UNSIGNED` | **Internally perfect, signed by a real key — just not the log's.** A verifier that checks the head against whichever key travels with the receipt says `VERIFIED` here |
| `malformed-truncated` | `MALFORMED` | A half-finished download is not an attack |
| `malformed-indefinite-length` | `MALFORMED` | Valid RFC 8949, outside the clause 2 profile |
| `malformed-trailing-bytes` | `MALFORMED` | A signed payload with an unsigned appendix |
| `rekor-valid` | `VERIFIED` | The external-log profile: Rekor's leaf format and a signed-note checkpoint |
| `rekor-certificate-submitter` | `VERIFIED` | An X.509 certificate where a public key is expected — **the production shape** |
| `rekor-unpinned-body` | `FORGED` | **Everything folds, and `entry_body` attests a different corpus root.** Skip `canonicalization.md` 5.2 step 3 and this reports `VERIFIED` |
| `rekor-checkpoint-mismatch` | `UNSIGNED` | A valid signature over a different tree than the proof claims |
| `internal-with-entry-body` | `MALFORMED` | A receipt supplying the leaf bytes it is not allowed to choose |

Four of them are the ones worth writing a verifier against. `unsigned-wrong-log`, `rekor-unpinned-body`, `rekor-checkpoint-mismatch` and `internal-with-entry-body` are each internally consistent, each carry real signatures, and each report `VERIFIED` under an implementation that folds proofs without asking what the proof was over. An implementation that returns `VERIFIED` for any of them is non-conforming, and that has to be checkable by someone who does not work here.

## Two properties, stated

**These are adversarial by construction.** Several are receipts this repository's own `Emit` would refuse to issue — it checks the commitment against the text before signing. That refusal is a property of our emitter, not of the format. A verifier that assumes a well-behaved emitter is a verifier that fails exactly when it matters.

**Twelve are byte-reproducible; the four `rekor-*` are not.** They mirror Rekor exactly, which means ECDSA, and ECDSA draws a fresh nonce per signature — so their bytes change on every regeneration while remaining equally valid. That is `canonicalization.md` clause 2.7 in the wild: canonicalization fixes what gets signed, not what a signature looks like. The committed bytes are the fixtures; the `reproducible` flag in the manifest says which is which.

## Synthetic vectors are only half the job

The `rekor-*` vectors are synthetic. They check that we handle the profile correctly; they cannot check that the profile is what we think it is, because they were built from the same assumptions as the code reading them.

That second question is answered by [`sourcemark/tests/test_rekor_live.py`](../sourcemark/tests/test_rekor_live.py), which fetches a real entry from production Rekor, read-only, and confirms the leaf folds and the checkpoint verifies under Rekor's published key. It is not decoration: it is what discovered that production entries carry an **X.509 certificate** where the profile expected a public key — a bug that passed every synthetic fixture and would have failed against every real entry. `rekor-certificate-submitter` exists because of it.
