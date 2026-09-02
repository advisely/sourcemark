# C2PA assertion profile — Sourcemark receipt v0.1

**Licence:** CC0-1.0.
**Status:** Draft. See §7 for what must be checked against the published C2PA text before this is called normative.

`docs/SPEC.md` §6 commits to emitting a C2PA manifest rather than a bespoke envelope, so that existing C2PA tooling parses the outer structure and we contribute an assertion instead of a stack. This document says exactly what that assertion is.

---

## 1. What is being claimed, and what is not

C2PA describes the provenance of an **asset** — here, the text an AI system emitted. A Sourcemark receipt describes the provenance of one **input** to that asset: a retrieved chunk, and where it came from.

So the two do not overlap and neither subsumes the other:

| | C2PA manifest | Sourcemark receipt |
|---|---|---|
| Subject | the generated answer | one cited chunk |
| Asserts | who produced this asset, with what, from what ingredients | this text is byte-identical to what was ingested at those coordinates, committed at time *T* |
| Signed by | the producing application | the retrieval system, and independently the transparency log |
| Cardinality | one per answer | one per citation, so zero or many per answer |

A C2PA manifest with no Sourcemark assertion says who generated an answer. A Sourcemark receipt with no manifest says where a quotation came from. Neither is a substitute for the other, and no material may imply that a C2PA-signed answer is a verified answer.

## 2. Assertion label

```
dev.sourcemark.retrieval.receipt
```

Reverse-DNS, per C2PA's convention for vendor assertions. The version lives inside the assertion (`receipt_version`), not in the label, so that a manifest carrying receipts of two versions remains well-formed during a migration.

## 3. Assertion data

The assertion payload is CBOR, which is C2PA's native assertion encoding, and is **the `receipt` map defined by [`receipt.cddl`](receipt.cddl)** — the payload, not the COSE_Sign1 envelope.

The envelope is dropped inside a manifest because its signature would be redundant with the C2PA claim signature, which already covers the assertion by hash. Carrying both invites a validator to check one and a reader to believe the other was checked.

**The receipt's custody claim does not depend on either signature.** It rests on the inclusion proofs and the log's signed tree head — parties outside the system under audit. `canonicalization.md` clause 5.4 states this for the standalone envelope and it holds identically here: a validator MUST NOT report a receipt as verified on the strength of a valid C2PA claim signature. The claim signature says the producing application asserted this. Custody is checked by folding the proofs.

When a receipt travels **outside** a manifest — over HTTP, through MCP, as a file on disk — it MUST be the tagged COSE_Sign1 of `receipt.cddl`, because in that setting there is no claim to bind it to.

## 4. Multiple receipts

An answer citing four chunks carries four assertions with the same label. C2PA distinguishes repeated assertions by index in the assertion store; a consumer MUST NOT assume there is exactly one, and MUST NOT merge them.

Ordering carries no meaning. A consumer that needs to associate a receipt with a span of the generated text uses `context.query_id` together with the citation markers in the answer; C2PA assertion order MUST NOT be used for that association.

## 5. Behaviour of a C2PA validator that has never heard of Sourcemark

This is the property that makes the profile worth having, and it should be verified rather than assumed:

1. The assertion is hashed into the claim like any other, so a generic validator's hard binding covers it. Tampering with a receipt inside a manifest breaks the manifest.
2. An unrecognised assertion label does not invalidate a manifest. A generic validator reports the manifest valid and surfaces the assertion as an opaque blob.
3. Consequently a generic validator reports **"this manifest is intact"**, never **"this citation is genuine"**. Those are different sentences and the difference is the entire product.

A Sourcemark-aware consumer performs the checks in [`verification.md`](verification.md) after C2PA validation succeeds. It MUST NOT skip them because the manifest validated.

## 6. Ingredients

Where the producing application already records retrieval inputs as C2PA ingredients, a receipt SHOULD reference the corresponding ingredient so the two views agree. Where it does not, the receipt stands alone; `custody.source.source_uri` and `custody.source.content_hash` identify the document without any ingredient entry.

A Sourcemark receipt MUST NOT be emitted as an ingredient in place of an assertion. An ingredient describes an asset that went into this one; a receipt describes a *proof about a fragment* of such an asset, and flattening the two loses the coordinates.

## 7. Open items — to confirm against the published C2PA specification

These are recorded rather than guessed. Each must be checked against the C2PA text and this document updated before the profile is called normative; `docs/ROADMAP.md` places C2PA assertion registration in Phase 1, which is the right time.

| # | Item |
|---|---|
| 1 | The exact manifest type for unstructured text introduced in C2PA v2.3, and whether a text asset's hard binding is defined over the same structure as a media asset's |
| 2 | Whether `dev.sourcemark.*` requires registration with the C2PA assertion registry, or whether reverse-DNS vendor labels are unreserved |
| 3 | The precise assertion-store indexing rule for repeated labels, to make §4 exact rather than descriptive |
| 4 | Whether a text manifest may be embedded in the answer payload or must travel sidecar, which determines how Emit delivers over HTTP |
| 5 | Whether C2PA's own timestamping interacts with the ordering check in `verification.md` §4.6, and which timestamp wins if they disagree |

Until item 1 is resolved, the COSE_Sign1 form in `receipt.cddl` is the interoperable one, and it is what the verifier and `conformance/` are built against.

## 8. What this profile refuses to do

- It does not extend C2PA. A profile that needs a C2PA change is a profile that ships when C2PA ships.
- It does not claim a C2PA-validated manifest verifies a citation. §5 exists to prevent exactly that reading.
- It does not put the answer text inside the receipt. The receipt commits to the *source* chunk; the answer is the manifest's subject, and duplicating it would create two copies that can disagree.
