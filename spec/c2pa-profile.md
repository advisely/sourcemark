# C2PA assertion profile — Sourcemark receipt v0.1

**Licence:** CC0-1.0.
**Status:** Draft, with every open item now resolved against the published specification. Checked against [C2PA v2.3](https://c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html) and confirmed unchanged in v2.4; §7 records what was found. It stays draft until an implementation actually emits and validates one — a profile nobody has run is a design, not a profile.

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

C2PA §6.2.1 requires an entity-specific namespace to **begin with the Internet domain name for the entity**, ordered as Java packages are (`com.litware`, `net.fineartschool`), with each period-separated component matching:

```abnf
entity           = entity-component *( "." entity-component )
entity-component = 1( DIGIT / ALPHA ) *( DIGIT / ALPHA / "-" / "_" )
```

For `sourcemark.dev` that is `dev.sourcemark`, and every component here is well-formed. **No registration is required**: only the `c2pa` namespace is reserved by the specification, and entity namespaces are self-allocated on the strength of owning the domain. The corollary is that the domain is the claim to the label, so letting `sourcemark.dev` lapse would hand someone else the right to mint assertions under it.

The version lives inside the assertion (`receipt_version`), not in the label, so that a manifest carrying receipts of two versions remains well-formed during a migration.

## 3. Assertion data

The assertion payload is CBOR, which is C2PA's native assertion encoding, and is **the `receipt` map defined by [`receipt.cddl`](receipt.cddl)** — the payload, not the COSE_Sign1 envelope.

The envelope is dropped inside a manifest because its signature would be redundant with the C2PA claim signature, which already covers the assertion by hash. Carrying both invites a validator to check one and a reader to believe the other was checked.

**The receipt's custody claim does not depend on either signature.** It rests on the inclusion proofs and the log's signed tree head — parties outside the system under audit. `canonicalization.md` clause 5.4 states this for the standalone envelope and it holds identically here: a validator MUST NOT report a receipt as verified on the strength of a valid C2PA claim signature. The claim signature says the producing application asserted this. Custody is checked by folding the proofs.

When a receipt travels **outside** a manifest — over HTTP, through MCP, as a file on disk — it MUST be the tagged COSE_Sign1 of `receipt.cddl`, because in that setting there is no claim to bind it to.

## 4. Multiple receipts

An answer citing four chunks carries four assertions of the same type. C2PA §6.4 requires assertion labels to be unique within a manifest, and disambiguates repeats by appending a **double underscore and a monotonically increasing index**:

```
dev.sourcemark.retrieval.receipt
dev.sourcemark.retrieval.receipt__1
dev.sourcemark.retrieval.receipt__2
dev.sourcemark.retrieval.receipt__3
```

The first instance carries no suffix. A consumer MUST NOT assume there is exactly one, MUST NOT merge them, and MUST NOT treat `__0` as valid — it is not a form the specification produces.

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

## 7. The five open items, resolved

These were recorded rather than guessed, and have now been checked against the published text. Section numbers are C2PA v2.3; each was confirmed unchanged in v2.4.

**1 — How a text asset is bound.** C2PA §A.7 defines embedding for unstructured text: a `C2PATextManifestWrapper` carrying a complete Manifest Store in JUMBF, encoded as **Unicode Variation Selectors** (U+FE00–U+FE0F and U+E0100–U+E01EF), which are non-rendering by design. The wrapper is `magic` = `C2PATXT\0` (`0x4332504154585400`), `version` = 1, `manifestLength`, then the JUMBF container. Quantity is zero or one per asset.

The hard binding is **not** the same structure as a media asset's: §9.2.4 says a **data hash assertion** shall be used for text embedded this way. That matters for us in one direction only — it is what covers our assertion, so tampering with a receipt inside a manifest breaks the manifest, which is the property §5 above depends on.

**2 — No registration.** See §2. Entity namespaces are self-allocated from a domain you control, and only `c2pa` is reserved.

**3 — `__1`, `__2`, and no `__0`.** See §4. §6.4 gives the exact rule, so that section is now exact rather than descriptive.

**4 — Embedded is available; sidecar is not forced.** §A.7.1 exists precisely for "content intended for copy-paste operations across different systems", so a manifest can ride inside the answer text itself and survive being pasted into an email. Emit may therefore deliver over HTTP either way. Note the cost before choosing it: the variation-selector encoding inflates the payload substantially and is invisible in a diff, so a receipt embedded this way is one nobody will notice has been stripped. For a machine-to-machine path, the sidecar COSE_Sign1 remains the honest default.

**5 — The two timestamps have different subjects, and ours governs the ordering check.** C2PA's is an RFC 3161 countersignature over the *claim signature* (§10.3.2.5), attesting when that signature existed; a manifest carries at most one. Ours attests when the corpus root entered the log. They cannot contradict each other because they are not about the same event, and if they appear to, the log's is the one that matters: it is signed by a party outside the system under audit, while a claim timestamp attests only to the producing application's own signature.

One concrete consequence. C2PA represents time in assertions as **CBOR tag 1, in seconds** (§6.9). A receipt carried as an assertion keeps its own integer-millisecond fields and MUST NOT be converted, because `canonicalization.md` clause 6.3 exists to make the ordering comparison an integer comparison, and rounding to seconds would make two events a few hundred milliseconds apart compare equal — in the one check the whole format turns on.

**What remains before this is normative** is not a question about the specification. It is that nobody has yet emitted a manifest carrying this assertion and validated it with a generic C2PA validator. §5 makes three predictions about what such a validator does; until one has been run, they are predictions.

## 8. What this profile refuses to do

- It does not extend C2PA. A profile that needs a C2PA change is a profile that ships when C2PA ships.
- It does not claim a C2PA-validated manifest verifies a citation. §5 exists to prevent exactly that reading.
- It does not put the answer text inside the receipt. The receipt commits to the *source* chunk; the answer is the manifest's subject, and duplicating it would create two copies that can disagree.
