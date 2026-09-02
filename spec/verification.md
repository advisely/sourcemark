# Verification — Sourcemark receipt v0.1

**Licence:** CC0-1.0.
**Status:** Normative.

`spec/`'s acceptance criterion is that a second implementer writes a working verifier **from this directory alone**, without reading the reference implementation — which is why that implementation lives in a separate repository, [`advisely/sourcemark-verify`](https://github.com/advisely/sourcemark-verify). A format document that stops at the schema cannot meet it: knowing which fields exist does not tell you what to check, in what order, or what to conclude. This document is the missing half.

It defines the seven outcomes in [`docs/ARCHITECTURE.md` §7](../docs/ARCHITECTURE.md) as a decision procedure with fixed precedence, so that two conforming verifiers handed the same broken receipt report the *same* failure rather than two defensible ones.

---

## 1. Inputs

| Input | Required | Why |
|---|---|---|
| The receipt | yes | The COSE_Sign1 bytes as received, never a re-encoding |
| The log's public key | yes | Check 1 is meaningless without it |
| The cited text | yes | See §2 |
| The original source file | no | Enables the strongest check, §4.7 |
| A fresher signed tree head | no | Enables consistency checking, out of scope for v0.1 |

The verifier operates entirely offline. It MUST NOT open a network socket, including to fetch `proof.log.url`, resolve `salt_ref`, or report telemetry. The reference implementation makes this a test that fails if a socket opens.

## 2. The cited text is not optional

A verifier MUST NOT report `VERIFIED` without the cited text.

Without it, checks 4.2 and 4.7 cannot run, and every remaining check proves only that *some* leaf is in the tree — not that it is the leaf backing the sentence in front of the auditor. A tool that returns `VERIFIED` for a receipt whose text it never saw has certified the thing the receipt does not say.

An implementation that is handed no text MUST refuse with an error naming the missing input. It MUST NOT downgrade to a weaker verdict, because a weaker verdict rendered in a terminal is read as a pass.

## 3. Outcome precedence

Checks run in this order. **The first failure terminates and is the outcome.**

| # | Check | Outcome on failure |
|---|---|---|
| 0 | Parse and profile conformance | `MALFORMED` (§6) |
| 1 | Log identity and tree-head signature | `UNSIGNED` |
| 2 | Entry covered by this tree head | `PENDING` |
| 3 | Leaf reconstruction and three folds | `FORGED` |
| 4 | Content binding | `TAMPERED`, or `ERASED` (§4.5) |
| 5 | Ordering | `BACKDATED` |
| — | all passed | `VERIFIED`, or `ERASED` if §4.5 deferred |

The order is total and arbitrary in the sense that a doubly-broken receipt has more than one true answer. It is fixed here so implementations never disagree. The rationale for this particular order: report the failure nearest the evidence before the failure in its metadata, and never evaluate anything downstream of a tree head you have not established you can trust.

A verifier MUST NOT continue after a failure and report a "worst" or aggregated outcome. It MUST NOT report a boolean.

---

## 4. The checks

### 4.1 Log identity and tree-head signature → `UNSIGNED`

1. Parse the receipt strictly per [`canonicalization.md`](canonicalization.md) clause 2. Reject indefinite lengths, non-canonical integers, out-of-order or duplicate map keys, unknown tags.
2. Compute `H(SubjectPublicKeyInfo DER)` of the supplied log key and compare to `proof.log.log_id`. **If they differ, stop.** Without this, a receipt naming a log the auditor never chose to trust verifies cleanly against whichever key was handed over.
3. Check `proof.log.signed_tree_head` is a tagged COSE_Sign1 whose `alg` is -8 or -7 and no other value.
4. If `alg` is -7, reject the signature unless its `s` is in the lower half of the P-256 order (`canonicalization.md` clause 5).
5. Rebuild `Sig_structure` and verify against the log key.
6. Check the STH payload's `log_id` equals `proof.log.log_id` and `root_hash` equals `proof.log.root_hash`. A signature over a tree head describing a *different* tree proves nothing about this one.

### 4.2 Entry covered by this tree head → `PENDING`

If `proof.log.leaf_index >= sth.tree_size`, the entry is not yet in the signed tree. Report `PENDING`.

`PENDING` is not a failure. It means "queryable but not yet verifiable", the state in `docs/ARCHITECTURE.md` §6, and it resolves on its own once the batch window closes. Reporting it as `FORGED` would raise an incident over a system working correctly.

### 4.3 Leaf reconstruction and three folds → `FORGED`

1. Recompute `leaf_hash` from `location`, `derivation.chunk_id`, `source.document_version_id` and `derivation.content_commitment` per `canonicalization.md` clause 3.3. Compare to `proof.leaf_hash`. A receipt that misstates its own leaf is `FORGED`, not `TAMPERED` — nothing about the source has been shown to be wrong yet.
2. Fold `proof.document.path` from `proof.leaf_hash` at `(leaf_index, tree_size)`; compare to `proof.document.doc_root`.
3. Recompute the document leaf per clause 3.4 from `document_version_id`, `doc_root` and `proof.document.tree_size`; fold `proof.corpus.path`; compare to `proof.corpus.corpus_root`.
4. Reject unless `proof.log.entry_profile` is exactly `sourcemark.corpus.v1`.
5. **Recompute** the log entry bytes per clause 5.1 from `corpus_root` and `source.committed_at`. Do not accept them from the receipt; reject the receipt if it carries them.
6. Fold `proof.log.path`; compare to `proof.log.root_hash`.

Each fold MUST reject an out-of-range index and a path that is longer or shorter than the tree is deep, rather than returning whatever it accumulated. A fold that terminates early accepts a truncated path, and a truncated path is a forgery.

### 4.4 Content binding → `TAMPERED`

With `opening.salt` present: recompute `HMAC-SHA-256(salt, utf8(cited_text))` and compare to `derivation.content_commitment`. On mismatch, `TAMPERED`.

The text MUST be compared as the exact bytes committed to. A verifier MUST NOT trim whitespace, normalize Unicode, or repair line endings before hashing. Every one of those changes what was committed to, and a verifier that quietly repairs its input has stopped checking anything.

### 4.5 Erasure → `ERASED`

If `derivation.opening` is `{erased: true}`, skip 4.4, continue to 4.5, and report `ERASED` in place of `VERIFIED` at the end.

`ERASED` is not `INVALID`. It is the correct outcome for a chunk whose version key was destroyed: the tree is unchanged, the inclusion proofs still fold, the log has no gap, and no party — including us — can produce a new opening for that leaf. The regulator's "the data is destroyed" and the auditor's "the log was not rewritten" hold simultaneously, which is the entire argument of `docs/SPEC.md` §7.

`examples/receipt-erased.cbor` is the same chunk as `examples/receipt.cbor` after erasure. Its `leaf_hash`, all three paths, both roots and the signed tree head are byte-identical. Only the opening differs. A verifier that reports anything other than `ERASED` for it, or that reports `ERASED` for it while reporting anything other than `VERIFIED` for the live one, is non-conforming.

**What erasure does not do:** it does not reach into receipts already issued and handed to third parties. Those carry their own opening and remain openable. Erasure prevents *future* openings and leaves the log itself revealing nothing. Per-chunk salt derivation confines an already-issued opening to its one chunk. This limitation MUST be stated in any material describing the erasure property; describing it as retroactive would be false.

### 4.6 Ordering → `BACKDATED`

Report `BACKDATED` unless `source.committed_at <= context.retrieved_at`, and unless `sth.timestamp >= source.committed_at`.

This is the check that distinguishes a citation attached before the answer from one invented after it, and it is the reason timestamps are integers rather than parsed date strings (`canonicalization.md` clause 6.3).

A verifier SHOULD also report `BACKDATED` when `context.retrieved_at` lies in its own future by more than a stated tolerance, and MUST name the tolerance it applied. Clock skew is real; silence about it is not acceptable in a timeline check.

### 4.7 Source re-derivation, when `--source` is supplied

Read `location.byte_range` from the original file, and confirm the bytes are identical to the cited text. Then run 4.4 against those bytes rather than against text supplied on the command line.

This is the check an auditor actually wants, and the one the launch gate in `docs/ROADMAP.md` tests: *the document I am holding contains this text at this location, and your system committed to that before it answered.* On mismatch, `TAMPERED`.

A verifier MUST report which of §4.4 and §4.7 it performed. "Verified against text you supplied" and "verified against the document itself" are different claims and MUST NOT render identically.

---

## 5. Reporting

Output MUST name the outcome, and MUST list which checks ran. A receipt verified without `--source` and one verified with it both reach `VERIFIED` by this procedure, and a tool that renders them identically has thrown away the distinction the auditor is paying for.

Output MUST NOT contain the words "proven", "correct", or "accurate" in reference to the answer. Custody is not support (`docs/SPEC.md` §5). A `VERIFIED` receipt whose `support.class` is `UNSUPPORTED` is a correctly functioning receipt reporting a failed answer, and the report has to be able to say so.

## 6. `MALFORMED` is an error, not a verdict

A receipt that does not parse, or that violates the clause 2 profile, yields `MALFORMED`.

This is deliberately outside the seven outcomes of `docs/ARCHITECTURE.md` §7, which describe the verification of a well-formed receipt. It needs a name because the alternative is worse in both directions: reporting `FORGED` labels a truncated download as an attack, and returning an error the caller might treat as absence turns "I could not read this" into "nothing was wrong".

A verifier MUST exit with a distinct non-zero status for `MALFORMED`, separate from the status used for a failing verdict.

## 7. Exit statuses

| Status | Meaning |
|---|---|
| 0 | `VERIFIED` |
| 1 | `TAMPERED`, `FORGED`, `BACKDATED`, `UNSIGNED` — a custody failure |
| 2 | `MALFORMED` — unreadable input |
| 3 | `PENDING` — not yet verifiable, retry later |
| 4 | `ERASED` — verifiable as anchored, not openable |
| 64 | Usage error, including a missing cited text (§2) |

Distinct statuses exist so that a CI job can treat `PENDING` as a retry and `ERASED` as a pass-with-note without parsing human-readable output.
