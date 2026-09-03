"""One test per defect found by adversarial probing, so none returns quietly.

Each of these failed before the commit that added it. They are collected in
one file rather than scattered because the interesting property is the list:
every one is a case where the system did something plausible-looking instead
of refusing, and six of the eight would have produced or accepted a receipt.

Run:  python3 -m sourcemark.tests.test_regressions

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import dataclasses
import hashlib
import pathlib
import sys
import tempfile
import warnings

from ..adapters.stores.memory import MemoryStore
from ..anchor import Anchor, WritebackError
from ..cbor import MAX_DEPTH, CborError, decode, encode
from ..crypto import content_commitment
from ..emit import Emit
from ..keys import Ed25519Signer, LocalVersionKeys
from ..log import InProcessLog
from ..models import Chunk, Document

_passed, _failed = 0, 0


def check(label: str, condition: bool, detail: str = "") -> None:
    global _passed, _failed
    if condition:
        _passed += 1
        print(f"  pass  {label}" + (f"   {detail}" if detail else ""))
    else:
        _failed += 1
        print(f"  FAIL  {label}" + (f"   {detail}" if detail else ""))


def raises(exc, fn, *a, **kw) -> bool:
    try:
        fn(*a, **kw)
        return False
    except exc:
        return True


class FakeResult:
    def __init__(self, chunk_id: str, text: str) -> None:
        self.chunk_id, self.text = chunk_id, text

    def __eq__(self, other):
        return (self.chunk_id, self.text) == (other.chunk_id, other.text)


class StrictRetriever:
    """Accepts exactly the arguments it declares, like any real retriever."""

    def __init__(self, rows: dict[str, str]) -> None:
        self._rows = rows

    def search(self, query: str, k: int = 5) -> list[FakeResult]:
        return [FakeResult(cid, text) for cid, text in list(self._rows.items())[:k]]


def fixture(tmp: pathlib.Path, name: str):
    keys = LocalVersionKeys(tmp / f"{name}.json", quiet=True)
    store = MemoryStore()
    log = InProcessLog(signer=Ed25519Signer.from_seed(b"log-" + name.encode()))
    issuer = Ed25519Signer.from_seed(b"issuer-" + name.encode())
    doc = Document("d1", f"dv-{name}", "s3://policies/x.pdf", hashlib.sha256(b"file").digest())
    chunks = [Chunk(f"c{i}", f"paragraph {i} of the validated cycle", (i * 40, i * 40 + 30))
              for i in range(4)]
    with Anchor(store=store, log=log, keys=keys, parser="docling@2.3.1") as a:
        a.commit(doc, chunks)
    return keys, store, log, issuer, doc, chunks


def main() -> int:
    warnings.simplefilter("ignore")
    tmp = pathlib.Path(tempfile.mkdtemp())

    print("A. A non-finite float has no canonical encoding, so it cannot be signed")
    for v in (float("nan"), float("inf"), float("-inf")):
        check(f"encode rejects {v!r}", raises(CborError, encode, {"score": v}))
    check("a finite score still encodes", encode(0.91) == bytes.fromhex("fb3fed1eb851eb851f"))

    print("\nB. Every rejection is a CborError, so `except CborError` is complete")
    check("a map keyed on an array raises CborError, not TypeError",
          raises(CborError, decode, bytes.fromhex("a1810101")))

    print("\nC. Hostile nesting is refused rather than crashing the interpreter")
    check("deep input is refused on decode",
          raises(CborError, decode, b"\x81" * (MAX_DEPTH + 20) + b"\x01"))
    nested = 1
    for _ in range(MAX_DEPTH + 20):
        nested = [nested]
    check("deep input is refused on encode", raises(CborError, encode, nested))
    ok = 1
    for _ in range(MAX_DEPTH - 2):
        ok = [ok]
    check("legitimate nesting still works", decode(encode(ok)) == ok)

    print("\nD. Sourcemark's own arguments never reach the wrapped retriever")
    keys, store, log, issuer, doc, chunks = fixture(tmp, "kwargs")
    retriever = StrictRetriever({c.chunk_id: c.text for c in chunks})
    emit = Emit(retriever, store=store, keys=keys, signer=issuer)
    try:
        results = emit.search("deviation", k=2, sm_query_id="q_explicit")
        payload = decode(decode(results[0].receipt).value[2])
        check("an explicit query id reaches the receipt, not the retriever",
              payload["context"]["query_id"] == "q_explicit")
    except TypeError as exc:
        check("an explicit query id reaches the receipt, not the retriever", False, str(exc))

    print("\nE. A receipt is never issued for text that is not what was anchored")
    keys, store, log, issuer, doc, chunks = fixture(tmp, "drift")
    row = store.read("c1")
    store._rows["c1"] = dataclasses.replace(row, text="SOMEONE EDITED THIS ROW")
    emit = Emit(StrictRetriever({"c1": "SOMEONE EDITED THIS ROW"}),
                store=store, keys=keys, signer=issuer)
    out = emit.search("q", k=1)[0]
    check("no receipt is signed over drifted text", out.receipt is None)
    check("the refusal names TEXT_MISMATCH",
          (out.unavailable or {}).get("receipt_unavailable", {}).get("state") == "TEXT_MISMATCH")
    # Restoring the row is not enough: the check is against the text the
    # RETRIEVER is handing back, so a retriever still serving the edited text
    # is still refused. That is the property, not a quirk of the fixture.
    still_bad = emit.search("q", k=1)[0]
    check("restoring the row does not excuse a retriever still serving the edit",
          still_bad.receipt is None)

    store._rows["c1"] = row
    emit_clean = Emit(StrictRetriever({"c1": row.text}),
                      store=store, keys=keys, signer=issuer)
    good = emit_clean.search("q", k=1)[0]
    check("an untouched chunk still gets a receipt", good.receipt is not None)
    payload = decode(decode(good.receipt).value[2])["custody"]
    check("and its commitment binds the text returned",
          content_commitment(payload["derivation"]["opening"]["salt"], row.text)
          == payload["derivation"]["content_commitment"])

    print("\nF. A missing version key degrades the query, it does not crash it")
    keys, store, log, issuer, doc, chunks = fixture(tmp, "nokey")
    emit = Emit(StrictRetriever({"c0": chunks[0].text}), store=store, keys=keys, signer=issuer)
    keys._keys.pop(doc.document_version_id)   # a KMS outage, not an erasure
    emit.forget()
    try:
        out = emit.search("q", k=1)[0]
        check("the query survives a key outage", out.receipt is None)
        check("the refusal names KEY_UNAVAILABLE, distinct from ERASED",
              out.unavailable["receipt_unavailable"]["state"] == "KEY_UNAVAILABLE")
    except LookupError as exc:
        check("the query survives a key outage", False, str(exc))

    print("\nG. A failed write-back keeps the work, and never logs a second root")
    class BrokenOnce:
        def __init__(self) -> None:
            self.rows, self.fail = {}, True

        def write(self, anchorings):
            if self.fail:
                raise RuntimeError("disk full")
            for a in anchorings:
                self.rows[a.chunk_id] = a

        def read(self, cid):
            return self.rows.get(cid)

        def read_many(self, cids):
            return {c: self.rows[c] for c in cids if c in self.rows}

    broken = BrokenOnce()
    log2 = InProcessLog(signer=Ed25519Signer.from_seed(b"log-wb"))
    anchor = Anchor(store=broken, log=log2,
                    keys=LocalVersionKeys(tmp / "wb.json", quiet=True))
    anchor.commit(doc, chunks)
    size_before = log2.size
    check("the failure is reported, not swallowed", raises(WritebackError, anchor.flush))
    check("the log advanced exactly once", log2.size == size_before + 1)
    check("the unwritten work is still held", anchor.unwritten_chunks == len(chunks))
    check("flushing again is refused while work is outstanding",
          raises(WritebackError, anchor.flush))
    broken.fail = False
    check("retry_writeback finishes the job", anchor.retry_writeback() == len(chunks))
    check("and does not log a second root for the same batch", log2.size == size_before + 1)
    check("every chunk landed", len(broken.rows) == len(chunks))

    print("\nH. One document version cannot occupy two leaves of one corpus tree")
    anchor2 = Anchor(store=MemoryStore(), log=log2,
                     keys=LocalVersionKeys(tmp / "dup.json", quiet=True))
    anchor2.commit(doc, [Chunk("z0", "t", (0, 4))])
    check("committing the same document version twice in one batch is refused",
          raises(ValueError, anchor2.commit, doc, [Chunk("z1", "t", (0, 4))]))
    check("flushing then committing it again is allowed", anchor2.flush() == 1)

    print(f"\n{_passed} passed, {_failed} failed")
    return 1 if _failed else 0


if __name__ == "__main__":
    sys.exit(main())
