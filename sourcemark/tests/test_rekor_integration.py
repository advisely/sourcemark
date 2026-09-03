"""Anchor to a real Rekor, end to end, and check what comes back.

This is the other half of `test_rekor_live.py`. That one reads production and
never writes; this one writes, and therefore points at a **local** Rekor. The
split is the whole design:

    production, read-only   is the format still what the profile says?
    local, read-write       does our client actually work against a real
                            Rekor backed by a real Trillian?

Neither alone is enough, and submitting to production to answer the second
question would put permanent test data in a log that belongs to everybody.

    docker compose -f sourcemark/tests/rekor-compose.yml up -d
    SOURCEMARK_REKOR_WRITE=http://localhost:3010 \
      python3 -m sourcemark.tests.test_rekor_integration
    docker compose -f sourcemark/tests/rekor-compose.yml down -v

Skips, with a printed reason, when the variable is unset. It refuses outright
if pointed at a public host: a test that submits should never be one command
line away from writing into somebody else's log.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import hashlib
import os
import pathlib
import sys
import tempfile
import warnings

_passed, _failed = 0, 0

# A submission is irreversible. Refusing by hostname is crude and correct:
# the failure being prevented is somebody exporting the variable they used
# for the read-only test.
PUBLIC_HOSTS = ("rekor.sigstore.dev", "rekor.sigstage.dev", "log.sourcemark.dev")

TEXT = ("Any deviation from the validated cleaning cycle must be recorded on Form "
        "QA-114b and reviewed by the Qualified Person before the affected batch "
        "is released.")


def check(label: str, condition: bool, detail: str = "") -> None:
    global _passed, _failed
    if condition:
        _passed += 1
        print(f"  pass  {label}" + (f"   {detail}" if detail else ""))
    else:
        _failed += 1
        print(f"  FAIL  {label}" + (f"   {detail}" if detail else ""))


def main() -> int:
    warnings.simplefilter("ignore")
    url = os.environ.get("SOURCEMARK_REKOR_WRITE")
    if not url:
        print("  SKIP  set SOURCEMARK_REKOR_WRITE to a LOCAL Rekor to run "
              "(this suite submits; never point it at a public log)")
        return 0
    if any(host in url for host in PUBLIC_HOSTS):
        print(f"  FAIL  {url} is a public log. This suite submits entries, and a "
              f"submission cannot be withdrawn. Refusing.")
        return 1

    from ..adapters.stores.memory import MemoryStore
    from ..anchor import Anchor
    from ..cbor import decode
    from ..crypto import (
        LEAF_PREFIX, content_commitment, corpus_entry_data, fold, sha256,
    )
    from ..emit import Emit
    from ..keys import Ed25519Signer, Es256Signer, LocalVersionKeys
    from ..log import LogError, RekorLog
    from ..models import Chunk, Document

    submitter = Es256Signer.from_seed(b"sourcemark/integration/submitter")
    try:
        log = RekorLog(submitter, url=url)
        log_id = log.log_id()
    except LogError as exc:
        print(f"  SKIP  no Rekor at {url}: {exc}")
        return 0

    check("the log's public key parses as PEM", len(log_id) == 32,
          f"log_id {log_id.hex()[:16]}…")

    store = MemoryStore()
    keys = LocalVersionKeys(pathlib.Path(tempfile.mkdtemp()) / "k.json", quiet=True)
    issuer = Ed25519Signer.from_seed(b"sourcemark/integration/issuer")

    # Several batches, so the log tree has depth and the path is not empty.
    target = None
    for batch in range(3):
        with Anchor(store=store, log=log, keys=keys, parser="docling@2.3.1") as anchor:
            for d in range(2):
                dv = f"dv_it{batch}{d}"
                doc = Document(f"doc_it{batch}{d}", dv, f"s3://corpus/{dv}.pdf",
                               hashlib.sha256(dv.encode()).digest())
                chunks = []
                for i in range(6):
                    is_target = (batch, d, i) == (2, 1, 3)
                    body = TEXT if is_target else f"filler {dv} paragraph {i}"
                    chunks.append(Chunk(f"{dv}#c{i}", body,
                                        (i * 200, i * 200 + len(body.encode())),
                                        page=1 + i, bbox=(72, 318, 540, 402),
                                        paragraph=f"p-{i}"))
                    if is_target:
                        target = f"{dv}#c{i}"
                anchor.commit(doc, chunks)

    row = store.read(target)
    lp = row.log_proof
    check("the entry uses the Rekor profile", lp.entry_profile == "rekor.hashedrekord.v0.0.1")
    check("and a note checkpoint", lp.head_format == "note.checkpoint.v1")
    check("entry_body travels with the receipt", isinstance(lp.entry_body, bytes))
    check("the checkpoint is UTF-8 text with a signature line",
          lp.signed_tree_head.decode("utf-8").count("\n") >= 4)

    # Rekor's own leaf, folded independently of anything Rekor told us.
    check("Rekor's leaf folds to the root it published",
          fold(sha256(LEAF_PREFIX + lp.entry_body), lp.leaf_index, lp.tree_size,
               lp.path) == lp.root_hash,
          f"entry {lp.leaf_index} of {lp.tree_size}, {len(lp.path)} hashes")

    # The pin that makes entry_body safe to carry.
    import json as _json
    body = _json.loads(lp.entry_body)
    entry_data = corpus_entry_data(row.corpus_proof.root, row.committed_at)
    check("the logged artefact digest is our recomputed corpus entry",
          body["spec"]["data"]["hash"]["value"] == sha256(entry_data).hex())

    # And the whole receipt.
    class OneResult:
        def search(self, query: str, k: int = 1):
            return [type("Row", (), {"chunk_id": target, "text": TEXT})()]

    emit = Emit(OneResult(), store=store, keys=keys, signer=issuer,
                retriever_name="pgvector@0.8.1")
    result = emit.search("deviation")[0]
    check("a receipt is issued", result.receipt is not None)
    payload = decode(decode(result.receipt).value[2])["custody"]
    check("the commitment binds the chunk text",
          content_commitment(payload["derivation"]["opening"]["salt"], TEXT)
          == payload["derivation"]["content_commitment"])
    check("the receipt names the Rekor log we submitted to",
          payload["proof"]["log"]["log_id"] == log_id)

    print(f"\n{_passed} passed, {_failed} failed")
    return 1 if _failed else 0


if __name__ == "__main__":
    sys.exit(main())
