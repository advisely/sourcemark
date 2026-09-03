"""Emit -- sign at query time.

A pass-through wrapper around a retriever. It does not re-rank, re-embed,
filter, or otherwise touch retrieval quality: it reads back what Anchor
wrote, derives the openings, and signs. `tests/test_emit.py` asserts the
wrapped retriever returns the identical objects in the identical order, which
is the only form of that promise worth making.

**Where the salt comes from, and why it is not in the store.** A receipt has
to carry the chunk's salt, or an auditor with no KMS access cannot run the
content-binding check -- the one check that ties the proof to actual text.
But if the salt were persisted alongside the chunk, destroying the version
key would erase nothing: the openings would still be sitting in the database.
So Emit derives salts from the version key at query time and caches them in
process.

That cache is the erasure latency, stated plainly. A salt cached before an
erasure stays usable until it expires, so `salt_cache_ttl` is not a
performance knob, it is how long an erasure takes to become true on this
process. `forget()` makes it immediate for a caller who needs that.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from . import receipt as receipt_mod
from .anchor import AnchorStore
from .crypto import Signer, chunk_salt
from .keys import ErasedError, VersionKeys
from .models import Anchoring, Opening
from .receipt import SupportClaim

__all__ = ["Emit", "Result"]


@dataclass
class Result:
    """The retriever's own result object, with a receipt attached.

    Attribute access falls through to the wrapped object, so existing code
    that reads `.text` or `.score` keeps working. `inner` is kept whole and
    unmodified rather than copied field by field, because copying is where a
    wrapper starts quietly changing what the retriever returned.
    """

    inner: Any
    chunk_id: str
    receipt: bytes | None = None
    unavailable: dict | None = None

    def __getattr__(self, name: str) -> Any:
        # Guard the fall-through: without it, anything that touches Result
        # before `inner` is set -- copy, pickle, a debugger -- recurses until
        # the stack runs out, and the traceback names none of the culprits.
        if name.startswith("_") or name == "inner":
            raise AttributeError(name)
        return getattr(self.inner, name)

    def save(self, path: str) -> None:
        if self.receipt is None:
            raise ValueError(
                f"{self.chunk_id} has no receipt: "
                f"{(self.unavailable or {}).get('receipt_unavailable', {}).get('reason', 'unknown')}"
            )
        with open(path, "wb") as fh:
            fh.write(self.receipt)


class Emit:
    def __init__(
        self,
        retriever: Any,
        *,
        store: AnchorStore,
        keys: VersionKeys,
        signer: Signer,
        retriever_name: str = "unknown@0",
        salt_cache_ttl: float = 300.0,
        chunk_id_of: Callable[[Any], str] | None = None,
    ) -> None:
        self._retriever = retriever
        self.store, self.keys, self.signer = store, keys, signer
        self.retriever_name = retriever_name
        self.salt_cache_ttl = salt_cache_ttl
        self._chunk_id_of = chunk_id_of or _default_chunk_id
        self._salts: dict[str, tuple[float, bytes]] = {}
        self._queries = 0

    # -- the wrapper -------------------------------------------------------

    def search(self, *args: Any, **kwargs: Any) -> list[Result]:
        """Call the wrapped retriever, then attach a receipt to each result.

        Ranking is whatever the retriever returned, in the order it returned
        it. Nothing here reorders, drops, or filters -- a result whose chunk
        was never anchored comes back with `receipt_unavailable`, not
        removed, because silently dropping it would change the answer.
        """
        results = self._retriever.search(*args, **kwargs)
        self._queries += 1
        query_id = kwargs.get("query_id") or f"q_{self._queries:08x}"
        retrieved_at = int(time.time() * 1000)

        ids = [self._chunk_id_of(r) for r in results]
        anchorings = self.store.read_many(ids)
        support = kwargs.get("support") or {}

        out = []
        for original, chunk_id in zip(results, ids):
            anchoring = anchorings.get(chunk_id)
            if anchoring is None:
                out.append(Result(original, chunk_id, unavailable=receipt_mod.unavailable(
                    f"chunk {chunk_id} has no anchoring record",
                    remedy="re-anchor the corpus segment containing this chunk",
                    state="NOT_ANCHORED",
                )))
                continue
            out.append(self._sign_one(
                original, anchoring,
                query_id=query_id,
                retrieved_at=retrieved_at,
                support=support.get(chunk_id),
            ))
        return out

    def receipt_for(
        self,
        chunk_id: str,
        *,
        query_id: str,
        retrieved_at: int | None = None,
        support: SupportClaim | None = None,
    ) -> bytes | dict:
        """Issue a receipt for one chunk outside a search."""
        anchoring = self.store.read(chunk_id)
        if anchoring is None:
            return receipt_mod.unavailable(
                f"chunk {chunk_id} has no anchoring record",
                remedy="re-anchor the corpus segment containing this chunk",
                state="NOT_ANCHORED",
            )
        result = self._sign_one(
            None, anchoring,
            query_id=query_id,
            retrieved_at=retrieved_at if retrieved_at is not None else int(time.time() * 1000),
            support=support,
        )
        return result.receipt if result.receipt is not None else result.unavailable

    # -- one receipt -------------------------------------------------------

    def _sign_one(
        self,
        original: Any,
        anchoring: Anchoring,
        *,
        query_id: str,
        retrieved_at: int,
        support: SupportClaim | None,
    ) -> Result:
        try:
            opening = Opening(salt=self._salt_for(anchoring))
        except ErasedError:
            opening = Opening(erased=True)
        structure = receipt_mod.build(
            anchoring, opening,
            query_id=query_id,
            retriever=self.retriever_name,
            retrieved_at=retrieved_at,
            support=support,
        )
        return Result(original, anchoring.chunk_id, receipt=receipt_mod.sign(structure, self.signer))

    def _salt_for(self, anchoring: Anchoring) -> bytes:
        dv = anchoring.document.document_version_id
        cache_key = f"{dv}\x00{anchoring.chunk_id}"
        hit = self._salts.get(cache_key)
        now = time.monotonic()
        if hit is not None and hit[0] > now:
            return hit[1]
        salt = chunk_salt(self.keys.key(dv), dv, anchoring.chunk_id)
        self._salts[cache_key] = (now + self.salt_cache_ttl, salt)
        return salt

    def forget(self, document_version_id: str | None = None) -> int:
        """Drop cached salts, making an erasure effective immediately here.

        Call it on every process that holds an Emit after an erasure. There is
        no way for this process to learn about an erasure on its own: the
        version key is in a KMS, and Emit does not poll it -- polling would
        put the network back on the query path.
        """
        if document_version_id is None:
            n, self._salts = len(self._salts), {}
            return n
        prefix = f"{document_version_id}\x00"
        stale = [k for k in self._salts if k.startswith(prefix)]
        for k in stale:
            del self._salts[k]
        return len(stale)


def _default_chunk_id(result: Any) -> str:
    for attr in ("chunk_id", "id"):
        value = getattr(result, attr, None)
        if value is not None:
            return str(value)
    if isinstance(result, dict) and "chunk_id" in result:
        return str(result["chunk_id"])
    raise AttributeError(
        f"{type(result).__name__} has no chunk_id. Pass chunk_id_of= to Emit "
        f"rather than letting the wrapper guess which field identifies a chunk."
    )
