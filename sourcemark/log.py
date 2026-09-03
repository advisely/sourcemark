"""Transparency log clients.

A receipt's strongest claim is that a root was in an append-only log at a
stated size, signed by a key the issuer does not hold. Everything else in the
receipt is arithmetic an auditor can redo; this is the part that requires a
second party.

Which is why `InProcessLog` below carries a warning rather than a feature
list. A log you operate yourself, signed with a key you hold, proves that you
are consistent with yourself. That is worth something for detecting your own
bugs and nothing at all for the threat this format exists to address. It is
here so the pipeline is testable offline and so `build.py`-style fixtures can
exist -- Rekor and Trillian arrive in Phase 0 deliverable 6.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import time
import warnings
from dataclasses import dataclass, field
from typing import Protocol

from .crypto import (
    MerkleTree,
    Signer,
    cose_sign1,
    log_leaf_hash,
    sha256,
)

__all__ = ["LogEntry", "TransparencyLog", "InProcessLog"]


@dataclass(frozen=True)
class LogEntry:
    """One submitted root, with everything a receipt needs to prove it.

    Frozen at the tree size the log had when the entry was incorporated. An
    inclusion proof is relative to a tree size, and the signed tree head that
    fixes that size travels with the proof -- which is what lets Emit stay
    offline. A proof fetched at query time would put a network round trip on
    the query path and make every receipt depend on the log being up.
    """

    url: str
    log_id: bytes
    entry_id: str
    leaf_index: int
    tree_size: int
    path: list[bytes]
    root_hash: bytes
    signed_tree_head: bytes
    entry_profile: str = "sourcemark.corpus.v1"


class TransparencyLog(Protocol):
    def submit(self, entry_data: bytes) -> LogEntry:
        """Submit one entry and block until it is incorporated and provable."""


@dataclass
class InProcessLog:
    """An RFC 6962 log in memory. Real tree, real proofs, wrong trust model.

    Use it in tests and in the tamper demo. Do not use it to make a claim to
    anyone who was not in the room, and do not let it become the default in
    a deployment guide: the entire argument for a transparency log is that
    somebody other than the issuer signs the tree head.
    """

    signer: Signer
    url: str = "inprocess://sourcemark/dev"
    log_id: bytes = b""
    _leaves: list[bytes] = field(default_factory=list, repr=False)
    _warned: bool = field(default=False, repr=False)

    def __post_init__(self) -> None:
        if not self.log_id:
            # log_id is H(SubjectPublicKeyInfo DER) so that an auditor can
            # confirm the key they were handed is the key the receipt names.
            spki = getattr(self.signer, "public_spki_der", None)
            self.log_id = sha256(spki()) if spki else sha256(self.signer.kid)
        if not self._warned:
            self._warned = True
            warnings.warn(
                "InProcessLog signs its own tree heads with a key this process "
                "holds. Receipts anchored to it prove self-consistency and "
                "nothing more. Point at Rekor or a Trillian instance before "
                "showing a receipt to anyone.",
                stacklevel=3,
            )

    @property
    def size(self) -> int:
        return len(self._leaves)

    def submit(self, entry_data: bytes) -> LogEntry:
        index = len(self._leaves)
        self._leaves.append(log_leaf_hash(entry_data))
        tree = MerkleTree(self._leaves)
        timestamp_ms = int(time.time() * 1000)
        sth = cose_sign1(
            _encode_sth(self.log_id, tree.size, tree.root, timestamp_ms),
            {1: self.signer.alg, 4: self.signer.kid},
            self.signer,
        )
        return LogEntry(
            url=self.url,
            log_id=self.log_id,
            entry_id=f"0x{index:08x}",
            leaf_index=index,
            tree_size=tree.size,
            path=tree.path(index),
            root_hash=tree.root,
            signed_tree_head=sth,
        )


def _encode_sth(log_id: bytes, tree_size: int, root_hash: bytes, timestamp_ms: int) -> bytes:
    from .cbor import encode

    return encode({
        "log_id": log_id,
        "tree_size": tree_size,
        "root_hash": root_hash,
        "timestamp": timestamp_ms,
    })
