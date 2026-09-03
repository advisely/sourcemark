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

import base64
import json
import time
import urllib.error
import urllib.request
import warnings
from dataclasses import dataclass, field
from typing import Protocol

from .crypto import (
    LEAF_PREFIX,
    MerkleTree,
    Signer,
    cose_sign1,
    log_leaf_hash,
    sha256,
)

__all__ = ["LogEntry", "TransparencyLog", "InProcessLog", "RekorLog", "LogError"]


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
    head_format: str = "cose.sth.v1"
    entry_body: bytes | None = None


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


class LogError(RuntimeError):
    """The log could not be reached, or answered with something unusable."""


class RekorLog:
    """Sigstore Rekor, over its v1 HTTP API.

    This is the point of the exercise. `InProcessLog` proves the pipeline is
    self-consistent; Rekor is a log operated by somebody else, signed with a
    key nobody here holds, with an operating history that cannot be
    manufactured after the fact. A 2026 checkpoint cannot be produced in 2028,
    and that is the only property in this system that money cannot buy later.

    Rekor hashes its own canonicalized entry rather than ours, so the receipt
    carries `entry_body` and the verifier re-pins it: the artefact digest
    inside the body must equal H(entry_data) recomputed from corpus_root
    (`canonicalization.md` 5.2). Without that step the body would be an input
    the issuer chooses, which is exactly what 5.1 exists to prevent.

    Submission is signed with `signer`. That key establishes who submitted,
    not who is telling the truth: anyone may submit a corpus root to a public
    log, and doing so does not help them, because the root still has to fold
    from a chunk leaf they cannot forge.
    """

    DEFAULT_URL = "https://rekor.sigstore.dev"

    def __init__(
        self,
        signer,
        *,
        url: str = DEFAULT_URL,
        timeout: float = 30.0,
        public_key_pem: bytes | None = None,
    ) -> None:
        from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

        if not isinstance(getattr(signer, "_key", None), EllipticCurvePrivateKey):
            raise TypeError(
                "Rekor's hashedrekord type takes an ECDSA P-256 submission key. "
                "Pass an Es256Signer; the Ed25519 signer is for receipts and tree heads."
            )
        self.signer = signer
        self.url = url.rstrip("/")
        self.timeout = timeout
        self._public_key_pem = public_key_pem

    # -- HTTP ---------------------------------------------------------------

    def _request(self, path: str, body: bytes | None = None,
                 accept: str = "application/json") -> bytes:
        request = urllib.request.Request(
            f"{self.url}{path}",
            data=body,
            headers={"Accept": accept,
                     **({"Content-Type": "application/json"} if body else {})},
            method="POST" if body else "GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.read()
        except urllib.error.HTTPError as exc:
            raise LogError(f"{self.url}{path} returned {exc.code}: "
                           f"{exc.read()[:200].decode(errors='replace')}") from exc
        except OSError as exc:
            raise LogError(f"{self.url}{path} is unreachable: {exc}") from exc

    def public_key_pem(self) -> bytes:
        """The log's public key. Fetched once, and only for convenience.

        An auditor MUST obtain this out of band. A key fetched from the same
        host that served the proof establishes that the host is consistent
        with itself, which is not a claim anyone needs.
        """
        if self._public_key_pem is None:
            # This endpoint answers PEM, and honours Accept: asking for JSON
            # gets a JSON-quoted string that fails to parse as a key much
            # later, inside the verifier, with no hint of where it came from.
            self._public_key_pem = self._request(
                "/api/v1/log/publicKey", accept="application/x-pem-file")
        if not self._public_key_pem.lstrip().startswith(b"-----BEGIN"):
            raise LogError(
                f"{self.url}/api/v1/log/publicKey did not return PEM: "
                f"{self._public_key_pem[:60]!r}")
        return self._public_key_pem

    def log_id(self) -> bytes:
        from cryptography.hazmat.primitives import serialization

        key = serialization.load_pem_public_key(self.public_key_pem())
        return sha256(key.public_bytes(serialization.Encoding.DER,
                                       serialization.PublicFormat.SubjectPublicKeyInfo))

    # -- submission ---------------------------------------------------------

    def submit(self, entry_data: bytes) -> LogEntry:
        digest = sha256(entry_data)
        signature = self.signer.sign_raw_der(digest)
        proposed = {
            "apiVersion": "0.0.1",
            "kind": "hashedrekord",
            "spec": {
                "data": {"hash": {"algorithm": "sha256", "value": digest.hex()}},
                "signature": {
                    "content": base64.b64encode(signature).decode(),
                    "publicKey": {
                        "content": base64.b64encode(self.signer.public_pem()).decode()
                    },
                },
            },
        }
        raw = self._request("/api/v1/log/entries", json.dumps(proposed).encode())
        return self._entry_from(json.loads(raw), entry_data)

    def fetch(self, log_index: int) -> dict:
        raw = self._request(f"/api/v1/log/entries?logIndex={log_index}")
        return json.loads(raw)

    # -- shaping ------------------------------------------------------------

    def _entry_from(self, response: dict, entry_data: bytes) -> LogEntry:
        try:
            uuid, entry = next(iter(response.items()))
            body = base64.b64decode(entry["body"])
            proof = entry["verification"]["inclusionProof"]
        except (KeyError, StopIteration, ValueError) as exc:
            raise LogError(f"Rekor's response is missing an inclusion proof: {exc}") from exc

        # Do not take Rekor's word for it. If this does not fold here, it will
        # not fold at an auditor's desk either, and finding out now costs one
        # exception instead of one deposition.
        leaf = sha256(LEAF_PREFIX + body)
        path = [bytes.fromhex(h) for h in proof["hashes"]]
        root = bytes.fromhex(proof["rootHash"])
        from .crypto import fold

        folded = fold(leaf, proof["logIndex"], proof["treeSize"], path)
        if folded != root:
            raise LogError("Rekor returned an inclusion proof that does not fold to its "
                           "own root; refusing to write an unverifiable receipt")
        parsed = json.loads(body)
        claimed = parsed.get("spec", {}).get("data", {}).get("hash", {}).get("value")
        if claimed != sha256(entry_data).hex():
            raise LogError("Rekor logged a different artefact digest than we submitted")

        return LogEntry(
            url=self.url,
            log_id=self.log_id(),
            entry_id=uuid,
            leaf_index=proof["logIndex"],
            tree_size=proof["treeSize"],
            path=path,
            root_hash=root,
            signed_tree_head=proof["checkpoint"].encode("utf-8"),
            entry_profile="rekor.hashedrekord.v0.0.1",
            head_format="note.checkpoint.v1",
            entry_body=body,
        )
