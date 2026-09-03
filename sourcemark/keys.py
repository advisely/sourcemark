"""Key custody: version keys for erasure, and the signing key for receipts.

Two different secrets live here and they fail differently.

The **version key** is per document version. Every chunk's salt derives from
it, and destroying it is what cryptographic erasure *is*. Losing it by
accident is indistinguishable from erasing the document on purpose, so it
belongs in a KMS with the same care as any other deletion-capable credential.

The **signing key** signs receipts. Losing it stops new receipts being
issued; leaking it lets someone else issue receipts in your name. Note which
one that is not: it does not let them forge inclusion in the transparency
log, because the log signs its own tree heads with a key nobody here holds.
That asymmetry is the reason `spec/canonicalization.md` clause 5 says the
receipt signature is the weaker claim.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import json
import os
import pathlib
import secrets
import warnings
from typing import Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .crypto import ALG_EDDSA, sha256

__all__ = ["VersionKeys", "LocalVersionKeys", "Ed25519Signer", "ErasedError"]


class ErasedError(LookupError):
    """The version key is gone. This is a correct outcome, not a fault."""


class VersionKeys(Protocol):
    """Whatever holds version keys. In production this is a KMS client."""

    def create(self, document_version_id: str) -> str:
        """Mint a key for a document version; return its reference."""

    def key(self, document_version_id: str) -> bytes:
        """Return the 32-byte version key, or raise ErasedError."""

    def ref(self, document_version_id: str) -> str:
        """The handle recorded in a receipt's `salt_ref`."""

    def destroy(self, document_version_id: str) -> None:
        """Erase. Idempotent: erasing twice is not an error."""


class LocalVersionKeys:
    """A file-backed version-key store, for development and tests.

    This is not a KMS and does not pretend to be one. The keys sit in a JSON
    file next to the code, which means a filesystem backup silently
    resurrects a key that erasure was supposed to destroy -- and an erasure
    you cannot prove happened is not an erasure. It warns once, loudly,
    because a dev-mode default that stays quiet is a dev-mode default that
    reaches production.
    """

    _warned = False

    def __init__(self, path: str | os.PathLike[str], *, quiet: bool = False) -> None:
        self.path = pathlib.Path(path)
        if not quiet and not LocalVersionKeys._warned:
            LocalVersionKeys._warned = True
            warnings.warn(
                "LocalVersionKeys stores version keys in a plain file. Erasure "
                "cannot be demonstrated against a store that gets backed up. "
                "Use a KMS-backed VersionKeys in production.",
                stacklevel=2,
            )
        self._keys: dict[str, str] = {}
        self._tombstones: set[str] = set()
        if self.path.exists():
            raw = json.loads(self.path.read_text())
            self._keys = raw.get("keys", {})
            self._tombstones = set(raw.get("erased", []))

    def _flush(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps({"keys": self._keys, "erased": sorted(self._tombstones)}, indent=2)
        )

    def create(self, document_version_id: str) -> str:
        if document_version_id in self._tombstones:
            raise ErasedError(
                f"{document_version_id} was erased; re-minting a key would "
                f"resurrect a document version that a deletion request destroyed"
            )
        self._keys.setdefault(document_version_id, secrets.token_bytes(32).hex())
        self._flush()
        return self.ref(document_version_id)

    def key(self, document_version_id: str) -> bytes:
        if document_version_id in self._tombstones:
            raise ErasedError(f"{document_version_id} has been erased")
        try:
            return bytes.fromhex(self._keys[document_version_id])
        except KeyError:
            raise LookupError(f"no version key for {document_version_id}") from None

    def ref(self, document_version_id: str) -> str:
        return f"local://{self.path.name}/{document_version_id}"

    def destroy(self, document_version_id: str) -> None:
        self._keys.pop(document_version_id, None)
        self._tombstones.add(document_version_id)
        self._flush()


class Ed25519Signer:
    """Ed25519 (COSE alg -8), mandatory to implement per clause 5.

    Deterministic by construction, which is why the committed example vectors
    are signed with it: two runs of the same build produce the same bytes.
    ES256 would not, and a vector that changes on every regeneration cannot
    be a fixture.
    """

    def __init__(self, private_key: Ed25519PrivateKey, *, kid: bytes | None = None) -> None:
        self._key = private_key
        # Default kid is H(SubjectPublicKeyInfo DER), so a key identifies
        # itself and a verifier can confirm the key it was handed is the key
        # the receipt names. A deployment that prefers its own label -- a KMS
        # alias, a rotation slot -- passes one; the CDDL types kid as an
        # opaque bstr precisely so that choice stays local.
        self._kid = kid if kid is not None else sha256(self.public_spki_der())

    @classmethod
    def generate(cls, *, kid: bytes | None = None) -> "Ed25519Signer":
        return cls(Ed25519PrivateKey.generate(), kid=kid)

    @classmethod
    def from_seed(cls, seed: bytes, *, kid: bytes | None = None) -> "Ed25519Signer":
        """Derive a key from a seed. For tests and reproducible examples only:
        a seed that is written down is a private key that is written down."""
        return cls(Ed25519PrivateKey.from_private_bytes(sha256(seed)), kid=kid)

    @property
    def alg(self) -> int:
        return ALG_EDDSA

    @property
    def kid(self) -> bytes:
        return self._kid

    def public_key(self) -> Ed25519PublicKey:
        return self._key.public_key()

    def public_spki_der(self) -> bytes:
        return self._key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)
