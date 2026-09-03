"""Sourcemark -- anchor, emit, adapters.

    from sourcemark import Anchor, Emit, Chunk, Document

Anchor commits at ingest, Emit signs at query time, and neither is the part
that matters most. The part that matters is that a stranger with the receipt,
the cited text, a public key and no access to any of this can reach the same
conclusion offline -- which is why the verifier is a different repository,
`advisely/sourcemark-verify`, and why `spec/` rather than this package is
normative about every byte.

SPDX-License-Identifier: Apache-2.0
"""

from .anchor import Anchor, AnchorStore, CommitResult
from .emit import Emit, Result
from .keys import Ed25519Signer, ErasedError, LocalVersionKeys, VersionKeys
from .log import InProcessLog, LogEntry, TransparencyLog
from .models import Anchoring, Chunk, Document, LogProof, MerkleProof, Opening
from .receipt import SupportClaim

__version__ = "0.1.0.dev0"
__all__ = [
    "Anchor", "AnchorStore", "CommitResult",
    "Emit", "Result",
    "Chunk", "Document", "Anchoring", "MerkleProof", "LogProof", "Opening",
    "SupportClaim",
    "Ed25519Signer", "LocalVersionKeys", "VersionKeys", "ErasedError",
    "InProcessLog", "LogEntry", "TransparencyLog",
]
