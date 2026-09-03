"""An in-memory AnchorStore, for tests and the tamper demo.

Deliberately the simplest thing that satisfies the protocol, so that a test
failure is a failure in Anchor or Emit rather than in the fixture.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

from typing import Iterable

from ...models import Anchoring

__all__ = ["MemoryStore"]


class MemoryStore:
    def __init__(self) -> None:
        self._rows: dict[str, Anchoring] = {}

    def write(self, anchorings: list[Anchoring]) -> None:
        for a in anchorings:
            self._rows[a.chunk_id] = a

    def read(self, chunk_id: str) -> Anchoring | None:
        return self._rows.get(chunk_id)

    def read_many(self, chunk_ids: Iterable[str]) -> dict[str, Anchoring]:
        return {cid: self._rows[cid] for cid in chunk_ids if cid in self._rows}

    def __len__(self) -> int:
        return len(self._rows)
