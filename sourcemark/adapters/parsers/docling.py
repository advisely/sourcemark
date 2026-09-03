"""Docling coordinate adapter.

Docling already emits everything Anchor needs; this normalizes it. Two things
it does not do, and both are the point:

It does not re-parse, and it does not touch the text. The bytes committed to
must be the bytes the retriever will later return, and a normalization step
here -- Unicode NFC, whitespace collapsing, a stray `.strip()` -- silently
changes what was committed while leaving every hash internally consistent.
The mismatch then surfaces years later, at an auditor's desk, as a `TAMPERED`
verdict on a document nobody touched. Normalize before Anchor sees the text,
so that the normalized form is what the source file is checked against.

It also does not invent a byte range. Docling reports bbox and page for a
layout item; the byte range comes from the extracted text stream. Where a
document has no usable byte offsets, this raises instead of guessing, because
`byte_range` is the coordinate an auditor re-derives without a parser and a
wrong one fails the strongest check in the format.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

from typing import Any, Iterable

from ...models import Chunk

__all__ = ["chunks", "PARSER_ID"]

PARSER_ID = "docling"


def _get(item: Any, *names: str, default: Any = None) -> Any:
    for name in names:
        if isinstance(item, dict):
            if name in item:
                return item[name]
        elif hasattr(item, name):
            return getattr(item, name)
    return default


def _bbox(item: Any) -> tuple[int, int, int, int] | None:
    raw = _get(item, "bbox", "bounding_box")
    if raw is None:
        return None
    if isinstance(raw, dict):
        try:
            values = [raw["l"], raw["t"], raw["r"], raw["b"]]
        except KeyError:
            values = [raw[k] for k in ("x0", "y0", "x1", "y1")]
    else:
        values = list(raw)
    if len(values) != 4:
        raise ValueError(f"bbox must have four values, got {values!r}")
    # Rounded to integers in PDF user space. Sub-point precision is below what
    # any renderer agrees on, and a float in a hash preimage is a float two
    # implementations can format differently.
    return tuple(int(round(float(v))) for v in values)  # type: ignore[return-value]


def chunks(items: Iterable[Any], *, id_prefix: str = "chk") -> list[Chunk]:
    """Normalize Docling layout items into `Chunk`s.

    Accepts dicts or objects, because Docling's shape has moved between minor
    versions and pinning to one of them would make this adapter a liability
    rather than an integration.
    """
    out: list[Chunk] = []
    for n, item in enumerate(items):
        text = _get(item, "text", "content")
        if text is None:
            raise ValueError(f"item {n} has no text")
        span = _get(item, "byte_range", "byte_span", "offsets")
        if span is None:
            start = _get(item, "start_offset", "start")
            end = _get(item, "end_offset", "end")
            if start is None or end is None:
                raise ValueError(
                    f"item {n} has no byte range. Anchor will not guess one: it is "
                    f"the coordinate an auditor re-derives from the original file, "
                    f"and a wrong one fails the check that matters most."
                )
            span = (start, end)
        chunk_id = _get(item, "chunk_id", "id") or f"{id_prefix}_{n:06d}"
        page = _get(item, "page", "page_no")
        out.append(
            Chunk(
                chunk_id=str(chunk_id),
                text=str(text),
                byte_range=(int(span[0]), int(span[1])),
                page=int(page) if page is not None else None,
                bbox=_bbox(item),
                paragraph=_get(item, "paragraph", "label"),
            )
        )
    return out
