"""Deterministic CBOR, encoder and strict decoder.

`spec/canonicalization.md` clause 2 profiles RFC 8949 4.2.1 with two added
restrictions and one refused relaxation. This module implements that profile
and nothing wider.

It does not use a CBOR library, and that is deliberate rather than
territorial. A canonicalization rule reading "use cbor2" specifies cbor2's
behaviour, not the format's: the day cbor2 changes how it breaks a tie on map
ordering, every receipt ever issued is retroactively either valid or not, and
the spec cannot say which. The bytes are the format, so we own the bytes.

The decoder is strict in the direction that matters. Anything a conforming
encoder would never produce is rejected rather than accepted-and-normalized:
indefinite lengths, non-shortest integer arguments, out-of-order or duplicate
map keys, trailing bytes. `Emit` runs its own output back through it before
handing a receipt out, so a divergence surfaces at the emitter rather than in
front of an auditor.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import struct
from typing import Any

__all__ = ["encode", "decode", "CborError"]


class CborError(ValueError):
    """The bytes are not inside the clause 2 profile."""


# --------------------------------------------------------------------------
# Encoding
# --------------------------------------------------------------------------

_MAJOR_UINT, _MAJOR_NINT, _MAJOR_BSTR, _MAJOR_TSTR = 0, 1, 2, 3
_MAJOR_ARRAY, _MAJOR_MAP, _MAJOR_TAG, _MAJOR_SIMPLE = 4, 5, 6, 7


def _head(major: int, n: int) -> bytes:
    """The shortest argument encoding that can carry n -- clause 2.2.

    Shortest-form is not an optimization. Two encoders that disagree about
    whether 24 takes one byte or two produce different digests for the same
    receipt, and the signature covers the digest.
    """
    if n < 0:
        raise CborError(f"argument must be non-negative, got {n}")
    b = major << 5
    if n < 24:
        return bytes([b | n])
    if n < 0x100:
        return bytes([b | 24, n])
    if n < 0x10000:
        return bytes([b | 25]) + n.to_bytes(2, "big")
    if n < 0x100000000:
        return bytes([b | 26]) + n.to_bytes(4, "big")
    if n < 0x10000000000000000:
        return bytes([b | 27]) + n.to_bytes(8, "big")
    raise CborError(f"argument {n} exceeds 64 bits; no encoding is defined")


def encode(value: Any) -> bytes:
    """Encode one value in the clause 2 profile.

    Unencodable types raise rather than degrade. A silent fallback to
    `str(value)` would put an object's repr inside a signed payload, which is
    the kind of thing that is discovered years later by someone holding a
    receipt that no longer verifies.
    """
    if value is True:
        return b"\xf5"
    if value is False:
        return b"\xf4"
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        if value >= 0:
            return _head(_MAJOR_UINT, value)
        return _head(_MAJOR_NINT, -value - 1)
    if isinstance(value, float):
        # Clause 2.6: always float64. Shrinking to the shortest float that
        # round-trips is the one place RFC 8949 4.2.1 permits a choice, and a
        # choice in a canonical form is a bug with a specification behind it.
        return b"\xfb" + struct.pack(">d", value)
    if isinstance(value, bytes):
        return _head(_MAJOR_BSTR, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _head(_MAJOR_TSTR, len(raw)) + raw
    if isinstance(value, (list, tuple)):
        return _head(_MAJOR_ARRAY, len(value)) + b"".join(encode(v) for v in value)
    if isinstance(value, dict):
        # Clause 2.5: sort by the ENCODED key, not by the Python key. Sorting
        # by Python value orders 10 before 9 for string keys and puts ints and
        # strings in an order that depends on the runtime's comparison rules.
        items = [(encode(k), encode(v)) for k, v in value.items()]
        items.sort(key=lambda kv: kv[0])
        for i in range(1, len(items)):
            if items[i][0] == items[i - 1][0]:
                raise CborError("duplicate map key after encoding")
        return _head(_MAJOR_MAP, len(items)) + b"".join(k + v for k, v in items)
    if isinstance(value, Tagged):
        return _head(_MAJOR_TAG, value.tag) + encode(value.value)
    raise CborError(f"{type(value).__name__} has no encoding in this profile")


class Tagged:
    """A CBOR tag. Only tag 18 (COSE_Sign1) is used by this format."""

    __slots__ = ("tag", "value")

    def __init__(self, tag: int, value: Any) -> None:
        self.tag, self.value = tag, value

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, Tagged)
            and self.tag == other.tag
            and self.value == other.value
        )

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Tagged({self.tag}, {self.value!r})"


# --------------------------------------------------------------------------
# Decoding
# --------------------------------------------------------------------------


def decode(data: bytes) -> Any:
    """Decode exactly one value, rejecting anything outside the profile.

    Trailing bytes are an error. A decoder that stops at the end of the first
    value and ignores the rest lets a signed payload carry an unsigned
    appendix, which two implementations will then disagree about.
    """
    value, offset = _decode_at(data, 0)
    if offset != len(data):
        raise CborError(f"{len(data) - offset} trailing byte(s) after the top-level value")
    return value


def _need(data: bytes, offset: int, n: int) -> None:
    if offset + n > len(data):
        raise CborError("truncated: input ends inside a value")


def _decode_head(data: bytes, offset: int) -> tuple[int, int, int]:
    _need(data, offset, 1)
    initial = data[offset]
    major, info = initial >> 5, initial & 0x1F
    offset += 1
    if info < 24:
        return major, info, offset
    if info == 31:
        raise CborError("indefinite-length item; clause 2.3 forbids it")
    if info > 27:
        raise CborError(f"reserved additional information {info}")
    width = 1 << (info - 24)
    _need(data, offset, width)
    n = int.from_bytes(data[offset : offset + width], "big")
    offset += width
    # Clause 2.2: reject any argument that had a shorter encoding available.
    minimum = (0, 24, 0x100, 0x10000, 0x100000000)[info - 23]
    if n < minimum:
        raise CborError(f"non-shortest argument: {n} encoded in {width} byte(s)")
    return major, n, offset


def _decode_simple(data: bytes, offset: int) -> tuple[Any, int]:
    """Major type 7 never carries a count, so it never goes through _decode_head.

    Routing it there would apply the shortest-form check to a float's bit
    pattern, and reject 0.0 -- whose eight bytes are all zero -- as a
    non-shortest encoding of nothing.
    """
    info = data[offset] & 0x1F
    offset += 1
    if info == 20:
        return False, offset
    if info == 21:
        return True, offset
    if info == 22:
        return None, offset
    if info == 27:
        _need(data, offset, 8)
        return struct.unpack(">d", data[offset : offset + 8])[0], offset + 8
    if info in (25, 26):
        raise CborError("float16/float32; clause 2.6 requires float64")
    if info == 31:
        raise CborError("break code outside an indefinite-length item")
    raise CborError(f"simple value {info} is not defined in this profile")


def _decode_at(data: bytes, offset: int) -> tuple[Any, int]:
    _need(data, offset, 1)
    if data[offset] >> 5 == _MAJOR_SIMPLE:
        return _decode_simple(data, offset)
    major, n, offset = _decode_head(data, offset)

    if major == _MAJOR_UINT:
        return n, offset
    if major == _MAJOR_NINT:
        return -1 - n, offset
    if major == _MAJOR_BSTR:
        _need(data, offset, n)
        return data[offset : offset + n], offset + n
    if major == _MAJOR_TSTR:
        _need(data, offset, n)
        raw = data[offset : offset + n]
        try:
            return raw.decode("utf-8"), offset + n
        except UnicodeDecodeError as exc:
            raise CborError(f"text string is not valid UTF-8: {exc}") from exc
    if major == _MAJOR_ARRAY:
        out = []
        for _ in range(n):
            item, offset = _decode_at(data, offset)
            out.append(item)
        return out, offset
    if major == _MAJOR_MAP:
        out: dict[Any, Any] = {}
        previous: bytes | None = None
        for _ in range(n):
            start = offset
            key, offset = _decode_at(data, offset)
            encoded_key = data[start:offset]
            if previous is not None and encoded_key <= previous:
                raise CborError(
                    "map keys are not in strictly increasing encoded order"
                    if encoded_key != previous
                    else "duplicate map key"
                )
            previous = encoded_key
            value, offset = _decode_at(data, offset)
            out[key] = value
        return out, offset
    if major == _MAJOR_TAG:
        if n != 18:
            raise CborError(f"tag {n} is not defined in this profile")
        inner, offset = _decode_at(data, offset)
        return Tagged(n, inner), offset

    raise CborError(f"unreachable major type {major}")  # pragma: no cover
