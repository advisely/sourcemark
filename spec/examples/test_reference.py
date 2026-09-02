#!/usr/bin/env python3
"""Tests for the reference implementation.

Run:  python3 spec/examples/test_reference.py

These are the tests canonicalization.md points at. Each one corresponds to a
MUST in that document; a clause with no test here is a clause nobody has
checked.

SPDX-License-Identifier: CC0-1.0
"""

import hashlib
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import reference as r

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

passed = failed = 0


def check(label: str, cond: bool) -> None:
    global passed, failed
    if cond:
        passed += 1
        print(f"  pass  {label}")
    else:
        failed += 1
        print(f"  FAIL  {label}")


def raises(label: str, fn) -> None:
    try:
        fn()
        check(label, False)
    except (ValueError, TypeError):
        check(label, True)


print("clause 2.2 - shortest-form arguments")
check("0..23 inline", r.encode(23) == b"\x17")
check("24 uses one-byte arg", r.encode(24) == b"\x18\x18")
check("1000 uses two bytes, not four", r.encode(1000) == bytes.fromhex("1903e8"))
check("negative integers use major 1", r.encode(-1) == b"\x20")

print("clause 2.5 - map keys sort by ENCODED key, not by string")
# As strings "a"*24 < "z". Encoded, "z" is 61 7a and "a"*24 is 78 18 ...,
# so 0x61 < 0x78 and the order reverses. An implementation that sorts the
# strings agrees with this spec on every field defined today and diverges
# the moment a key longer than 23 bytes is added.
short, long_ = "z", "a" * 24
enc = r.encode({long_: 1, short: 2})
check("string order says long_ first", long_ < short)
check("encoded order puts 'z' first", enc.index(b"\x61z") < enc.index(b"\x78\x18"))
check("ordering is stable regardless of insertion order",
      r.encode({long_: 1, short: 2}) == r.encode({short: 2, long_: 1}))

print("clause 2.6 - floats are always float64")
check("0.91 is nine bytes, 0xfb-prefixed", r.encode(0.91) == bytes.fromhex("fb3fed1eb851eb851f"))
check("1.0 is not shrunk to float16", r.encode(1.0)[0] == 0xFB and len(r.encode(1.0)) == 9)

print("clause 2.1 - unencodable types are refused, not guessed at")
raises("tuple refused", lambda: r.encode((1, 2)))
raises("set refused", lambda: r.encode({1, 2} - set()))

print("clause 3.2 - commitment is HMAC, not H(salt || text)")
salt = bytes(range(32))
c = r.content_commitment(salt, "hello")
check("differs from H(salt || text)", c != r.sha256(salt + b"hello"))
check("matches HMAC-SHA-256", c == __import__("hmac").new(salt, b"hello", hashlib.sha256).digest())

print("clause 3.3 - leaf preimage is unambiguous across field boundaries")
common = dict(page=1, bbox=None, byte_range=[0, 1], commitment=bytes(32))
a = r.leaf_hash(document_version_id="dv_c3e2881", chunk_id="chk_88a1c", **common)
b = r.leaf_hash(document_version_id="dv_c3e28", chunk_id="81chk_88a1c", **common)
check("the concatenation collision does not collide here", a != b)
check("leaf carries the RFC 6962 0x00 prefix",
      a == r.sha256(b"\x00" + r.encode(["sourcemark.leaf.v1", "dv_c3e2881", "chk_88a1c",
                                        1, None, [0, 1], bytes(32)])))

print("clause 3.1 - salt derivation is per chunk, not per version")
vk = bytes(range(32))
check("different chunks derive different salts",
      r.chunk_salt(vk, "dv_1", "chk_a") != r.chunk_salt(vk, "dv_1", "chk_b"))
check("different versions derive different salts",
      r.chunk_salt(vk, "dv_1", "chk_a") != r.chunk_salt(vk, "dv_2", "chk_a"))
check("derivation is deterministic",
      r.chunk_salt(vk, "dv_1", "chk_a") == r.chunk_salt(vk, "dv_1", "chk_a"))

print("clause 4.1 - RFC 6962 tree identities")
check("empty tree is H(\"\")", r.merkle_root([]) == r.sha256(b""))
leaf0 = r.sha256(b"\x00abc")
check("single-leaf tree is the leaf", r.merkle_root([leaf0]) == leaf0)

print("clause 4.3 - folding, exhaustively for n = 1..64")
bad = []
for n in range(1, 65):
    leaves = [r.sha256(b"\x00" + i.to_bytes(2, "big")) for i in range(n)]
    root = r.merkle_root(leaves)
    for i in range(n):
        if r.fold(leaves[i], i, n, r.inclusion_path(leaves, i)) != root:
            bad.append((n, i))
check(f"all 2080 (size, index) pairs fold to the root ({len(bad)} bad)", not bad)

leaves = [r.sha256(b"\x00" + i.to_bytes(2, "big")) for i in range(7)]
root, path = r.merkle_root(leaves), r.inclusion_path(leaves, 3)
tampered = [bytes(32)] + path[1:]
check("a tampered sibling does not fold to the root", r.fold(leaves[3], 3, 7, tampered) != root)
raises("truncated path rejected, not accepted early", lambda: r.fold(leaves[3], 3, 7, path[:-1]))
raises("over-long path rejected", lambda: r.fold(leaves[3], 3, 7, path + [bytes(32)]))
raises("leaf_index >= tree_size rejected", lambda: r.fold(leaves[0], 7, 7, path))

print("clause 5 - ES256 low-s")
sk = ec.derive_private_key(0x1234567890ABCDEF, ec.SECP256R1())
lows = highs = 0
for i in range(40):
    sig = sk.sign(b"msg %d" % i, ec.ECDSA(hashes.SHA256()))
    if r.es256_is_low_s(sig):
        lows += 1
    else:
        highs += 1
check(f"detector distinguishes both halves of the order (low={lows}, high={highs})",
      lows > 0 and highs > 0)

print("clause 2.7 - COSE round-trip")
prot = r.encode({1: r.ALG_EDDSA})
signed = r.cose_sign1(b"payload", {1: r.ALG_EDDSA}, lambda m: b"\x00" * 64)
p_, u_, pay_, sig_ = r._parse_sign1(signed)
check("tagged COSE_Sign1 round-trips", (p_, u_, pay_, sig_) == (prot, {}, b"payload", b"\x00" * 64))
raises("untagged COSE_Sign1 rejected", lambda: r._parse_sign1(signed[1:]))
raises("trailing bytes rejected", lambda: r._parse_sign1(signed + b"\x00"))

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
