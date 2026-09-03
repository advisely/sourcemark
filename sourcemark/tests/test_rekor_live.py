"""Our understanding of Rekor's format, checked against production Rekor.

Read-only, always. This test fetches an existing entry and confirms the maths
we rely on; it never submits. Writing test data into somebody else's permanent
append-only log to make a test suite green is not a trade worth making, and a
log entry cannot be withdrawn once it is in.

That split is deliberate. The conformance vectors check that we handle the
Rekor profile correctly; this checks that the profile is what we think it is.
A synthetic fixture can only ever confirm the first, and a format we got wrong
would pass it forever.

    SOURCEMARK_REKOR=https://rekor.sigstore.dev python3 -m sourcemark.tests.test_rekor_live

Skips, with a printed reason, when the network is unavailable or the
environment variable is unset. Opt-in, because a test suite that reaches the
internet by default fails in every air-gapped build.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import base64
import json
import os
import sys
import urllib.error
import urllib.request

_passed, _failed = 0, 0


def check(label: str, condition: bool, detail: str = "") -> None:
    global _passed, _failed
    if condition:
        _passed += 1
        print(f"  pass  {label}" + (f"   {detail}" if detail else ""))
    else:
        _failed += 1
        print(f"  FAIL  {label}" + (f"   {detail}" if detail else ""))


def main() -> int:
    url = os.environ.get("SOURCEMARK_REKOR")
    if not url:
        print("  SKIP  set SOURCEMARK_REKOR=https://rekor.sigstore.dev to run "
              "(read-only; this test never submits)")
        return 0

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from ..crypto import LEAF_PREFIX, fold, sha256

    def get(path: str, *, accept: str = "application/json") -> bytes:
        request = urllib.request.Request(f"{url.rstrip('/')}{path}",
                                         headers={"Accept": accept})
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read()

    try:
        info = json.loads(get("/api/v1/log"))
        # The key endpoint answers PEM, not JSON. Asking for JSON gets
        # something that is not a key and fails much later, in the verifier.
        log_key_pem = get("/api/v1/log/publicKey", accept="application/x-pem-file")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        print(f"  SKIP  {url} is unreachable: {exc}")
        return 0

    tree_size = info.get("treeSize")
    print(f"Live: {url}  treeSize {tree_size}")
    # Pick an entry well inside the tree rather than at its edge, so the proof
    # has a full-depth path rather than the degenerate right-hand spine.
    index = max(1, tree_size // 3)
    try:
        entry = list(json.loads(get(f"/api/v1/log/entries?logIndex={index}")).values())[0]
    except (urllib.error.URLError, OSError, ValueError, IndexError) as exc:
        print(f"  SKIP  could not fetch entry {index}: {exc}")
        return 0

    body = base64.b64decode(entry["body"])
    proof = entry["verification"]["inclusionProof"]

    # 1. The leaf formula in canonicalization.md 5.2. If H(0x00 ‖ body) were
    #    not the leaf, this fold could not reach the published root.
    leaf = sha256(LEAF_PREFIX + body)
    folded = fold(leaf, proof["logIndex"], proof["treeSize"],
                  [bytes.fromhex(h) for h in proof["hashes"]])
    check("H(0x00 ‖ body) folds to the root Rekor publishes",
          folded.hex() == proof["rootHash"],
          f"{folded.hex()[:16]}… vs {proof['rootHash'][:16]}…")

    parsed = json.loads(body)
    check("entries carry apiVersion, kind and spec",
          {"apiVersion", "kind", "spec"} <= set(parsed), f"kind {parsed.get('kind')!r}")

    # 2. The body shape our profile assumes. Rekor holds several entry kinds;
    #    walk a bounded window to find a hashedrekord rather than asserting
    #    that whichever index we picked happens to be one.
    hashedrekord = parsed if parsed.get("kind") == "hashedrekord" else None
    probed = 0
    for offset in range(1, 40):
        if hashedrekord is not None:
            break
        try:
            probed += 1
            candidate = list(json.loads(
                get(f"/api/v1/log/entries?logIndex={index + offset}")).values())[0]
            body_n = json.loads(base64.b64decode(candidate["body"]))
            if body_n.get("kind") == "hashedrekord":
                hashedrekord = body_n
        except (urllib.error.URLError, OSError, ValueError, IndexError):
            break
    if hashedrekord is None:
        print(f"  note  no hashedrekord entry within {probed} of index {index}; "
              f"body-shape checks skipped")
    else:
        digest = hashedrekord["spec"]["data"]["hash"]
        check("hashedrekord pins a sha256 artefact digest",
              digest.get("algorithm") == "sha256" and len(digest.get("value", "")) == 64,
              f"found after {probed} probe(s)")
        # The finding that justifies this whole file: production entries put an
        # X.509 CERTIFICATE here, not a bare public key, because Fulcio issues
        # one for the signing identity. A verifier that only parses the bare
        # form passes every synthetic fixture and fails on the real log.
        submitter_pem = base64.b64decode(
            hashedrekord["spec"]["signature"]["publicKey"]["content"])
        first = submitter_pem.split(b"\n")[0]
        check("and carries a signature", bool(hashedrekord["spec"]["signature"]["content"]))
        check("publicKey.content is a PEM public key OR an X.509 certificate",
              first in (b"-----BEGIN PUBLIC KEY-----", b"-----BEGIN CERTIFICATE-----"),
              first.decode(errors="replace"))

    # 3. The checkpoint: a signed note whose size and root match the proof.
    checkpoint = proof["checkpoint"]
    note_body, _, sig_block = checkpoint.partition("\n\n")
    note_body += "\n"
    lines = note_body.split("\n")
    check("the checkpoint's tree size matches the proof", int(lines[1]) == proof["treeSize"],
          f"{lines[1]} vs {proof['treeSize']}")
    check("the checkpoint's root hash matches the proof",
          base64.b64decode(lines[2]).hex() == proof["rootHash"])

    sig_line = next(line for line in sig_block.split("\n") if line.strip())
    raw = base64.b64decode(sig_line[2:].split(" ", 1)[1])
    signature = raw[4:]
    key = serialization.load_pem_public_key(log_key_pem)
    try:
        key.verify(signature, note_body.encode(), ec.ECDSA(hashes.SHA256()))
        check("the checkpoint verifies under Rekor's published key", True,
              f"{type(key).__name__.lstrip('_')} {getattr(key.curve, 'name', '')}")
    except Exception as exc:  # noqa: BLE001
        check("the checkpoint verifies under Rekor's published key", False, str(exc))

    check("the signature covers the body up to and including its final newline",
          note_body.endswith("\n") and not note_body.endswith("\n\n"))

    print(f"\n{_passed} passed, {_failed} failed")
    return 1 if _failed else 0


if __name__ == "__main__":
    sys.exit(main())
