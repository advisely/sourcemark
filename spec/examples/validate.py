#!/usr/bin/env python3
"""Validate the worked example against receipt.schema.json, and prove the
schema rejects the things it claims to reject.

Run:  python3 spec/examples/validate.py

A minimal validator is written out here rather than pulled in, for the same
reason the CBOR encoder is: `jsonschema` is not available in every
environment a second implementer will use, and a schema nobody has run
against the example is a wish rather than a schema. It supports exactly the
subset of draft 2020-12 this schema uses.

SPDX-License-Identifier: CC0-1.0
"""

import copy
import json
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).parent
SPEC = HERE.parent

schema = json.loads((SPEC / "receipt.schema.json").read_text())
doc = json.loads((HERE / "receipt.json").read_text())
defs = schema["$defs"]
errors: list[str] = []


def resolve(node: dict) -> dict:
    return defs[node["$ref"].split("/")[-1]] if "$ref" in node else node


def validate(node: dict, value, path: str) -> None:
    node = resolve(node)
    for sub in node.get("allOf", []):
        validate(sub, value, path)
    if "oneOf" in node:
        matched = 0
        for sub in node["oneOf"]:
            before = len(errors)
            validate(sub, value, path)
            if len(errors) == before:
                matched += 1
            else:
                del errors[before:]
        if matched != 1:
            errors.append(f"{path}: matched {matched} of {len(node['oneOf'])} oneOf branches, expected exactly 1")
    if "const" in node and value != node["const"]:
        errors.append(f"{path}: expected {node['const']!r}, got {value!r}")
    if "enum" in node and value not in node["enum"]:
        errors.append(f"{path}: {value!r} not in {node['enum']}")
    if "pattern" in node and (not isinstance(value, str) or not re.match(node["pattern"], value)):
        errors.append(f"{path}: {str(value)[:40]!r} fails /{node['pattern']}/")
    t = node.get("type")
    if t == "object" and isinstance(value, dict):
        props = node.get("properties", {})
        for req in node.get("required", []):
            if req not in value:
                errors.append(f"{path}.{req}: required but absent")
        if node.get("additionalProperties") is False:
            allowed = set(props)
            for sub in node.get("allOf", []):
                allowed |= set(resolve(sub).get("properties", {}))
            for k in value:
                if k not in allowed:
                    errors.append(f"{path}.{k}: not permitted by the schema")
        for k, v in value.items():
            if k in props:
                validate(props[k], v, f"{path}.{k}")
    if t == "array" and isinstance(value, list):
        if "items" in node:
            for i, item in enumerate(value):
                validate(node["items"], item, f"{path}[{i}]")
        if len(value) < node.get("minItems", 0):
            errors.append(f"{path}: {len(value)} items, min {node['minItems']}")
        if "maxItems" in node and len(value) > node["maxItems"]:
            errors.append(f"{path}: {len(value)} items, max {node['maxItems']}")
    if t == "integer" and isinstance(value, int) and value < node.get("minimum", value):
        errors.append(f"{path}: {value} below minimum {node['minimum']}")


# The three proof sub-objects carry their shared shape via allOf; flatten it
# so additionalProperties:false has the full key set to work with.
for key in ("document", "corpus", "log"):
    n = schema["properties"]["custody"]["properties"]["proof"]["properties"][key]
    n.setdefault("type", "object")
    n["properties"] = {**defs["merkleProof"]["properties"], **n.get("properties", {})}
    n["required"] = sorted(set(n.get("required", [])) | set(defs["merkleProof"]["required"]))
    n["additionalProperties"] = False

validate(schema, doc, "receipt")
if errors:
    print(f"{len(errors)} validation error(s) against the worked example:")
    for e in errors:
        print("  -", e)
    sys.exit(1)
print("receipt.json validates against receipt.schema.json")

# A schema is only as good as what it refuses. Each mutation below
# corresponds to a claim made in canonicalization.md or receipt.cddl.
NEGATIVES = [
    ("proven: true",              lambda d: d["support"].__setitem__("proven", True)),
    ("unknown top-level field",   lambda d: d.__setitem__("extra", 1)),
    ("salt mislabelled sha256:",  lambda d: d["custody"]["derivation"]["opening"].__setitem__("salt", "sha256:" + "0" * 64)),
    ("opening both salt+erased",  lambda d: d["custody"]["derivation"]["opening"].__setitem__("erased", True)),
    ("opening erased: false",     lambda d: d["custody"]["derivation"].__setitem__("opening", {"erased": False})),
    ("opening empty",             lambda d: d["custody"]["derivation"].__setitem__("opening", {})),
    ("custody removed",           lambda d: d.pop("custody")),
    ("support class 'PROVEN'",    lambda d: d["support"].__setitem__("class", "PROVEN")),
    ("entry_profile swapped",     lambda d: d["custody"]["proof"]["log"].__setitem__("entry_profile", "attacker.v1")),
    ("byte_range dropped",        lambda d: d["custody"]["location"].pop("byte_range")),
    ("truncated digest",          lambda d: d["custody"]["proof"].__setitem__("leaf_hash", "sha256:abcd")),
    ("timestamp as bare date",    lambda d: d["context"].__setitem__("retrieved_at", "2026-09-02")),
    ("log entry bytes supplied",  lambda d: d["custody"]["proof"]["log"].__setitem__("entry_data", "base16:00")),
]

failures = 0
for label, mutate in NEGATIVES:
    errors.clear()
    bad = copy.deepcopy(doc)
    mutate(bad)
    validate(schema, bad, "receipt")
    if errors:
        print(f"  rejects  {label}")
    else:
        print(f"  ACCEPTS  {label}  <- schema is too permissive")
        failures += 1

print(f"\n{len(NEGATIVES) - failures}/{len(NEGATIVES)} negative controls rejected")

# --- receipt.cddl and the example must not drift apart ---------------------
# The CDDL is normative and the JSON schema is a projection of it. Nothing
# stops the two from being edited independently except this check.
import re  # noqa: E402

cddl = (SPEC / "receipt.cddl").read_text()
erased_doc = json.loads((HERE / "receipt-erased.json").read_text())


def cddl_body(rule: str) -> str:
    r"""Return a rule's brace body, matching braces rather than regex.

    A non-greedy /\{.*?\}/ stops at the first nested brace, which silently
    truncates `proof` (whose members carry inline `.and { ... }` groups) and
    made this check pass while seeing only half the rule.
    """
    m = re.search(rf"^{rule}\s*=\s*\{{", cddl, re.M)
    if m is None:
        raise KeyError(f"no CDDL rule named {rule!r}")
    depth, i = 0, m.end() - 1
    for j in range(i, len(cddl)):
        if cddl[j] == "{":
            depth += 1
        elif cddl[j] == "}":
            depth -= 1
            if depth == 0:
                return cddl[i + 1 : j]
    raise ValueError(f"unbalanced braces in rule {rule!r}")


def cddl_keys(rule: str) -> set[str]:
    body = re.sub(r";[^\n]*", "", cddl_body(rule))
    # A member starts at the opening brace, after a comma, or at a line
    # start. Anchoring only to line starts misses members written inline,
    # such as `{ erased: true, ? erased_at: timestamp_ms }`.
    return set(re.findall(r"(?:^|[{,])\s*\??\s*([a-z_]+)\s*:", body, re.M))


c = doc["custody"]
RULES = [
    ("receipt", set(doc)),
    ("custody", set(c)),
    ("source", set(c["source"])),
    ("location", set(c["location"])),
    ("derivation", set(c["derivation"])),
    ("proof", set(c["proof"])),
    ("log_proof", set(c["proof"]["log"])),
    ("merkle_proof", set(c["proof"]["document"]) - {"doc_root"}),
    ("support", set(doc["support"])),
    ("context", set(doc["context"])),
    ("live_opening", set(c["derivation"]["opening"])),
    ("erased_opening", set(erased_doc["custody"]["derivation"]["opening"])),
]

drift = 0
print()
for rule, present in RULES:
    declared = cddl_keys(rule)
    extra = present - declared
    if extra:
        print(f"  DRIFT  {rule}: example has {sorted(extra)}, CDDL does not declare it")
        drift += 1
    else:
        print(f"  ok     {rule}")
print(f"\n{len(RULES) - drift}/{len(RULES)} CDDL rules match the worked example")

sys.exit(1 if failures or drift else 0)
