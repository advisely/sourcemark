"""The Sourcemark MCP server.

Two audiences, and they need different things.

**Anyone holding a receipt** wants to know whether it is genuine. That needs
no corpus, no database and no configuration: point the host at this server
and ask. `verify_receipt` is the tool, and it is why this listing exists --
a receipt is designed to leave the organization that produced it, and every
recipient needs a verifier.

**A team running a corpus** wants their assistant's answers to arrive with
receipts already attached. That is `search`, and it needs a store, so it is
advertised only when one is configured. A tool that is listed and then fails
because the operator did not set an environment variable is worse than a
tool that is honestly absent.

Verification is delegated to `sourcemark-verify`, which is a **separate,
optional** import. This server does not reimplement the decision procedure:
a second implementation living in the same repository as the emitter is
exactly what the repository split exists to prevent. If the package is not
installed, the tool says so and says how to fix it.

    pip install sourcemark-verify        # for verify_receipt
    SOURCEMARK_STORE=postgresql://…      # for search

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import base64
import json
import os
import pathlib
from typing import Any

from .protocol import (
    INVALID_PARAMS, LATEST, PROTOCOL_VERSIONS, McpError, Server,
)

__version__ = "0.1.0.dev0"

INSTRUCTIONS = (
    "Sourcemark turns an AI answer's citation into evidence. A receipt proves that "
    "a quoted passage came from a specific place in a specific version of a document, "
    "and that the commitment predates the answer.\n\n"
    "Use verify_receipt when the user has a receipt and wants to know whether it is "
    "genuine. It reports one of seven outcomes, never a boolean, and it runs offline.\n\n"
    "Important: a VERIFIED receipt establishes where text came from. It settles "
    "nothing about whether the answer built on that text holds up. Never present a "
    "verified receipt as evidence that an answer is right."
)

RECEIPT_MIME = "application/vnd.sourcemark.receipt+cbor"
META = "dev.sourcemark/"          # reverse-DNS _meta prefix; `mcp`/`modelcontextprotocol`
                                  # second labels are reserved, `sourcemark` is not.

OUTCOME_HELP = {
    "VERIFIED": "The cited text is what was committed, at those coordinates, before the answer.",
    "ERASED": "Correct and not a failure: the key was destroyed, the tree is intact, the "
              "content can no longer be shown.",
    "PENDING": "Not yet inside a signed tree. Retry shortly; nothing is wrong.",
    "TAMPERED": "The cited text is not what the receipt commits to. The source changed.",
    "FORGED": "The inclusion proof does not fold. The receipt is not what it claims.",
    "BACKDATED": "The commitment does not precede the answer.",
    "UNSIGNED": "The tree head does not verify against the key supplied.",
    "MALFORMED": "Not a readable receipt. A truncated download looks like this; so does junk.",
}


def _verifier():
    try:
        import sourcemark_verify  # noqa: F401
    except ImportError as exc:
        raise McpError(
            "sourcemark-verify is not installed, so this server cannot check receipts. "
            "Install it with `pip install sourcemark-verify`. It is a separate package "
            "on purpose: the verifier is the part you are not asked to trust us about, "
            "so it ships from its own repository with its own history.",
            data={"missing": "sourcemark-verify"},
        ) from exc
    from sourcemark_verify import verify
    return verify


def _read(path: str | None, what: str) -> bytes | None:
    if not path:
        return None
    p = pathlib.Path(path).expanduser()
    if not p.is_file():
        raise McpError(f"{what}: {p} is not a readable file")
    return p.read_bytes()


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

VERIFY_TOOL = {
    "name": "verify_receipt",
    "title": "Verify a Sourcemark receipt",
    "description": (
        "Check a retrieval receipt offline and report one of seven outcomes. "
        "Requires the log's public key and the cited text -- without the text the "
        "check proves only that some leaf is in the tree, not that it is the one "
        "backing the sentence in front of you. Supplying the original document with "
        "source_path is stronger still: the text is then re-derived from the file "
        "rather than taken on trust."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "receipt_path": {"type": "string", "description": "Path to the receipt (.cbor)."},
            "log_key_path": {"type": "string",
                             "description": "The log's public key, PEM or DER."},
            "text": {"type": "string", "description": "The cited text, inline."},
            "text_path": {"type": "string", "description": "Or a file holding it."},
            "source_path": {"type": "string",
                            "description": "The original document. Enables the strongest check."},
        },
        "required": ["receipt_path", "log_key_path"],
    },
    "annotations": {"readOnlyHint": True, "openWorldHint": False},
}


def verify_receipt(args: dict) -> dict:
    verify = _verifier()
    receipt = _read(args.get("receipt_path"), "receipt_path")
    log_key = _read(args.get("log_key_path"), "log_key_path")
    if receipt is None or log_key is None:
        raise McpError("receipt_path and log_key_path are both required")
    source = _read(args.get("source_path"), "source_path")
    text = args.get("text")
    if text is None and args.get("text_path"):
        text = _read(args["text_path"], "text_path").decode("utf-8")
    if text is None and source is None:
        raise McpError(
            "no cited text. Pass text, text_path, or source_path. Without it the "
            "verifier can only show that some leaf is in the tree, and reporting that "
            "as a pass would certify something the receipt does not say."
        )

    from sourcemark_verify import MissingInput
    try:
        report = verify(receipt, log_key, cited_text=text, source_bytes=source)
    except MissingInput as exc:
        raise McpError(str(exc)) from exc

    lines = [f"{report.outcome} — {OUTCOME_HELP.get(report.outcome, '')}", ""]
    for check in report.checks:
        lines.append(f"  {'ok  ' if check.passed else 'FAIL'}  {check.name}"
                     + (f"   {check.detail}" if check.detail else ""))
    if report.notes:
        lines.append("")
        lines.extend(f"  note  {n}" for n in report.notes)
    # Not "does not say the answer is correct". `verification.md` §5 forbids
    # that word anywhere in a verifier's output, and the rule is blunt on
    # purpose: a reader skimming for a verdict carries the word to whatever is
    # nearest, and here that is the answer. Saying it without the word costs
    # one clause.
    lines += ["", "Scope: this is a custody claim. It establishes where the text came "
                  "from. Whether the answer built on that text holds up is a separate "
                  "question, which no receipt can settle."]

    return {
        "content": [{"type": "text", "text": "\n".join(lines)}],
        "structuredContent": {
            "outcome": report.outcome,
            "exit_status": report.exit_status,
            "binding": report.binding,
            "checks": [{"name": c.name, "passed": c.passed, "detail": c.detail}
                       for c in report.checks],
            "notes": report.notes,
        },
        # isError is for tool failure, not for a verdict. A TAMPERED receipt is
        # this tool working, and flagging it as an error would invite a host to
        # retry it as if something had gone wrong.
        "isError": False,
    }


SEARCH_TOOL = {
    "name": "search",
    "title": "Search an anchored corpus",
    "description": (
        "Retrieve passages from a Sourcemark-anchored corpus. Each result carries a "
        "receipt as a resource link, so the provenance travels with the answer instead "
        "of being reconstructed later."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "query": {"type": "string"},
            "k": {"type": "integer", "minimum": 1, "maximum": 50, "default": 5},
        },
        "required": ["query"],
    },
    "annotations": {"readOnlyHint": True, "openWorldHint": False},
}


class Corpus:
    """Whatever the operator configured, or nothing at all."""

    def __init__(self) -> None:
        self.dsn = os.environ.get("SOURCEMARK_STORE")
        self._emit = None

    @property
    def available(self) -> bool:
        return bool(self.dsn)

    def emit(self):
        if self._emit is None:
            raise McpError(
                "SOURCEMARK_STORE is set but no retriever is wired up. This server "
                "exposes search only when an operator supplies one; see mcp/README.md."
            )
        return self._emit


CORPUS = Corpus()
RECEIPTS: dict[str, bytes] = {}


def search(args: dict) -> dict:
    if not CORPUS.available:
        raise McpError(
            "no corpus is configured, so this server cannot search. Set SOURCEMARK_STORE "
            "to a Sourcemark-anchored store. verify_receipt works without one."
        )
    emit = CORPUS.emit()
    results = emit.search(args["query"], k=int(args.get("k", 5)))
    content: list[dict] = []
    for r in results:
        content.append({"type": "text", "text": r.text})
        if r.receipt is None:
            reason = (r.unavailable or {}).get("receipt_unavailable", {})
            content.append({"type": "text",
                            "text": f"[no receipt for {r.chunk_id}: "
                                    f"{reason.get('reason', 'unknown')}]"})
            continue
        RECEIPTS[r.chunk_id] = r.receipt
        content.append({
            "type": "resource_link",
            "uri": f"sourcemark://receipt/{r.chunk_id}",
            "name": f"receipt for {r.chunk_id}",
            "mimeType": RECEIPT_MIME,
            "description": "Cryptographic provenance for the passage above. Verify it "
                           "with verify_receipt or the standalone verifier.",
            "_meta": {META + "chunkId": r.chunk_id, META + "bytes": len(r.receipt)},
        })
    return {"content": content, "isError": False}


# ---------------------------------------------------------------------------
# Wiring
# ---------------------------------------------------------------------------


def build() -> Server:
    server = Server("sourcemark", __version__, INSTRUCTIONS)

    def tools() -> list[dict]:
        listed = [VERIFY_TOOL]
        if CORPUS.available:
            listed.append(SEARCH_TOOL)
        return listed

    capabilities = {"tools": {"listChanged": False}, "resources": {"subscribe": False,
                                                                  "listChanged": False}}

    @server.method("server/discover")
    def _discover(params: dict) -> dict:
        return server.result("discover", {
            "supportedVersions": PROTOCOL_VERSIONS,
            "capabilities": capabilities,
            "instructions": INSTRUCTIONS,
            "_meta": {META + "serverInfo": {"name": "sourcemark", "version": __version__}},
        }, ttl_ms=3_600_000, scope="public")

    @server.method("initialize")
    def _initialize(params: dict) -> dict:
        # Older revisions. Echo a version the client asked for when we speak
        # it, rather than insisting on our newest: a server that answers with
        # a version the client did not offer has ended the conversation.
        asked = params.get("protocolVersion")
        chosen = asked if asked in PROTOCOL_VERSIONS else LATEST
        return {
            "protocolVersion": chosen,
            "capabilities": capabilities,
            "serverInfo": {"name": "sourcemark", "version": __version__},
            "instructions": INSTRUCTIONS,
        }

    @server.method("tools/list")
    def _tools_list(params: dict) -> dict:
        return server.result("complete", {"tools": tools()},
                             ttl_ms=3_600_000, scope="public")

    @server.method("tools/call")
    def _tools_call(params: dict) -> dict:
        name, args = params.get("name"), params.get("arguments") or {}
        handler = {"verify_receipt": verify_receipt, "search": search}.get(name)
        if handler is None:
            raise McpError(f"no tool named {name!r}", code=INVALID_PARAMS)
        return server.result("complete", handler(args))

    @server.method("resources/list")
    def _resources_list(params: dict) -> dict:
        return server.result("complete", {"resources": [
            {"uri": f"sourcemark://receipt/{cid}", "name": f"receipt for {cid}",
             "mimeType": RECEIPT_MIME}
            for cid in sorted(RECEIPTS)
        ]}, ttl_ms=0)

    @server.method("resources/read")
    def _resources_read(params: dict) -> dict:
        uri = params.get("uri", "")
        prefix = "sourcemark://receipt/"
        if not uri.startswith(prefix):
            raise McpError(f"{uri!r} is not a Sourcemark receipt URI")
        receipt = RECEIPTS.get(uri[len(prefix):])
        if receipt is None:
            raise McpError(f"no receipt is held for {uri!r}. Receipts are cached only "
                           f"for results this session returned.")
        return server.result("complete", {"contents": [{
            "uri": uri, "mimeType": RECEIPT_MIME,
            "blob": base64.b64encode(receipt).decode(),
        }]}, ttl_ms=0)

    @server.method("ping")
    def _ping(params: dict) -> dict:
        return {}

    return server


def main() -> int:
    build().serve()
    return 0
