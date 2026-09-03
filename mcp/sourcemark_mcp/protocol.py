"""JSON-RPC 2.0 over stdio, and the MCP shapes this server needs.

Written against the published schema for protocol revision **2026-07-28**,
not from memory. Two things in that revision would have been wrong if they
had been guessed:

  - `initialize` is gone. A server advertises itself through `server/discover`,
    and capabilities are declared **per request** in `params._meta`, with the
    schema stating plainly that servers MUST NOT infer them from earlier
    requests.
  - Every result carries `resultType`, `cacheScope` and `ttlMs`, and they are
    required rather than optional.

Hosts in the field still speak older revisions, so `initialize` is handled
too and answered in its own shape. Advertising a version you cannot speak is
worse than not speaking it.

**No SDK dependency, deliberately.** The official Python SDK pulls in
opentelemetry transitively, and a provenance tool whose verifier promises "no
telemetry, ever" should not ship a transport that ships a telemetry library.
The stdio surface for a tools-and-resources server is small enough to own.

SPDX-License-Identifier: Apache-2.0
"""

from __future__ import annotations

import json
import sys
from typing import Any, Callable

__all__ = ["Server", "McpError", "PROTOCOL_VERSIONS", "LATEST"]

LATEST = "2026-07-28"
# Newest first. A client picks the first it recognises.
PROTOCOL_VERSIONS = [LATEST, "2025-11-25", "2025-06-18"]

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


class McpError(Exception):
    """An error to report to the client, with a JSON-RPC code."""

    def __init__(self, message: str, code: int = INVALID_PARAMS, data: Any = None) -> None:
        super().__init__(message)
        self.code, self.data = code, data


class Server:
    """A stdio MCP server.

    Framing is line-delimited JSON, which is what stdio transports use. A
    message is one line; a line that does not parse is answered with a
    JSON-RPC parse error rather than crashing the loop, because the process
    on the other end is a host we do not control.
    """

    def __init__(self, name: str, version: str, instructions: str = "") -> None:
        self.name, self.version, self.instructions = name, version, instructions
        self._methods: dict[str, Callable[[dict], Any]] = {}

    def method(self, name: str) -> Callable:
        def register(fn: Callable[[dict], Any]) -> Callable:
            self._methods[name] = fn
            return fn
        return register

    # -- results -----------------------------------------------------------

    @staticmethod
    def result(kind: str, body: dict, *, ttl_ms: int = 0, scope: str = "private") -> dict:
        """Wrap a result with the fields the 2026-07-28 revision requires.

        `cacheScope` defaults to `private` and `ttlMs` to 0 -- do not cache,
        do not share. For a tool that answers questions about a specific
        receipt, a shared cache would be a way for one caller's verdict to be
        served to another, and the conservative default is the correct one.
        """
        return {"resultType": kind, "cacheScope": scope, "ttlMs": ttl_ms, **body}

    # -- the loop ----------------------------------------------------------

    def serve(self, stdin=None, stdout=None) -> None:
        stdin = stdin or sys.stdin
        stdout = stdout or sys.stdout
        for line in stdin:
            line = line.strip()
            if not line:
                continue
            response = self._handle_line(line)
            if response is not None:
                stdout.write(json.dumps(response) + "\n")
                stdout.flush()

    def _handle_line(self, line: str) -> dict | None:
        try:
            message = json.loads(line)
        except ValueError as exc:
            return _error(None, PARSE_ERROR, f"could not parse message: {exc}")
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return _error(message.get("id") if isinstance(message, dict) else None,
                          INVALID_REQUEST, "not a JSON-RPC 2.0 message")

        method, request_id = message.get("method"), message.get("id")
        if method is None:
            return None                      # a response to us; we send none
        if request_id is None:
            # A notification. Nothing to answer, including for methods we do
            # not implement -- answering a notification is itself a protocol
            # error.
            return None
        handler = self._methods.get(method)
        if handler is None:
            return _error(request_id, METHOD_NOT_FOUND, f"no method {method!r}")
        try:
            return {"jsonrpc": "2.0", "id": request_id,
                    "result": handler(message.get("params") or {})}
        except McpError as exc:
            return _error(request_id, exc.code, str(exc), exc.data)
        except Exception as exc:  # noqa: BLE001 - never take the loop down
            return _error(request_id, INTERNAL_ERROR, f"{type(exc).__name__}: {exc}")


def _error(request_id: Any, code: int, message: str, data: Any = None) -> dict:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}
