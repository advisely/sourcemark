# mcp/ — receipts inside any MCP host

**Licence:** Apache-2.0.

A receipt is designed to leave the organization that produced it. It goes to an auditor, a regulator, a contracting officer, opposing counsel — and every one of those people needs a way to check it. MCP is how that reaches them without anyone writing an integration: add one config block and the assistant they already use can verify receipts.

## Install

```bash
pip install sourcemark-mcp sourcemark-verify
```

```json
{
  "mcpServers": {
    "sourcemark": {
      "command": "sourcemark-mcp"
    }
  }
}
```

Works in Claude Desktop, Claude Code, Cursor, VS Code — anything that speaks MCP. No account, no key, no network.

## Two tools, and only one needs setup

| Tool | Needs | What it does |
|---|---|---|
| `verify_receipt` | nothing | Checks a receipt offline and reports one of seven outcomes, never a boolean |
| `search` | `SOURCEMARK_STORE` | Retrieves from an anchored corpus, attaching each receipt as an MCP resource link |

`search` is **advertised only when a corpus is configured.** A tool that is listed and then fails because the operator never set an environment variable is worse than a tool that is honestly absent — the host has already told the user it can do something.

Receipts returned by `search` are exposed as resources at `sourcemark://receipt/<chunk_id>`, so a host can fetch the bytes and hand them on. They are held only for results this session returned; nothing is persisted.

## Design notes

**No SDK dependency.** The official Python SDK pulls in opentelemetry transitively. Shipping a telemetry library inside a tool whose verifier promises *"no telemetry, ever"* is a contradiction a sceptical auditor would notice, and the stdio surface for a tools-and-resources server is small enough to own outright. `protocol.py` is about 130 lines.

**Written against the published schema, not from memory.** Protocol revision `2026-07-28` removed `initialize` in favour of `server/discover`, moved capability declaration to per-request `_meta`, and made `resultType`, `cacheScope` and `ttlMs` required on every result. All four would have been wrong if guessed. Older revisions are still spoken, because hosts in the field ship them — and `initialize` echoes the version the client asked for rather than insisting on ours.

**Verification is delegated, not reimplemented.** `sourcemark-verify` is a separate optional import. A second implementation of the decision procedure living in the same repository as the emitter is precisely what the repository split exists to prevent. Without it installed, the tool says so and says how to fix it.

**A verdict is not a tool error.** A `TAMPERED` receipt is this server working correctly. Setting `isError` on it would invite a host to retry as though something had gone wrong, and would let a real finding read as a glitch.

## The line the tool will not cross

Every reply states it: a receipt establishes **where text came from**. Whether the answer built on that text holds up is a separate question no receipt can settle. The server's instructions tell the model this directly, and its output never describes an answer as proven, correct, or accurate — a rule inherited from [`spec/verification.md`](../spec/verification.md) §5, which is blunt on purpose because the failure mode is a reader skimming for a verdict.

## Tests

```bash
python3 mcp/tests_mcp.py     # 28 checks over the wire, 21 without sourcemark-verify
```

The verifier-dependent checks skip loudly rather than failing when the optional package is absent, and the tool's refusal is checked instead. A suite that goes red over a missing optional dependency teaches people to ignore red.

No MCP client library — the point is to exercise the wire format, and a client sharing assumptions with the server would test the assumptions instead of the protocol.
