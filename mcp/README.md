# mcp/ — MCP server

**Licence:** Apache-2.0.

Delivers receipts inside the resource-link annotations MCP already defines for provenance metadata. Any MCP host — Claude Code, Claude Desktop, Cursor — gets receipts by editing one config block, with no integration work.

## Phase 1 deliverable

```json
{ "mcpServers": { "sourcemark": {
    "command": "sourcemark", "args": ["mcp", "--store", "pgvector://localhost/corpus"] } } }
```

Read-only. Retrieval and receipt tools only — no mutation, no ingestion, no admin.

## Why it matters out of proportion to its size

It is the cheapest possible adoption path: a config block rather than a code change. See the growth loop in `docs/DISTRIBUTION.md` §4.
