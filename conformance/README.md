# conformance/ — test vectors

**Licence:** CC0.

A format with two independent implementations is a standard. With one it is a product. This directory is what makes the second implementation possible.

## Phase 1 deliverable

| Vector | Must produce |
|---|---|
| `valid/` | `VERIFIED` |
| `tampered/` | `TAMPERED` — one byte altered in the source |
| `forged/` | `FORGED` — inclusion path that does not fold to the root |
| `backdated/` | `BACKDATED` — log entry postdating the answer |
| `erased/` | `ERASED` — salt destroyed, tree intact |
| `pending/` | `PENDING` — leaf not yet in a logged root |
| `unsigned/` | `UNSIGNED` — invalid tree-head signature |

Every vector ships with its expected outcome and the reason. An implementation that returns `VERIFIED` for anything under `tampered/` is non-conforming, and that has to be checkable by someone who does not work here.
