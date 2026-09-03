"""Run every suite in this package.

    python3 -m sourcemark.tests

The two live suites skip, with a printed reason, when their dependency is
absent -- a database for pgvector, `SOURCEMARK_REKOR` for Rekor. A skip that
is silent is a test that passes because it never ran.

The Rekor suite is opt-in rather than default because it reaches the network,
and a suite that does that by default fails in every air-gapped build. It is
read-only and never submits: writing test data into somebody else's permanent
append-only log to keep a build green is not a trade worth making.

SPDX-License-Identifier: Apache-2.0
"""

import sys

from . import (
    test_conformance, test_pgvector, test_pipeline, test_regressions, test_rekor_live,
)

SUITES = (
    ("conformance", test_conformance),
    ("pipeline", test_pipeline),
    ("regressions", test_regressions),
    ("pgvector (live database)", test_pgvector),
    ("rekor (live, read-only)", test_rekor_live),
)

if __name__ == "__main__":
    failures = 0
    for name, module in SUITES:
        print(f"\n{'=' * 68}\n{name}\n{'=' * 68}")
        failures += module.main()
    print("\nall suites passed" if not failures else f"\n{failures} suite(s) failed")
    sys.exit(1 if failures else 0)
