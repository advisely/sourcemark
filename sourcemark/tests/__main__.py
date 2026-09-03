"""Run every suite in this package.

    python3 -m sourcemark.tests

SPDX-License-Identifier: Apache-2.0
"""

import sys

from . import test_conformance, test_pipeline

if __name__ == "__main__":
    failures = 0
    for name, module in (("conformance", test_conformance), ("pipeline", test_pipeline)):
        print(f"\n{'=' * 68}\n{name}\n{'=' * 68}")
        failures += module.main()
    print("\nall suites passed" if not failures else f"\n{failures} suite(s) failed")
    sys.exit(1 if failures else 0)
