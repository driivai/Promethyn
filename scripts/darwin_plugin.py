"""Flip sys.platform to darwin AFTER collection, per docs/OPEN-GAPS.md G10.

ctypes is imported first because it selects a backend by platform at import
time; flipping before that import changes which backend loads and the run stops
being a simulation of anything.
"""

import ctypes  # noqa: F401  - must be imported while sys.platform is real
import sys


def pytest_collection_finish(session):
    sys.platform = "darwin"
