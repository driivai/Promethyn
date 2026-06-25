"""The Python-function benchmark, exposed at the canonical harness location.

The dataset itself ships inside the distribution (so the installed CLI can run
the demo offline); the harness re-exports it as the open benchmark surface so
evaluation code has a single, stable import path.
"""

from prometheus_protocol._examples.python_functions import (
    Benchmark,
    build_benchmark,
    build_solution_book,
)

__all__ = ["Benchmark", "build_benchmark", "build_solution_book"]
