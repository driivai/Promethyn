"""Evaluation harness: benchmarks, metrics, and audit tooling.

The harness sits outside the importable library on purpose. It depends on the
public API of ``prometheus_protocol`` and is used to evaluate and audit the
runtime, not to ship inside it.
"""
