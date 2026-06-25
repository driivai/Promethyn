# Examples

Runnable examples that use only the public API.

## `run_demo.py`

The full loop on the bundled benchmark, offline:

```bash
python examples/run_demo.py
```

It uses the default simulated provider, an ephemeral skill registry, and an
in-memory ledger — no network and no API key. Expect a held-out baseline of
40%, 100% after one cycle, a +60% ablation contribution for the mined skill,
and a second cycle that finds nothing new to learn.

The same flow is available as `prometheus-protocol demo`.
