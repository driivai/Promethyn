# Dependency licenses

Every package in the runtime and development dependency closure, its license,
and the obligation it carries. Resolved 2026-09-06 from a clean virtual
environment installed with `pip install ".[dev]" -c constraints.txt`
(Python 3.11, Linux x86-64); the machine-readable form is `docs/sbom.cdx.json`.

**Headline for counsel:** no GPL or AGPL component anywhere in the closure.
One runtime dependency is LGPL-3.0 (`psycopg`), used as an unmodified,
separately installed library — the position is stated in full below. The
rest are permissive (MIT, BSD, Apache-2.0, PSF) or, in one dev-only case,
MPL-2.0.

## Runtime (installed with the product)

| Package | Version | License | Role | Obligation / position |
|---|---|---|---|---|
| `psycopg` | 3.3.5 | **LGPL-3.0-only** | PostgreSQL driver for the chokepoint runner | **Copyleft, library-scoped — see the position below.** Unmodified, imported at runtime, installed separately by pip. |
| `psycopg-binary` | 3.3.5 | **LGPL-3.0-only** (the wheel bundles `libpq` — PostgreSQL License, permissive — and OpenSSL — Apache-2.0) | the pre-built extension for `psycopg` (`[binary]` extra) | Same position as `psycopg`. The `[binary]` extra is a convenience; the pure `psycopg` package against a system `libpq` carries the same license. |
| `cryptography` | 50.0.1 | **Apache-2.0 OR BSD-3-Clause** (wheels statically link OpenSSL, Apache-2.0) | ECDSA P-256 approval signing for the external-signer path (PIH-2) | Permissive. Attribution: retain the license text in distributions (satisfied by the wheel's own metadata). Added by PIH-2; the standard library has no asymmetric primitives. |
| `cffi` | 2.1.1 | MIT-0 | C FFI used by `cryptography` | None beyond attribution (MIT-0 waives even that). |
| `pycparser` | 3.0 | BSD-3-Clause | C parser used by `cffi` | Attribution. |

## Development and build (not distributed with the product)

| Package | Version | License | Role | Obligation |
|---|---|---|---|---|
| `pytest` | 9.1.1 | MIT | test runner | attribution only; not shipped |
| `iniconfig` | 2.3.0 | MIT | pytest dependency | — |
| `pluggy` | 1.6.0 | MIT | pytest dependency | — |
| `packaging` | 26.3 | Apache-2.0 OR BSD-2-Clause | pytest / build dependency | — |
| `pygments` | 2.21.0 | BSD-2-Clause | pytest dependency | — |
| `colorama` | 0.4.6 | BSD-3-Clause | pytest dependency, Windows only | — |
| `exceptiongroup` | 1.3.1 | MIT | pytest dependency, Python < 3.11 only | — |
| `tomli` | 2.4.1 | MIT | pytest dependency, Python < 3.11 only | — |
| `build` | 1.6.0 | MIT | wheel builder | — |
| `pyproject_hooks` | 1.2.0 | MIT | build dependency | — |
| `mypy` | 2.3.1 | MIT | type gate (`mypy.ini`) | — |
| `PyYAML` | 6.0.3 | MIT | the CI-workflow guard parses `ci.yml` as a structure (`tests/conformance/test_type_gate.py`); the guard it replaced matched substrings and an independent review walked past it with one line | — |
| `types-PyYAML` | 6.0.12.20260906 | Apache-2.0 | PyYAML stubs; mypy at the declared floor of the supported range needs them to check the guard | stub-only package, no runtime code |
| `mypy_extensions` | 1.1.0 | MIT | mypy dependency | — |
| `typing_extensions` | 4.16.0 | PSF-2.0 | mypy dependency | — |
| `pathspec` | 1.1.1 | **MPL-2.0** | mypy dependency | file-level copyleft on `pathspec`'s own files only; not modified, not shipped — no obligation attaches to this code |
| `librt` | 0.15.0 | MIT | mypy dependency (mypyc runtime) | — |
| `ast_serialize` | 0.9.0 | MIT | mypy dependency (mypyc) | — |
| `setuptools` (build backend, `>=77`) | build-time | MIT | PEP 517 backend | not installed by the product |

CI additionally installs `voidguard` from a pinned commit of
`driivai/voidguard` (the project's own scanner, run as a tool, not a
dependency of the product) and uses the standard GitHub Actions
(`actions/checkout`, `actions/setup-python`; MIT).

## The LGPL position (`psycopg`)

The PROM-AUDIT-2 flag, stated plainly so a prime's counsel does not have to
ask twice:

- **What LGPL-3.0 is not.** It is not GPL. The LGPL's copyleft attaches to the
  *library* and to modified versions of it; a program that merely uses the
  library through its interface is a "Combined Work" (LGPL-3.0 §4) and may be
  distributed under terms of the distributor's choice, including proprietary
  terms, provided the conditions for the library itself are met.
- **How Promethyn uses it.** `psycopg` is imported, unmodified, through its
  public API, from a separately installed package that pip resolves from PyPI.
  Promethyn does not vendor it, patch it, statically combine it, or ship it
  inside its own wheel. A user can replace it with any other compliant version
  (LGPL-3.0 §4(d): the library is a separately installed, relinkable
  component). The single import site is the chokepoint runner's PostgreSQL
  executor and receipt lookup (`chokepoint/runner.py`), and it is lazy — the
  rest of the product never loads it.
- **What that means for the relicense.** No obligation attaches to
  Promethyn's own code. The relicense to proprietary terms is unaffected by
  the presence of an LGPL dependency used this way.
- **What a prime's counsel will still ask, and the answers:** unmodified —
  yes; dynamically loaded, not statically combined — yes (Python import);
  separately obtainable and replaceable by the end user — yes; the library's
  license text and notices preserved — yes, in the installed package's own
  metadata; any distribution of Promethyn that bundles `psycopg` (a frozen
  container image, for example) must keep that metadata intact and must not
  prevent the user from replacing the library — a deployment requirement,
  stated here.
- **If a zero-copyleft closure is a contract requirement,** the driver can be
  replaced: `pg8000` (BSD-3-Clause, pure Python) or `asyncpg` (Apache-2.0).
  The change is contained to the executor and receipt-lookup functions in the
  chokepoint runner. **It is not made in this sprint**, on purpose: swapping a
  driver in a security-relevant path is its own change with its own tests.

## Pinning, provenance and abandonment

- **Pinned.** `pyproject.toml` keeps version ranges, as a library should;
  `constraints.txt` pins every package in the closure to an exact version and
  CI installs under it, so a build is reproducible and the SBOM describes what
  actually installs. Regeneration procedure is in `constraints.txt`.
- **Provenance.** Every name resolves to the canonical PyPI project with the
  expected upstream: `psycopg`/`psycopg-binary` (psycopg.org), `cryptography`,
  `cffi`, `pycparser` (PyCA and their long-standing maintainers), `pytest`,
  `iniconfig`, `pluggy` (pytest-dev), `packaging`, `build`, `pyproject_hooks`
  (PyPA), `mypy`, `mypy_extensions`, `typing_extensions` (python/mypy and
  python/typing), `librt` and `ast_serialize` (the mypyc organisation; new
  packages, first published 2025-09 and 2026-01, required by mypy 2.x).
  None is a look-alike of another project.
- **Not abandoned.** Every package has a release within the last twelve
  months except `colorama` (last release 2022-10, a small, complete,
  Windows-only dev dependency) and `pyproject_hooks` (2024-09, stable, PyPA).
  Latest-release dates were read from PyPI on 2026-09-06.
- **Python 3.10 note.** `exceptiongroup` and `tomli` install only on 3.10; the
  SBOM was generated on 3.11 and therefore omits them, which is why they are
  listed here and pinned in `constraints.txt`.

## Regenerating this record

```
python -m venv /tmp/closure && /tmp/closure/bin/pip install ".[dev]" -c constraints.txt
/tmp/closure/bin/pip freeze                      # compare with constraints.txt
pip install cyclonedx-bom && cyclonedx-py environment /tmp/closure \
    --pyproject pyproject.toml --mc-type application --output-reproducible \
    --of JSON --sv 1.6 -o docs/sbom.cdx.json --validate
```

Then update the tables above for any package that changed, and re-read its
license: the position in this document is only as current as its date.

**SBOM regenerated (TYPE-GATE-HARDEN-2).** `docs/sbom.cdx.json` was knowingly
stale after TYPE-GATE-HARDEN — it described the 18-package closure and omitted
`PyYAML` and `types-PyYAML`. It has been regenerated from the pinned closure and
now carries 22 components including both. The three packages still absent from
it — `colorama`, `exceptiongroup`, `tomli` — are the pre-existing Python 3.10
note above, not new drift.
