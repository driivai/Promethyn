"""The CI database's coordinates have ONE source in the workflow.

They used to be typed twice — once in the Postgres service container's env and
once in the live-database step's env — with nothing enforcing that the two
copies agreed (docs/pre-disclosure-audit.md L2/L3 flagged the duplication). Two
copies that must agree, with nothing checking, is a fail-open waiting for the
edit that changes one of them: the service comes up with one password and the
proofs connect with another, and the proofs fail for a reason unrelated to what
they prove.

Now the values live once, in the build job's ``env``, and every consumer reads
them by expression. This test pins that shape: every consumer references the
source, and each literal appears exactly once in the file. It reads the YAML
the same way ``test_type_gate.py`` does, and it is a structural check — it does
not (and cannot) start a container; the live step in CI is what proves the
expression resolved.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
WORKFLOW = REPO / ".github" / "workflows" / "ci.yml"

#: The one source, by env name, and the literal each carries.
SOURCE = {
    "PROM_CI_PG_DB": "appdb",
    "PROM_CI_PG_USER": "migrator",
    "PROM_CI_PG_PASSWORD": "chokepoint-ci-password",
}

#: Consumers: (where, key) -> the source it must reference.
SERVICE_CONSUMERS = {
    "POSTGRES_DB": "PROM_CI_PG_DB",
    "POSTGRES_USER": "PROM_CI_PG_USER",
    "POSTGRES_PASSWORD": "PROM_CI_PG_PASSWORD",
}
STEP_CONSUMERS = {
    "PROM_CHOKEPOINT_PG_DB": "PROM_CI_PG_DB",
    "PROM_CHOKEPOINT_PG_USER": "PROM_CI_PG_USER",
    "PROM_CHOKEPOINT_PG_PASSWORD": "PROM_CI_PG_PASSWORD",
}
LIVE_STEP = "PostgreSQL chokepoint live tests (must run, never skip)"


def _job() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["build"]


def _reference(name: str) -> str:
    return "${{ env." + name + " }}"


def test_the_job_env_is_the_one_source():
    env = _job()["env"]
    for name, literal in SOURCE.items():
        assert env.get(name) == literal, f"jobs.build.env.{name} is {env.get(name)!r}"


def test_the_service_container_reads_the_source_by_expression():
    service_env = _job()["services"]["postgres"]["env"]
    for key, source in SERVICE_CONSUMERS.items():
        assert service_env.get(key) == _reference(source), (
            f"services.postgres.env.{key} is {service_env.get(key)!r}; it must be "
            f"{_reference(source)!r} so the container and the proofs cannot disagree"
        )


def test_the_live_step_reads_the_source_by_expression():
    steps = [s for s in _job()["steps"] if s.get("name") == LIVE_STEP]
    assert len(steps) == 1, f"expected exactly one step named {LIVE_STEP!r}"
    step_env = steps[0]["env"]
    for key, source in STEP_CONSUMERS.items():
        assert step_env.get(key) == _reference(source), (
            f"step env {key} is {step_env.get(key)!r}; it must be {_reference(source)!r}"
        )


def test_each_literal_appears_exactly_once_in_the_workflow():
    """The structural half of "one source": a second copy of the literal
    anywhere in the file — a comment quoting it included — is a second source
    a future edit can leave behind."""

    text = WORKFLOW.read_text(encoding="utf-8")
    for name, literal in SOURCE.items():
        occurrences = len(re.findall(re.escape(literal), text))
        assert occurrences == 1, (
            f"{literal!r} appears {occurrences} times in ci.yml; the one permitted "
            f"occurrence is the {name} source in jobs.build.env"
        )


def test_the_health_check_reads_the_containers_own_environment():
    """The health command runs inside the container; it reads POSTGRES_USER and
    POSTGRES_DB from there rather than restating the literals."""

    options = _job()["services"]["postgres"]["options"]
    assert "$POSTGRES_USER" in options and "$POSTGRES_DB" in options, options
    for literal in SOURCE.values():
        assert literal not in options, f"{literal!r} is retyped in the health check"
