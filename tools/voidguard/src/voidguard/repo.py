"""Repository discovery: files, workflows, and tool configs.

Everything here is read-only and static. No network, no execution of repo code.
"""

from __future__ import annotations

import configparser
import json
import re
from dataclasses import dataclass
from pathlib import Path

try:  # py311+
    import tomllib
except ImportError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

import yaml

_SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", ".tox", ".nox", ".venv", "venv", "node_modules", "dist",
    "build", ".eggs", "htmlcov", "target", ".next", ".cache",
}

_TEXT_MAX = 2 * 1024 * 1024  # per-file read cap


@dataclass
class WorkflowFile:
    path: Path          # absolute
    rel: str            # repo-relative
    data: dict | None   # parsed YAML (None if unparseable)
    text: str


class Repo:
    """A scanned checkout. Caches file lists; all lookups repo-relative."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        self._files: list[Path] | None = None
        self._workflows: list[WorkflowFile] | None = None
        self.notes: list[str] = []

    # -- files ---------------------------------------------------------------

    def files(self) -> list[Path]:
        if self._files is None:
            out: list[Path] = []
            stack = [self.root]
            while stack:
                d = stack.pop()
                try:
                    entries = sorted(d.iterdir())
                except OSError:
                    continue
                for p in entries:
                    if p.is_dir():
                        if p.name not in _SKIP_DIRS:
                            stack.append(p)
                    elif p.is_file():
                        out.append(p)
            self._files = out
        return self._files

    def rel(self, p: Path) -> str:
        return str(p.relative_to(self.root))

    def read(self, p: Path) -> str:
        try:
            if p.stat().st_size > _TEXT_MAX:
                return ""
            return p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def glob(self, *patterns: str) -> list[Path]:
        """Repo-relative glob over the cached walk (so skip-dirs stay skipped)."""

        out = []
        for p in self.files():
            r = self.rel(p)
            if any(_glob_match(r, pat) for pat in patterns):
                out.append(p)
        return out

    def exists(self, rel_path: str) -> bool:
        return (self.root / rel_path).exists()

    # -- workflows -------------------------------------------------------------

    def workflows(self) -> list[WorkflowFile]:
        if self._workflows is None:
            out = []
            for p in self.glob(".github/workflows/*.yml", ".github/workflows/*.yaml"):
                text = self.read(p)
                try:
                    data = yaml.safe_load(text)
                    if not isinstance(data, dict):
                        data = None
                except yaml.YAMLError:
                    data = None
                    self.notes.append(
                        f"workflow {self.rel(p)} did not parse as YAML; skipped "
                        "(findings in it cannot be assessed)"
                    )
                out.append(WorkflowFile(path=p, rel=self.rel(p), data=data, text=text))
            self._workflows = out
        return self._workflows

    # -- language / config discovery -------------------------------------------

    def python_test_files(self) -> list[Path]:
        out = []
        for p in self.files():
            if p.suffix != ".py":
                continue
            r = self.rel(p)
            name = p.name
            if name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py":
                out.append(p)
            elif r.startswith(("tests/", "test/")) or "/tests/" in r or "/test/" in r:
                out.append(p)
        return out

    def first_party_packages(self) -> dict[str, str]:
        """Import name -> layout ('src' or 'flat') for first-party packages."""

        pkgs: dict[str, str] = {}
        src = self.root / "src"
        if src.is_dir():
            for child in sorted(src.iterdir()):
                if child.is_dir() and (child / "__init__.py").exists():
                    pkgs[child.name] = "src"
        for child in sorted(self.root.iterdir()):
            if (
                child.is_dir()
                and child.name not in _SKIP_DIRS
                and child.name not in {"tests", "test", "docs", "examples", "scripts", "src"}
                and (child / "__init__.py").exists()
            ):
                pkgs.setdefault(child.name, "flat")
        return pkgs

    def mypy_config(self) -> tuple[str, dict, dict[str, dict]] | None:
        """(config_rel_path, global_section, per_module_sections) or None.

        Reads mypy.ini / setup.cfg [mypy] / pyproject [tool.mypy]. Values are
        normalized to strings; booleans lowercased.
        """

        ini = self.root / "mypy.ini"
        if ini.exists():
            cp = configparser.ConfigParser()
            try:
                cp.read_string(self.read(ini))
            except configparser.Error:
                return None
            return ("mypy.ini",) + _split_mypy_sections(cp)
        setup = self.root / "setup.cfg"
        if setup.exists():
            cp = configparser.ConfigParser()
            try:
                cp.read_string(self.read(setup))
            except configparser.Error:
                cp = None  # type: ignore[assignment]
            if cp is not None and cp.has_section("mypy"):
                return ("setup.cfg",) + _split_mypy_sections(cp)
        pyproj = self.root / "pyproject.toml"
        if pyproj.exists() and tomllib is not None:
            try:
                data = tomllib.loads(self.read(pyproj))
            except Exception:
                return None
            tool = data.get("tool", {}).get("mypy")
            if isinstance(tool, dict):
                glob = {
                    k: _norm(v) for k, v in tool.items() if k != "overrides"
                }
                per: dict[str, dict] = {}
                for ov in tool.get("overrides", []) or []:
                    mods = ov.get("module", [])
                    if isinstance(mods, str):
                        mods = [mods]
                    body = {k: _norm(v) for k, v in ov.items() if k != "module"}
                    for m in mods:
                        per[str(m)] = body
                return ("pyproject.toml", glob, per)
        return None

    def tsconfig(self) -> dict | None:
        p = self.root / "tsconfig.json"
        if not p.exists():
            return None
        text = self.read(p)
        # tsconfig is JSONC: strip // and /* */ comments, trailing commas.
        text = re.sub(r"//[^\n]*", "", text)
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
        text = re.sub(r",\s*([}\]])", r"\1", text)
        try:
            data = json.loads(text)
            return data if isinstance(data, dict) else None
        except json.JSONDecodeError:
            return None

    def pytest_markers(self) -> set[str]:
        """Markers declared in pytest config (pytest.ini / pyproject / setup.cfg)."""

        out: set[str] = set()
        for relf, section, key in (
            ("pytest.ini", "pytest", "markers"),
            ("setup.cfg", "tool:pytest", "markers"),
        ):
            p = self.root / relf
            if p.exists():
                cp = configparser.ConfigParser()
                try:
                    cp.read_string(self.read(p))
                except configparser.Error:
                    continue
                if cp.has_option(section, key):
                    for line in cp.get(section, key).splitlines():
                        line = line.strip()
                        if line:
                            out.add(line.split(":")[0].split("(")[0].strip())
        pyproj = self.root / "pyproject.toml"
        if pyproj.exists() and tomllib is not None:
            try:
                data = tomllib.loads(self.read(pyproj))
            except Exception:
                data = {}
            markers = (
                data.get("tool", {}).get("pytest", {}).get("ini_options", {}).get("markers", [])
            )
            for line in markers if isinstance(markers, list) else []:
                out.add(str(line).split(":")[0].split("(")[0].strip())
        return out


def _split_mypy_sections(cp: configparser.ConfigParser) -> tuple[dict, dict[str, dict]]:
    glob: dict = {}
    per: dict[str, dict] = {}
    for section in cp.sections():
        body = {k: _norm(v) for k, v in cp.items(section)}
        if section == "mypy":
            glob = body
        elif section.startswith("mypy-"):
            per[section[len("mypy-"):]] = body
    return glob, per


def _norm(v: object) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, list):
        return ", ".join(str(x) for x in v)
    return str(v).strip()


def _glob_match(rel: str, pattern: str) -> bool:
    """fnmatch with '**' support, anchored to the repo root."""

    rx = re.escape(pattern)
    rx = rx.replace(r"\*\*/", "(?:.*/)?").replace(r"\*\*", ".*").replace(r"\*", "[^/]*")
    return re.fullmatch(rx, rel) is not None
