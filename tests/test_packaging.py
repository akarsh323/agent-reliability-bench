"""Tests that packaging metadata stays consistent."""

import tomllib
from pathlib import Path

import reliabench
from reliabench import _registry

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text())


def requirements(name: str) -> set[str]:
    lines = (ROOT / name).read_text().splitlines()
    return {
        line.strip()
        for line in lines
        if line.strip() and not line.startswith(("#", "-r"))
    }


def test_requirements_match_pyproject():
    project = PYPROJECT["project"]
    assert requirements("requirements.txt") == set(project["dependencies"])
    assert requirements("requirements-dev.txt") == set(
        project["optional-dependencies"]["dev"]
    )


def test_version_and_entry_point():
    assert PYPROJECT["project"]["version"] == reliabench.__version__
    entry_points = PYPROJECT["project"]["entry-points"]["inspect_ai"]
    assert entry_points == {"reliabench": "reliabench._registry"}
    assert set(_registry.__all__) == {"ReferenceAgentAPI", "credit_desk"}
