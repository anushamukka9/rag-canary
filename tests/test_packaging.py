"""Packaging guards: version sync and entry points."""

import re
from pathlib import Path

import rag_canary

ROOT = Path(__file__).resolve().parent.parent


def test_version_synced_with_pyproject():
    pyproject = (ROOT / "pyproject.toml").read_text()
    match = re.search(r'^version = "([^"]+)"', pyproject, re.M)
    assert match, "no version in pyproject.toml"
    assert match.group(1) == rag_canary.__version__


def test_cli_entry_point_importable():
    from rag_canary.cli import main

    assert callable(main)


def test_pyproject_declares_script():
    pyproject = (ROOT / "pyproject.toml").read_text()
    assert "rag-canary" in pyproject
    assert "rag_canary.cli:main" in pyproject
