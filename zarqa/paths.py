"""Where Zarqa keeps user files.

* Source checkout: ``config.yaml``, ``.env`` and ``data/`` live in the checkout root.
* Installed wheel: they live in ``$ZARQA_HOME`` (default ``~/.zarqa``),
  created by ``zarqa init``.
"""
from __future__ import annotations

import os
from pathlib import Path

PKG_DIR = Path(__file__).resolve().parent
REPO_ROOT = PKG_DIR.parent


def is_checkout() -> bool:
    return (REPO_ROOT / "pyproject.toml").is_file() and (REPO_ROOT / "config.example.yaml").is_file()


def home_dir() -> Path:
    env = os.getenv("ZARQA_HOME", "").strip()
    if env:
        return Path(env).expanduser()
    if is_checkout():
        return REPO_ROOT
    return Path.home() / ".zarqa"
