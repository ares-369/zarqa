"""The code version (X.Y.Z-beta) and the package version in pyproject.toml (X.Y.ZbN) agree."""

import re
from pathlib import Path

import zarqa

ROOT = Path(__file__).resolve().parent.parent


def test_versions_agree():
    code = zarqa.__version__
    m = re.fullmatch(r"(\d+\.\d+\.\d+)(?:-beta)?", code)
    assert m, f"__version__ must read X.Y.Z or X.Y.Z-beta, not {code!r}"
    py = re.search(r'^version = "([^"]+)"', (ROOT / "pyproject.toml").read_text(), re.M).group(1)
    want = m.group(1) + ("b" if code.endswith("-beta") else "")
    assert py == m.group(1) or re.fullmatch(re.escape(want) + r"\d+", py), (code, py)


def test_package_data_lists_every_data_file():
    """Files the code reads at run time must be in the wheel (pyproject package-data)."""
    text = (ROOT / "pyproject.toml").read_text()
    for f in ("zarqa/intel/attack_data.json", "zarqa/config.example.yaml"):
        assert (ROOT / f).exists()
    assert '"intel/*.json"' in text and '"config.example.yaml"' in text
