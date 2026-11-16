import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def home(tmp_path, monkeypatch):
    """An isolated Zarqa home with the example config."""
    for var in ("ZARQA_CONFIG", "ZARQA_BIND_HOST", "ZARQA_BIND_PORT", "ZARQA_AUTH_PASSWORD",
                "ZARQA_SECRET_KEY", "ZARQA_ALLOW_UNAUTHENTICATED_NETWORK"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("ZARQA_HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    shutil.copyfile(ROOT / "config.example.yaml", tmp_path / "config.yaml")
    from zarqa import config
    from zarqa.connectors import hub
    config._CONFIG = None
    hub._HUB = None
    yield tmp_path
    if hub._HUB:
        hub._HUB.close()
    config._CONFIG = None
    hub._HUB = None


def write_cfg(home: Path, mutate):
    import yaml
    p = home / "config.yaml"
    d = yaml.safe_load(p.read_text())
    mutate(d)
    p.write_text(yaml.safe_dump(d))
