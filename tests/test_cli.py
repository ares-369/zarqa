import pytest

from zarqa import __version__, cli


def test_version(capsys):
    cli.cli_main(["version"])
    assert capsys.readouterr().out.strip() == f"zarqa {__version__}"


def test_init_writes_config_and_private_env(tmp_path, monkeypatch):
    monkeypatch.setenv("ZARQA_HOME", str(tmp_path / "h"))
    assert cli.cmd_init() == 0
    home = tmp_path / "h"
    assert (home / "config.yaml").exists() and (home / "data").is_dir()
    env = home / ".env"
    assert "ZARQA_SECRET_KEY=" in env.read_text() and oct(env.stat().st_mode)[-3:] == "600"
    before = env.read_text()
    assert cli.cmd_init() == 0                      # never overwrites
    assert env.read_text() == before


def test_models(home, capsys):
    with pytest.raises(SystemExit):
        cli.cli_main(["models"])
    out = capsys.readouterr().out
    assert "extractor" in out and "analyst" in out and "reporter" in out


def test_doctor_runs_offline(home, capsys):
    with pytest.raises(SystemExit) as e:
        cli.cli_main(["doctor", "--offline"])
    out = capsys.readouterr().out
    assert e.value.code == 0 and "organization" in out and "0 problem(s)" in out
