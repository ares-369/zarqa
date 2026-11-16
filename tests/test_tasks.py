import time

from zarqa.jobs import JobManager
from zarqa.tasks import TASKS, run_task


def test_ping_task_runs_through_the_job_manager(tmp_path):
    m = JobManager(tmp_path / "j.sqlite")
    jid = m.submit("ping", {}, None, task="ping", params={"echo": "hi"})
    end = time.time() + 5
    while time.time() < end and m.get(jid)["status"] in ("queued", "running"):
        time.sleep(0.02)
    assert m.get(jid)["status"] == "done" and "ping" in TASKS


def test_unknown_task():
    import pytest
    with pytest.raises(ValueError):
        run_task("nope", {})
