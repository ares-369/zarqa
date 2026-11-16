import time

from zarqa.jobs import JobManager


def _wait(mgr, jid, timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        j = mgr.get(jid)
        if j["status"] not in ("queued", "running"):
            return j
        time.sleep(0.02)
    raise AssertionError("job did not finish")


def test_job_runs(tmp_path):
    m = JobManager(tmp_path / "j.sqlite")
    jid = m.submit("t", {"a": 1}, lambda ctl: {"ok": True})
    assert _wait(m, jid)["status"] == "done"


def test_job_error(tmp_path):
    m = JobManager(tmp_path / "j.sqlite")

    def boom(ctl):
        raise RuntimeError("x")
    assert _wait(m, m.submit("t", {}, boom))["status"] == "error"


def test_job_cancel(tmp_path):
    m = JobManager(tmp_path / "j.sqlite")

    def loop(ctl):
        for _ in range(500):
            if not ctl.checkpoint():
                break
            time.sleep(0.01)
        return {}
    jid = m.submit("t", {}, loop)
    time.sleep(0.05)
    assert m.cancel(jid)
    assert _wait(m, jid)["status"] == "cancelled"
