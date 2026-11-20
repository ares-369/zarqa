"""Browser smoke test: every page of the web UI, on the demo data, in headless Chromium.

Fails on a JavaScript error, a failed API call, or "undefined" / "NaN" / "[object Object]" on screen, at desktop
and phone width. Skipped unless Playwright for Python is installed (the CI "UI smoke test" job installs it with
Chromium). A local Chromium can be used with ZARQA_UI_CHROMIUM=/path/to/chrome.
"""

import os
import re
import socket
import subprocess
import sys
import time
import urllib.request

import pytest

sync_api = pytest.importorskip("playwright.sync_api")

PAGES = ["overview", "intel", "entities", "add", "sources", "ask", "brand", "profile", "connectors", "jobs", "settings"]
BAD_TEXT = ("undefined", "NaN", "[object Object]")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    home = tmp_path_factory.mktemp("ui-demo")
    env = {**os.environ, "ZARQA_HOME": str(home), "ZARQA_CONFIG": str(home / "config.yaml")}
    subprocess.run([sys.executable, "-m", "zarqa", "demo", "--dir", str(home)], check=True, env=env,
                   capture_output=True, timeout=300)
    port = _free_port()
    cfg = home / "config.yaml"
    cfg.write_text(re.sub(r"bind_port: \d+", f"bind_port: {port}", cfg.read_text()))
    proc = subprocess.Popen([sys.executable, "-m", "zarqa", "serve"], env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            urllib.request.urlopen(base + "/healthz", timeout=1)
            break
        except OSError:
            time.sleep(0.2)
    else:
        proc.kill()
        pytest.fail("the demo server did not start: " + (proc.stdout.read() or b"").decode()[-2000:])
    yield base
    proc.terminate()
    proc.wait(timeout=10)


def _browser(p):
    exe = os.getenv("ZARQA_UI_CHROMIUM")
    try:
        return p.chromium.launch(**({"executable_path": exe} if exe else {}), args=["--no-sandbox"])
    except sync_api.Error as exc:
        if "Executable doesn't exist" in str(exc):
            pytest.skip("no Chromium for Playwright: run `python -m playwright install chromium`")
        raise


def _visit_all(page, base, issues, label):
    current = {"page": ""}
    page.on("pageerror", lambda e: issues.append(f"[{label} {current['page']}] JS error: {e}"))
    page.on("console", lambda m: m.type == "error" and issues.append(f"[{label} {current['page']}] console: {m.text}"))
    page.on("response", lambda r: r.status >= 400 and issues.append(
        f"[{label} {current['page']}] HTTP {r.status} {r.url.replace(base, '')}"))
    details: list[str] = []
    for name in PAGES:
        current["page"] = name
        page.goto(f"{base}/#{name}", wait_until="networkidle")
        page.wait_for_timeout(300)
        text = page.inner_text("main")
        for bad in BAD_TEXT:
            if bad in text:
                issues.append(f"[{label} {name}] shows {bad!r}")
        if len(text.strip()) < 20:
            issues.append(f"[{label} {name}] nearly empty")
        for href in page.eval_on_selector_all("main a[href^='#']", "els => els.map(e => e.getAttribute('href'))"):
            kind = href[1:].split("/")[0]
            if "/" in href and kind in ("doc", "entity", "inv") and not any(d.startswith(f"#{kind}/") for d in details):
                details.append(href)
    for href in details:
        current["page"] = href
        page.goto(f"{base}/{href}", wait_until="networkidle")
        page.wait_for_timeout(300)
        text = page.inner_text("main")
        for bad in BAD_TEXT:
            if bad in text:
                issues.append(f"[{label} {href}] shows {bad!r}")
    return details


def test_every_page_loads_cleanly(server):
    issues: list[str] = []
    with sync_api.sync_playwright() as p:
        b = _browser(p)
        page = b.new_page(viewport={"width": 1300, "height": 900})
        details = _visit_all(page, server, issues, "desktop")
        assert details, "no report or entity pages were reachable from the demo data"
        b.close()
    assert issues == []


def test_pages_fit_a_phone(server):
    wide: list[str] = []
    with sync_api.sync_playwright() as p:
        b = _browser(p)
        page = b.new_page(viewport={"width": 412, "height": 915}, device_scale_factor=1)
        for name in PAGES:
            page.goto(f"{server}/#{name}", wait_until="networkidle")
            page.wait_for_timeout(300)
            w = page.evaluate("[document.documentElement.scrollWidth, window.innerWidth]")
            if w[0] > w[1] + 2:
                wide.append(f"{name}: {w[0]}px wide on a {w[1]}px screen")
        b.close()
    assert wide == []

