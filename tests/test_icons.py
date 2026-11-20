"""The UI ships a subset of the icon font: every icon it names must be in the subset."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CSS = ROOT / "zarqa/static/mdi/css/icons.css"


def _named() -> set[str]:
    js = (ROOT / "zarqa/static/app.js").read_text()
    html = "".join((ROOT / "zarqa/templates" / n).read_text() for n in ("index.html", "login.html"))
    names = set(re.findall(r"mdi-([a-z0-9-]+)", js + html)) - {"set"}
    names |= set(re.findall(r'\bicon\("([a-z0-9-]+)"\)', js))
    names |= set(re.findall(r'\bsection\([^\n]*?,\s*"([a-z0-9-]+)"\s*,', js))
    for expr in re.findall(r"\bicon\(([^()]*\?[^()]*)\)", js):          # icon(x ? "a" : "b")
        names |= set(re.findall(r'"([a-z0-9-]+)"', expr))
    return names


def test_every_used_icon_is_in_the_subset():
    have = set(re.findall(r"\.mdi-([a-z0-9-]+)::before", CSS.read_text()))
    missing = sorted(_named() - have)
    assert not missing, f"icons missing from the subset, run scripts/build_icons.py: {missing}"


def test_font_is_small():
    fonts = list((ROOT / "zarqa/static/mdi/fonts").iterdir())
    assert [f.name for f in fonts] == ["icons.woff2"]
    assert fonts[0].stat().st_size < 50_000


def test_no_inline_styles_in_the_ui():
    """The Content Security Policy (style-src 'self') blocks inline style attributes, so they silently do nothing."""
    js = (ROOT / "zarqa/static/app.js").read_text()
    assert not re.search(r"\bstyle:\s*[\"'`]", js)
