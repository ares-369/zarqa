"""Rebuild the icon subset (static/mdi) from the full Material Design Icons webfont.

Shared between the ares-369 tools: it finds the package's templates/ and static/ folders, keeps only the
icons named there, and writes static/mdi/fonts/icons.woff2 and static/mdi/css/icons.css. After using a
new icon, run:

    npm pack @mdi/font@7.4.47 && tar xzf mdi-font-7.4.47.tgz      # gives package/css and package/fonts
    pip install fonttools brotli                                   # build-time only, not a dependency
    python scripts/build_icons.py package

tests/test_icons.py fails when the UI names an icon the subset lacks.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_SKIP = ("mdi", "node_modules", ".venv", "build", "_app")
_SPIN = ('.mdi-spin::before{-webkit-animation:mdi-spin 2s infinite linear;animation:mdi-spin 2s infinite linear}\n'
         "@-webkit-keyframes mdi-spin{0%{-webkit-transform:rotate(0deg);transform:rotate(0deg)}"
         "100%{-webkit-transform:rotate(359deg);transform:rotate(359deg)}}\n"
         "@keyframes mdi-spin{0%{-webkit-transform:rotate(0deg);transform:rotate(0deg)}"
         "100%{-webkit-transform:rotate(359deg);transform:rotate(359deg)}}\n")


def static_dir() -> Path:
    for p in sorted(ROOT.glob("**/static/mdi")):
        if not any(part in _SKIP[1:] or part.startswith(".") for part in p.relative_to(ROOT).parts):
            return p.parent
    raise SystemExit("no static/mdi folder found")


def sources() -> list[Path]:
    out = []
    for pat in ("**/templates/*.html", "**/static/*.js", "**/static/**/*.js"):
        for p in ROOT.glob(pat):
            rel = p.relative_to(ROOT).parts
            if not any(part in _SKIP or part.startswith(".") for part in rel[:-1]) and p not in out:
                out.append(p)
    return out


def used_names(known: set[str]) -> list[str]:
    text = "".join(p.read_text(encoding="utf-8") for p in sources())
    lits = set(re.findall(r"[\"'`]([a-z0-9-]+)[\"'`]", text)) | set(re.findall(r"mdi-([a-z0-9-]+)", text))
    return sorted(n for n in lits if n in known)


def main(pkg: str) -> None:
    from fontTools import subset
    pkg_dir = Path(pkg)
    css = (pkg_dir / "css" / "materialdesignicons.min.css").read_text()
    codes = dict(re.findall(r'\.mdi-([a-z0-9-]+)::?before\{content:"\\([0-9A-Fa-f]+)"', css))
    names = used_names(set(codes))
    out = static_dir() / "mdi"
    (out / "fonts").mkdir(parents=True, exist_ok=True)
    (out / "css").mkdir(parents=True, exist_ok=True)
    opts = subset.Options()
    opts.flavor = "woff2"
    opts.layout_features = []
    opts.name_IDs = ["*"]
    font = subset.load_font(str(pkg_dir / "fonts" / "materialdesignicons-webfont.ttf"), opts)
    sub = subset.Subsetter(opts)
    sub.populate(unicodes=[int(codes[n], 16) for n in names])
    sub.subset(font)
    subset.save_font(font, str(out / "fonts" / "icons.woff2"), opts)
    rules = "".join(f'.mdi-{n}::before{{content:"\\{codes[n]}"}}\n' for n in names)
    spin = _SPIN if any("mdi-spin" in p.read_text(encoding="utf-8") for p in sources()) else ""
    (out / "css" / "icons.css").write_text(
        "/* Subset of Material Design Icons 7.4.47 (Apache-2.0, see ../LICENSE); built by scripts/build_icons.py */\n"
        '@font-face{font-family:"Material Design Icons";src:url("../fonts/icons.woff2") format("woff2");'
        "font-weight:normal;font-style:normal}\n"
        '.mdi::before,.mdi-set{display:inline-block;font:normal normal normal 24px/1 "Material Design Icons";'
        "font-size:inherit;text-rendering:auto;line-height:inherit;-webkit-font-smoothing:antialiased;"
        "-moz-osx-font-smoothing:grayscale}\n" + rules + spin)
    print(f"{len(names)} icons, {(out / 'fonts' / 'icons.woff2').stat().st_size} bytes -> {out}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "package")
