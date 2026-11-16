# Contributing

Issues and pull requests are welcome. Zarqa is solo-maintained, so reviews can take a while.

## Development

```bash
python3 -m venv .venv-test
./.venv-test/bin/pip install -e '.[dev]'
./.venv-test/bin/ruff check zarqa tests scripts
./.venv-test/bin/pytest -q
node --check zarqa/static/app.js
```

## Rules

- Tests for every change; CI runs them on Python 3.10, 3.11 and 3.12.
- Few required packages; anything optional is an extra.
- The web UI loads nothing from the internet and never parses data as HTML (`textContent` only).
- New icons: run `scripts/build_icons.py` with the full `@mdi/font` package (see the script).
- No secrets, internal names or real indicators from private sources in the repository.
- Connectors for specific products belong in their own repositories; this one ships generic bridges.
