# Project standard

Actaeon, OniOps and Zarqa are built by the same author and follow one set of rules, so a user who knows one
knows how to install, run, configure and release the others. New tools start from this list. This page
is the same in every repository.

## Names and versions

- The package, CLI command and PyPI name are the project name in lower case (`actaeon`, `oniops`, `zarqa`).
  Environment variables start with the upper-case name (`ACTAEON_*`, `ONIOPS_*`, `ZARQA_*`).
- `__version__` in `<pkg>/__init__.py` reads `X.Y.Z-beta` while in beta; `pyproject.toml` has the
  PEP 440 form `X.Y.ZbN` (`0.2.0-beta` -> `0.2.0b0`). A test checks that they agree.
- Git tags and release titles use the code form: tag `vX.Y.Z-beta`, title `<Name> vX.Y.Z-beta`,
  published as a GitHub pre-release.
- Publishing the GitHub release runs `.github/workflows/publish.yaml`, which builds and uploads to
  PyPI with trusted publishing (no token stored in the repository).

## Install and run

- `pipx install <pkg>` (or `pip install <pkg>`) gives a working install, web UI included.
- `<pkg> init` writes `config.yaml`, `.env` (random secret key, mode 600) and `data/` to the home
  folder, `$<NAME>_HOME` or `~/.<pkg>`. It never overwrites existing files. In a source checkout,
  the checkout root is the home folder.
- Every tool has `serve`, `init`, `doctor`, `version` and `demo`. `demo` works offline, with no model
  and no external service.
- `config.example.yaml` documents every setting with its default. Secrets go in `.env` only.
- Docker: `docker compose up -d`, non-root user, data in a mounted folder. Linux service:
  `sudo bash scripts/install.sh`.

## Packaging

- Everything is declared in `pyproject.toml` (setuptools, Apache-2.0, `LICENSE` and `NOTICE`).
- Few required packages, listed and counted in CI; anything else is an extra. Every project has the
  extras `all` (every optional feature) and `dev` (tests and lint).
- The web UI loads nothing from the internet: no web fonts, CDNs or analytics. Icons are a subset of
  Material Design Icons built by `scripts/build_icons.py`, checked by `tests/test_icons.py`. No emojis.

## Repository files

`README.md`, `CHANGELOG.md`, `LICENSE`, `NOTICE`, `SECURITY.md`, `CONTRIBUTING.md`,
`CODE_OF_CONDUCT.md`, `DISCLAIMER.md`, `config.example.yaml`, `Dockerfile`, `docker-compose.yml`,
`docs/` and `scripts/`.

- **README** opens with the badges (CI, licence, Python versions, PyPI, release), one bold sentence
  saying what the tool does, a short paragraph, then the "Beta, solo-maintained" notice. Claims in it
  are ones the tests or the benchmark pages back.
- **CHANGELOG** follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/): `## [Unreleased]`,
  then `## [X.Y.Z-beta] — YYYY-MM-DD` with Security, Added, Changed, Fixed and Removed sections.
- **SECURITY.md** has the same three sections everywhere: reporting a vulnerability (private
  advisory), supported versions (latest release only), and links to `docs/threat-model.md` and the
  known limitations.
- **docs/** file names are lower-case kebab-case (`threat-model.md`, `known-limitations.md`).

## CI

`.github/workflows/ci.yml` runs, on every push:

- tests and ruff on Python 3.10, 3.11 and 3.12;
- a wheel smoke test: build, install outside the checkout, `init`, `demo`, start the server and fetch
  a page, plus the required-package count and a wheel size limit;
- security scans: bandit (medium and high fail the build; reviewed exceptions carry a `# nosec`
  comment that says why) and pip-audit over every extra;
- a secret scan (gitleaks);
- project-specific jobs (container build, PostgreSQL, browser or worker images).

## Where a project does not match yet

- OniOps: the container runs as root (moving to a fixed non-root user changes the owner of existing
  data folders, so it waits for a release with upgrade notes).
- OniOps: the web app (`webui.py`, `templates/`, `static/`, `playbooks/`) sits in the repository
  root and `setup.py` copies it into the wheel; Actaeon keeps it inside the package. `requirements.txt`
  stays for the OniOps installer and Dockerfile until that move.

- Zarqa: jobs run in the server only (no separate worker yet).

## Writing

- State what was tested and how; give numbers with their sample size and the misses. No superiority
  claims, no product or company names, no prices (token counts only).
- Commits are made as `ares-369`.
