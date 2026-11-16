# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Foundation: configuration (`config.yaml` + `.env`), home folder (`ZARQA_HOME` or `~/.zarqa`),
  `zarqa init | serve | doctor | version | models | users | hash-password`.
- Login modes none, basic, local, OIDC and reverse proxy, with viewer, operator and admin roles and
  identity-provider group mapping. The server refuses to listen on a network address without a login.
- Model providers per role (extractor, analyst, reporter): Ollama, Anthropic, Gemini, OpenAI, Azure
  OpenAI, OpenAI-compatible endpoints and a local model CLI, with fallbacks and rate-limit backoff.
- Privacy layer for cloud models: emails, private IPs, user names and listed terms are masked; public
  IPs are kept because they are the indicators.
- Background jobs (SQLite by default, PostgreSQL optional) and a task registry.
- Web shell: overview, jobs, settings (models with a diff before saving, model test, health check).
  Strict content security policy, no external assets, icon-font subset.
