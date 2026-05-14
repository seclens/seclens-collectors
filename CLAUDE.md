# CLAUDE.md

This file provides guidance to Claude Code when working in this repository.

## Project Memory: SecLens / Collectors Split

- `/Users/donaldford/app/seclens-collectors` is the collector project. It contains standalone collector scripts and the profile-driven runner.
- `/Users/donaldford/app/SecLens` is the server project. It owns the FastAPI app, database, UI, ingest API, subscriptions, and notifications.
- Keep these as sibling repositories. Do not nest this repo inside `SecLens`, and do not treat it as a Git submodule.
- The correct remote for this repository is `git@github.seclens:seclens/seclens-collectors.git`.
- `git@github.wzfukui:wzfukui/seclens-collectors.git` is an older bootstrap/archive remote. It has fewer collectors and no shared history with the current `github.seclens` repo.
- Production collector host: `192.168.44.44`, repository path `/home/ubuntu/seclens-collectors`, systemd timer `seclens-collectors.timer`.
- Before deployment, always compare the remote host worktree for untracked or local-only collectors and preserve them. On 2026-05-14, `collectors/ransomware_live/` existed only on `192.168.44.44`; it was backed up, restored, committed, and pushed.
- `arxiv_cs_cr` was added on 2026-05-14. It uses the public arXiv API for `cat:cs.CR`, requires no arXiv API key, publishes under `security_research`, and should run daily.

## Common Commands

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install requests pytest pyyaml beautifulsoup4 selenium selenium-stealth webdriver-manager urllib3

python run_collectors.py --profile profiles/default.example.json --dry-run
python -m pytest tests collectors/arxiv_cs_cr/test_collector.py
```

## Collector Rules

- Collectors must be standalone and must not import from the SecLens server project (`app.*`).
- Each collector should include `collector.py`, `manifest.json`, `requirements.txt`, `config.example.yaml`, and `README.md`.
- Use `shared.manifest.load_manifest_for_slug` so ingest can sync source metadata.
- Keep state files such as `.cursor`, `.cache.json`, `.state/`, and local profiles out of Git.
- Use low-frequency polling and a clear User-Agent for public sources.
