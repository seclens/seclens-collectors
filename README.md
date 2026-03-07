# SecLens Collectors

Community-driven security intelligence collectors for the [SecLens](https://github.com/seclens/SecLens) platform.

## What is this?

SecLens is a security intelligence aggregation platform. This repository contains **independent collector scripts** that fetch security bulletins from various sources and push them to a SecLens server via its Ingest API.

Each collector is a standalone program that:
1. Fetches data from a specific source (RSS, API, web scraping)
2. Normalizes it into a standard JSON format
3. POSTs it to a SecLens server with an API token

**No SDK required.** Collectors can be written in any language. The only contract is an HTTP POST with JSON.

## Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/seclens/seclens-collectors.git
cd seclens-collectors

# 2. Configure
export SECLENS_URL="https://your-seclens-server.com"
export SECLENS_TOKEN="your-api-token"

# 3. Run one collector (example)
cd collectors/the_hacker_news
pip install -r requirements.txt
python collector.py
```

## Centralized Runner (Enable/Disable Collectors by Profile)

Use a single profile file to decide which collectors run, instead of maintaining dozens of cron entries.

```bash
cd seclens-collectors

# Show all discovered collectors
python run_collectors.py --list

# Preview profile selection and due/skip decisions
python run_collectors.py --profile profiles/default.json --dry-run

# Execute selected collectors
python run_collectors.py --profile profiles/default.json
```

Profile example (`profiles/default.json`):

```json
{
  "run_mode": "enabled_only",
  "enabled": [],
  "disabled": [],
  "concurrency": 2,
  "timeout_seconds": 300,
  "continue_on_error": true,
  "state_file": ".state/scheduler_state.json",
  "default_interval_minutes": 60,
  "min_interval_minutes": 30,
  "schedule_overrides": {
    "the_hacker_news": {
      "interval_minutes": 30,
      "anchor_utc": "2026-03-07T02:10:00Z"
    },
    "cloudflare_blog": {
      "interval_minutes": 60,
      "anchor_utc": "2026-03-07T02:25:00Z",
      "env": {
        "HTTP_PROXY": "http://192.168.15.88:8080",
        "HTTPS_PROXY": "http://192.168.15.88:8080"
      }
    }
  }
}
```

Default profile keeps all collectors disabled (`enabled: []`). Enable only what you need.

`run_mode` options:
- `enabled_only`: run only collectors in `enabled`
- `all_except_disabled`: run all discovered collectors except `disabled`

Scheduling priority (highest to lowest):
- Environment override: `COLLECTOR_<SLUG>_INTERVAL_MINUTES`, `COLLECTOR_<SLUG>_ANCHOR_UTC`
- Profile `schedule_overrides.<slug>`
- Collector `config.example.yaml` recommended schedule
- `default_interval_minutes` fallback

The scheduler persists `next_due_at` in `state_file`, so service restarts do not trigger all collectors at once.
Set `anchor_utc` to spread collector start times and avoid burst traffic.
`schedule_overrides.<slug>.env` can inject plugin-specific environment variables (for example proxy settings). By default, plugins do not use a proxy unless configured.

## Collector List

| Collector | Source | Type | Language |
|-----------|--------|------|----------|
| the_hacker_news | The Hacker News RSS | RSS | Python |
| *more coming soon...* | | | |

## How Collectors Work

Every collector follows the same pattern:

```
[External Source] --fetch--> [Collector Script] --POST JSON--> [SecLens Server]
```

The SecLens Ingest API accepts a JSON array:

```bash
curl -X POST https://your-server.com/v1/ingest/bulletins \
  -H "Authorization: Bearer $SECLENS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '[{
    "source": {
      "source_slug": "the_hacker_news",
      "external_id": "unique-id-from-source",
      "origin_url": "https://original-article-url.com"
    },
    "content": {
      "title": "Article Title",
      "summary": "Brief description...",
      "published_at": "2026-03-06T08:00:00Z",
      "language": "en"
    },
    "fetched_at": "2026-03-06T10:00:00Z",
    "labels": ["security-news"],
    "topics": ["vulnerability"]
  }]'
```

Response: `{"accepted": 1, "duplicates": 0}`

## Contributing

We welcome contributions! See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for details.

**To add a new collector:**
1. Create a directory under `collectors/your_source_name/`
2. Implement the fetch + normalize + push logic
3. Add `requirements.txt`, `README.md`, and `config.example.yaml`
4. Submit a pull request

## Running with Docker

```bash
# Run a single collector
docker compose run the_hacker_news

# Run all collectors
docker compose up
```

## Running with Cron

```bash
# Wake every 5 minutes; actual run/skip is decided by collector schedule
*/5 * * * * cd /opt/seclens-collectors && /opt/seclens-collectors/.venv/bin/python run_collectors.py --profile profiles/default.json >> /var/log/seclens/collectors.log 2>&1
```

## Running with systemd timer (recommended)

```bash
sudo cp docs/systemd/seclens-collectors.service /etc/systemd/system/
sudo cp docs/systemd/seclens-collectors.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now seclens-collectors.timer

# Manual trigger (optional)
sudo systemctl start seclens-collectors.service

# View logs
sudo journalctl -u seclens-collectors.service -f
```

## License

MIT
