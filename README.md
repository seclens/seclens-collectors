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

# Preview profile selection only
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
  "continue_on_error": true
}
```

Default profile keeps all collectors disabled (`enabled: []`). Enable only what you need.

`run_mode` options:
- `enabled_only`: run only collectors in `enabled`
- `all_except_disabled`: run all discovered collectors except `disabled`

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
# Single entry: profile-driven run every hour
0 * * * * cd /opt/seclens-collectors && /usr/bin/python3 run_collectors.py --profile profiles/default.json >> /var/log/seclens/collectors.log 2>&1
```

## License

MIT
