# MSRC Security Update Guide Collector

Fetches vulnerability revisions and advisories from the [Microsoft Security Response Center](https://msrc.microsoft.com/update-guide/) RSS feed.

## Source

- **Publisher:** Microsoft
- **Feed URL:** https://api.msrc.microsoft.com/update-guide/rss
- **Content Type:** Security vulnerabilities, CVEs, patch advisories
- **Language:** English
- **Update Frequency:** Multiple times daily

## Setup

```bash
pip install -r requirements.txt

export SECLENS_URL="https://your-seclens-server.com"
export SECLENS_TOKEN="your-api-token"
```

## Run

```bash
python collector.py
```

## Schedule

Recommended: every 1 hour.

```bash
# crontab
0 * * * * cd /path/to/msrc_update_guide && python collector.py >> /var/log/msrc-collector.log 2>&1
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECLENS_URL` | Yes | - | SecLens server URL |
| `SECLENS_TOKEN` | Yes | - | API token for authentication |
| `MSRC_FEED_URL` | No | MSRC RSS URL | Override the RSS feed URL |
