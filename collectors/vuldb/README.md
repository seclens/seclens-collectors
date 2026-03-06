# VulDB Vulnerability Collector

Fetches recent vulnerabilities from the [VulDB](https://vuldb.com/) RSS feed.

## Source

- **Publisher:** VulDB
- **Feed URL:** https://vuldb.com/?rss.recent
- **Content Type:** Vulnerability reports, CVE entries
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
0 * * * * cd /path/to/vuldb && python collector.py >> /var/log/vuldb-collector.log 2>&1
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECLENS_URL` | Yes | - | SecLens server URL |
| `SECLENS_TOKEN` | Yes | - | API token for authentication |
| `VULDB_FEED_URL` | No | VulDB RSS URL | Override the RSS feed URL |
