# VIPRead Collector

Fetches security knowledge articles from the [VIPRead](https://vipread.com/) RSS feed.

## Source

- **Publisher:** VIPRead
- **Feed URL:** https://vipread.com/rss
- **Content Type:** Security knowledge base articles
- **Language:** Chinese (zh)
- **Update Frequency:** Several times per week

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

Recommended: every 4 hours.

```bash
# crontab
0 */4 * * * cd /path/to/vipread && python collector.py >> /var/log/vipread-collector.log 2>&1
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECLENS_URL` | Yes | - | SecLens server URL |
| `SECLENS_TOKEN` | Yes | - | API token for authentication |
| `VIPREAD_FEED_URL` | No | vipread RSS URL | Override the RSS feed URL |
