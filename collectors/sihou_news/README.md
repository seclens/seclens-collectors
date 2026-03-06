# Sihou News Collector

Fetches security news from [Sihou (4hou.com)](https://www.4hou.com/) RSS feed.

## Source

- **Publisher:** Sihou RoarTalk
- **Feed URL:** https://www.4hou.com/feed
- **Content Type:** Security news
- **Language:** Chinese (zh)
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
0 * * * * cd /path/to/sihou_news && python collector.py >> /var/log/sihou-news-collector.log 2>&1
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECLENS_URL` | Yes | - | SecLens server URL |
| `SECLENS_TOKEN` | Yes | - | API token for authentication |
| `SIHOU_FEED_URL` | No | https://www.4hou.com/feed | Override the RSS feed URL |
