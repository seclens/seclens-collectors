# The Hacker News Collector

Fetches cybersecurity headlines from [The Hacker News](https://thehackernews.com/) RSS feed.

## Source

- **Publisher:** The Hacker News
- **Feed URL:** https://feeds.feedburner.com/TheHackersNews
- **Content Type:** Security news, vulnerability reports, threat intelligence
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
0 * * * * cd /path/to/the_hacker_news && python collector.py >> /var/log/thn-collector.log 2>&1
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECLENS_URL` | Yes | - | SecLens server URL |
| `SECLENS_TOKEN` | Yes | - | API token for authentication |
| `THN_FEED_URL` | No | feedburner URL | Override the RSS feed URL |
