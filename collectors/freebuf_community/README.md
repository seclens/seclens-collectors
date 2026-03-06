# FreeBuf Community Collector

Fetches security articles from the [FreeBuf](https://www.freebuf.com/) RSS feed.

## Source

- **Publisher:** FreeBuf
- **Feed URL:** https://www.freebuf.com/feed
- **Content Type:** Security community articles and news
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

Recommended: every 30 minutes.

```bash
# crontab
*/30 * * * * cd /path/to/freebuf_community && python collector.py >> /var/log/freebuf-collector.log 2>&1
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECLENS_URL` | Yes | - | SecLens server URL |
| `SECLENS_TOKEN` | Yes | - | API token for authentication |
| `FREEBUF_FEED_URL` | No | freebuf feed URL | Override the RSS feed URL |
