# Doonsec WeChat Collector

Fetches security articles from the [Doonsec WeChat](https://wechat.doonsec.com/) RSS aggregator.

## Source

- **Publisher:** Doonsec (洞见网安)
- **Feed URL:** https://wechat.doonsec.com/rss.xml
- **Content Type:** Aggregated WeChat security articles
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
*/30 * * * * cd /path/to/doonsec_wechat && python collector.py >> /var/log/doonsec-collector.log 2>&1
```

## Whitelist Filtering

Optionally filter articles by author/account name:

```bash
export DOONSEC_WHITELIST_ENABLED=true
export DOONSEC_WHITELIST_AUTHORS="奇安信,绿盟科技,安天集团"
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECLENS_URL` | Yes | - | SecLens server URL |
| `SECLENS_TOKEN` | Yes | - | API token for authentication |
| `DOONSEC_FEED_URL` | No | doonsec RSS URL | Override the RSS feed URL |
| `DOONSEC_WHITELIST_ENABLED` | No | false | Enable author whitelist filtering |
| `DOONSEC_WHITELIST_AUTHORS` | No | - | Comma-separated list of allowed authors |
