# Amazon Linux 2023 Security Bulletins Collector

Fetches security bulletins from the [Amazon Linux 2023 ALAS RSS feed](https://alas.aws.amazon.com/AL2023/alas.rss).

## Source

- **Publisher:** Amazon Web Services
- **Feed URL:** https://alas.aws.amazon.com/AL2023/alas.rss
- **Content Type:** ALAS security advisories for Amazon Linux 2023
- **Language:** English
- **Update Frequency:** As new advisories are published

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
0 * * * * cd /path/to/amazon_linux_al2023 && python collector.py >> /var/log/al2023-collector.log 2>&1
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECLENS_URL` | Yes | - | SecLens server URL |
| `SECLENS_TOKEN` | Yes | - | API token for authentication |
| `ALAS_AL2023_FEED_URL` | No | https://alas.aws.amazon.com/AL2023/alas.rss | Override the RSS feed URL |
