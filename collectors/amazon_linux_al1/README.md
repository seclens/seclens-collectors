# Amazon Linux 1 Security Bulletins Collector

Fetches security bulletins from the [Amazon Linux 1 ALAS RSS feed](https://alas.aws.amazon.com/alas.rss).

## Source

- **Publisher:** Amazon Web Services
- **Feed URL:** https://alas.aws.amazon.com/alas.rss
- **Content Type:** ALAS security advisories for Amazon Linux 1 (EOL)
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
0 * * * * cd /path/to/amazon_linux_al1 && python collector.py >> /var/log/al1-collector.log 2>&1
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECLENS_URL` | Yes | - | SecLens server URL |
| `SECLENS_TOKEN` | Yes | - | API token for authentication |
| `ALAS_AL1_FEED_URL` | No | https://alas.aws.amazon.com/alas.rss | Override the RSS feed URL |
