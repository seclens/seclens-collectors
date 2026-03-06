# AWS Security Bulletins Collector

Fetches security bulletins from the [AWS Security Bulletins](https://aws.amazon.com/security/security-bulletins/) RSS feed.

## Source

- **Publisher:** Amazon Web Services
- **Feed URL:** https://aws.amazon.com/security/security-bulletins/rss/feed/
- **Content Type:** Official security bulletins, vulnerability advisories
- **Language:** English
- **Update Frequency:** As published

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
0 * * * * cd /path/to/aws_security_bulletins && python collector.py >> /var/log/aws-collector.log 2>&1
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECLENS_URL` | Yes | - | SecLens server URL |
| `SECLENS_TOKEN` | Yes | - | API token for authentication |
| `AWS_FEED_URL` | No | AWS RSS URL | Override the RSS feed URL |
