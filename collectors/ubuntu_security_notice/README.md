# Ubuntu Security Notice Collector

Fetches Ubuntu USN advisories from the [Ubuntu Security Notices](https://ubuntu.com/security/notices) RSS feed with JSON detail enrichment.

## Source

- **Publisher:** Canonical
- **Feed URL:** https://ubuntu.com/security/notices/rss.xml
- **Content Type:** Official security notices (USN), CVE advisories
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
0 * * * * cd /path/to/ubuntu_security_notice && python collector.py >> /var/log/ubuntu-collector.log 2>&1
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECLENS_URL` | Yes | - | SecLens server URL |
| `SECLENS_TOKEN` | Yes | - | API token for authentication |
| `UBUNTU_FEED_URL` | No | Ubuntu RSS URL | Override the RSS feed URL |
