# LinuxSecurity.com Hybrid Collector

Fetches combined advisories, features, and news from [LinuxSecurity.com](https://linuxsecurity.com/) hybrid RSS feed.

## Source

- **Publisher:** LinuxSecurity.com
- **Feed URL:** https://linuxsecurity.com/linuxsecurity_hybrid.xml
- **Content Type:** Security advisories, features, news
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
0 * * * * cd /path/to/linuxsecurity_hybrid && python collector.py >> /var/log/linuxsecurity-collector.log 2>&1
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECLENS_URL` | Yes | - | SecLens server URL |
| `SECLENS_TOKEN` | Yes | - | API token for authentication |
| `LINUXSECURITY_FEED_URL` | No | linuxsecurity.com URL | Override the RSS feed URL |
