# ThreatBook SilverFox Intelligence Collector

Fetches threat intelligence from [ThreatBook SilverFox](https://s.threatbook.com/cybercrime/silverfox) platform, including APT events, phishing, data theft, and ransomware analysis.

## Source

- **Publisher:** ThreatBook
- **Homepage:** https://s.threatbook.com/cybercrime/silverfox
- **Content Type:** Threat intelligence, APT tracking, attack analysis
- **Language:** Chinese (zh-CN)
- **Update Frequency:** Varies, check every 2 hours recommended

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

Recommended: every 2 hours.

```bash
# crontab
0 */2 * * * cd /path/to/threatbook_silverfox && python collector.py >> /var/log/threatbook-silverfox.log 2>&1
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECLENS_URL` | Yes | - | SecLens server URL |
| `SECLENS_TOKEN` | Yes | - | API token for authentication |
