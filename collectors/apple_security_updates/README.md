# Apple Security Updates Collector

Fetches Apple security release information from the [Apple Support advisory list](https://support.apple.com/en-us/100100).

## Source

- **Publisher:** Apple
- **Feed URL:** https://support.apple.com/en-us/100100
- **Content Type:** Security advisories and software updates
- **Language:** English
- **Update Frequency:** Several times per month

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

Recommended: every 4 hours.

```bash
# crontab
0 */4 * * * cd /path/to/apple_security_updates && python collector.py >> /var/log/apple-security-collector.log 2>&1
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECLENS_URL` | Yes | - | SecLens server URL |
| `SECLENS_TOKEN` | Yes | - | API token for authentication |
| `APPLE_LIST_URL` | No | Apple support URL | Override the listing page URL |
