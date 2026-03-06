# Adobe Security Collector

Fetches security advisories from the [Adobe Product Security Incident Response Team (PSIRT)](https://helpx.adobe.com/security.html) portal.

## Source

- **Publisher:** Adobe
- **List URL:** https://helpx.adobe.com/security/Home.html
- **Content Type:** Security advisories with affected products, solutions, and CVE references
- **Language:** English
- **Update Frequency:** As advisories are published

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

Recommended: every 8 hours.

```bash
# crontab
0 */8 * * * cd /path/to/adobe_security && python collector.py >> /var/log/adobe-collector.log 2>&1
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECLENS_URL` | Yes | - | SecLens server URL |
| `SECLENS_TOKEN` | Yes | - | API token for authentication |
| `ADOBE_LIST_URL` | No | Adobe Security Home URL | Override the listing page URL |
