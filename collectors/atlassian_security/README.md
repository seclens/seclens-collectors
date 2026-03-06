# Atlassian Security Collector

Fetches security advisories and CVE information from [Atlassian's vulnerability transparency API](https://www.atlassian.com/trust/security/advisories).

## Source

- **Publisher:** Atlassian
- **API URL:** https://www.atlassian.com/gateway/api/vuln-transparency/v1/products
- **Content Type:** CVE advisories, security vulnerabilities
- **Language:** English
- **Update Frequency:** Daily

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

Recommended: every 6 hours.

```bash
# crontab
0 */6 * * * cd /path/to/atlassian_security && python collector.py >> /var/log/atlassian-collector.log 2>&1
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECLENS_URL` | Yes | - | SecLens server URL |
| `SECLENS_TOKEN` | Yes | - | API token for authentication |
