# Red Hat Security Advisory Collector

Fetches security advisories from the [Red Hat Security Advisories](https://access.redhat.com/security/security-updates/security-advisories) Hydra API with article body extraction.

## Source

- **Publisher:** Red Hat
- **API URL:** https://access.redhat.com/hydra/rest/search/kcs
- **Content Type:** Official security advisories (RHSA), errata
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
0 * * * * cd /path/to/redhat_advisory && python collector.py >> /var/log/redhat-collector.log 2>&1
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECLENS_URL` | Yes | - | SecLens server URL |
| `SECLENS_TOKEN` | Yes | - | API token for authentication |
