# Oracle Security Alert Collector

Fetches security alerts from the [Oracle Security Alerts](https://www.oracle.com/security-alerts/) RSS feed.

## Source

- **Publisher:** Oracle
- **Feed URL:** https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/rss-otn-sec.xml
- **Content Type:** Security alerts, critical patch updates
- **Language:** English
- **Update Frequency:** Quarterly (Critical Patch Updates) plus ad-hoc alerts

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
0 * * * * cd /path/to/oracle_security_alert && python collector.py >> /var/log/oracle-security-collector.log 2>&1
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECLENS_URL` | Yes | - | SecLens server URL |
| `SECLENS_TOKEN` | Yes | - | API token for authentication |
| `ORACLE_FEED_URL` | No | Oracle RSS URL | Override the RSS feed URL |

## Notes

This collector uses a cursor file (`.cursor`) to track the last processed timestamp and avoid re-processing entries on subsequent runs.
