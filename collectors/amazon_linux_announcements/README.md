# Amazon Linux Security Announcements Collector

Fetches security announcements from the [Amazon Linux announcements page](https://alas.aws.amazon.com/announcements.html) by parsing the HTML table.

## Source

- **Publisher:** Amazon Web Services
- **Page URL:** https://alas.aws.amazon.com/announcements.html
- **Content Type:** Security announcements for all Amazon Linux distributions
- **Language:** English
- **Update Frequency:** As new announcements are published

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
0 */2 * * * cd /path/to/amazon_linux_announcements && python collector.py >> /var/log/al-announcements-collector.log 2>&1
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECLENS_URL` | Yes | - | SecLens server URL |
| `SECLENS_TOKEN` | Yes | - | API token for authentication |
| `ALAS_ANNOUNCEMENTS_URL` | No | https://alas.aws.amazon.com/announcements.html | Override the announcements page URL |
