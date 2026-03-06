# Alibaba Cloud Linux CVE Collector

Fetches CVE vulnerability notifications from the [Alibaba Cloud Linux Advisory System (ALAS)](https://alas.aliyuncs.com/).

## Source

- **Publisher:** Alibaba Cloud
- **Feed URL:** https://alas.aliyuncs.com/api/rss/v1/cves/rss.xml
- **Content Type:** CVE vulnerability notifications
- **Language:** English
- **Update Frequency:** Updated regularly

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
0 */2 * * * cd /path/to/alibaba_cloud_linux_cve && python collector.py >> /var/log/alas-cve-collector.log 2>&1
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECLENS_URL` | Yes | - | SecLens server URL |
| `SECLENS_TOKEN` | Yes | - | API token for authentication |
| `ALAS_CVE_FEED_URL` | No | ALAS CVE RSS URL | Override the RSS feed URL |
