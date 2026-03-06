# Alibaba Cloud Linux Security Advisory Collector

Fetches security advisories (errata) from the [Alibaba Cloud Linux Advisory System (ALAS)](https://alas.aliyuncs.com/).

## Source

- **Publisher:** Alibaba Cloud
- **Feed URL:** https://alas.aliyuncs.com/api/rss/v1/errata/rss.xml
- **Content Type:** Security advisories with CVE references, affected products, and solutions
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
0 */2 * * * cd /path/to/alibaba_cloud_linux_advisory && python collector.py >> /var/log/alas-advisory-collector.log 2>&1
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECLENS_URL` | Yes | - | SecLens server URL |
| `SECLENS_TOKEN` | Yes | - | API token for authentication |
| `ALAS_ADVISORY_FEED_URL` | No | ALAS errata RSS URL | Override the RSS feed URL |
