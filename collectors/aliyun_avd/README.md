# Aliyun AVD Collector

Fetches vulnerability information from [Aliyun AVD (Vulnerability Database)](https://avd.aliyun.com/) using Selenium for WAF bypass.

## Source

- **Publisher:** Alibaba Cloud (Aliyun)
- **URL:** https://avd.aliyun.com
- **Content Type:** CVE advisories, vulnerability database entries
- **Language:** Chinese (zh)
- **Update Frequency:** Multiple times daily

## Setup

```bash
pip install -r requirements.txt

export SECLENS_URL="https://your-seclens-server.com"
export SECLENS_TOKEN="your-api-token"
```

### Chrome/Selenium Requirements

This collector requires Chrome and ChromeDriver. You can either:

1. Let `webdriver-manager` auto-download ChromeDriver (default)
2. Set paths manually via environment variables:
   - `CHROME_BINARY_PATH` - Path to Chrome binary
   - `CHROME_DRIVER_PATH` - Path to ChromeDriver

## Run

```bash
python collector.py
```

## Schedule

Recommended: every 4 hours.

```bash
# crontab
0 */4 * * * cd /path/to/aliyun_avd && python collector.py >> /var/log/aliyun-avd-collector.log 2>&1
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECLENS_URL` | Yes | - | SecLens server URL |
| `SECLENS_TOKEN` | Yes | - | API token for authentication |
| `CHROME_BINARY_PATH` | No | auto | Path to Chrome binary |
| `CHROME_DRIVER_PATH` | No | auto | Path to ChromeDriver |
