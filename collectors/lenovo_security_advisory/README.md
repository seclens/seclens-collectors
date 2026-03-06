# Lenovo Security Advisory Collector

Fetches product security advisories from [Lenovo Support](https://newsupport.lenovo.com.cn/SecurityPolicy.html).

## Source

- **Publisher:** Lenovo
- **API URL:** https://newsupport.lenovo.com.cn/api/SafeNotice/SafeNoticeListInfo
- **Content Type:** Product security advisories, CVE bulletins
- **Language:** Chinese (zh-CN)
- **Update Frequency:** As published

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
0 */6 * * * cd /path/to/lenovo_security_advisory && python collector.py >> /var/log/lenovo-security-collector.log 2>&1
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECLENS_URL` | Yes | - | SecLens server URL |
| `SECLENS_TOKEN` | Yes | - | API token for authentication |
