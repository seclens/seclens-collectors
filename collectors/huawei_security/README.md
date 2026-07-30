# Huawei Security Collector

Fetches enterprise security advisories from [Huawei Security Bulletin](https://securitybulletin.huawei.com/enterprise/en/security-advisory).

The collector preserves an API-provided source URL when available. Huawei's
current list API usually returns `allPath: null`, so it derives the canonical
advisory detail URL from `sasnNo`. When a cursor exists, it follows subsequent
API pages until the previous cursor is found, preventing missed advisories when
more than one page is published between scheduled runs.

## Source

- **Publisher:** Huawei
- **API URL:** https://securitybulletin.huawei.com/vdmsapi/services/vdmsapi/rest/v1/enterprise/advisories
- **Content Type:** Security advisories, CVE bulletins
- **Language:** English
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
0 */6 * * * cd /path/to/huawei_security && python collector.py >> /var/log/huawei-security-collector.log 2>&1
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECLENS_URL` | Yes | - | SecLens server URL |
| `SECLENS_TOKEN` | Yes | - | API token for authentication |
