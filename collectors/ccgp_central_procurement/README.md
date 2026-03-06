# CCGP Central Procurement Collector

Scrapes central government procurement announcements from [CCGP](https://www.ccgp.gov.cn/cggg/zygg/) (China Government Procurement Network) and filters for security-related items.

## Source

- **Publisher:** China Government Procurement Network (中央政府采购网)
- **URL:** https://www.ccgp.gov.cn/cggg/zygg/
- **Content Type:** Central government procurement announcements (security-filtered)
- **Language:** Chinese (zh)
- **Update Frequency:** Multiple times daily

## Keyword Filtering

Only announcements containing these keywords are collected:
网安, 网络安全, 信息安全, 提示感知, 态势感知, 等级保护, 防火墙

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
0 * * * * cd /path/to/ccgp_central_procurement && python collector.py >> /var/log/ccgp-central-collector.log 2>&1
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECLENS_URL` | Yes | - | SecLens server URL |
| `SECLENS_TOKEN` | Yes | - | API token for authentication |
| `CCGP_LIST_URL` | No | central procurement URL | Override the list page URL |
