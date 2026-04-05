# TC260 Consultations Collector

Scrapes consultation announcements from [TC260](https://www.tc260.org.cn/portal/suggestion) (National Information Security Standardization Technical Committee).

## Source

- **Publisher:** TC260 (全国信息安全标准化技术委员会)
- **URL:** https://www.tc260.org.cn/portal/suggestion
- **Content Type:** Standard consultation drafts and announcements
- **Language:** Chinese (zh)
- **Update Frequency:** Several times per month

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

Recommended: every 4 hours.

```bash
# crontab
0 */4 * * * cd /path/to/tc260_consultations && python collector.py >> /var/log/tc260-collector.log 2>&1
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECLENS_URL` | Yes | - | SecLens server URL |
| `SECLENS_TOKEN` | Yes | - | API token for authentication |
| `TC260_VERIFY_SSL` | No | `true` | Set to `false` to ignore upstream TLS certificate validation failures |

The collector also parses detail-page attachments and stores attachment names and download URLs in bulletin metadata.
