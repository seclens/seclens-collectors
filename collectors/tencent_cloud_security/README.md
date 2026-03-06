# Tencent Cloud Security Collector

Fetches security announcements from [Tencent Cloud](https://cloud.tencent.com/announce/?categorys=21).

## Source

- **Publisher:** Tencent Cloud
- **URL:** https://cloud.tencent.com/announce/?categorys=21
- **Content Type:** Cloud security announcements, vulnerability notices
- **Language:** Chinese (zh)
- **Update Frequency:** As announced

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
0 */4 * * * cd /path/to/tencent_cloud_security && python collector.py >> /var/log/tencent-cloud-collector.log 2>&1
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECLENS_URL` | Yes | - | SecLens server URL |
| `SECLENS_TOKEN` | Yes | - | API token for authentication |
