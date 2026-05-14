# Ransomware.live Recent Victims Collector

Fetches recently discovered ransomware victim disclosures from [Ransomware.live](https://www.ransomware.live/) and pushes them to a SecLens server.

## Source

- **Publisher:** Ransomware.live
- **API:** `https://api-pro.ransomware.live/victims/recent?order=discovered`
- **Content Type:** Threat intelligence, ransomware victim disclosures
- **Language:** English
- **Update Frequency:** Frequently updated, check every 1 hour recommended

## Setup

```bash
pip install -r requirements.txt

export SECLENS_URL="https://your-seclens-server.com"
export SECLENS_TOKEN="your-api-token"
export RANSOMWARE_LIVE_API_KEY="your-ransomware-live-api-key"
```

## Run

```bash
python collector.py
```

## Schedule

Recommended: every 1 hour.

```bash
# crontab
0 * * * * cd /path/to/ransomware_live && python collector.py >> /var/log/ransomware-live.log 2>&1
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECLENS_URL` | Yes | - | SecLens server URL |
| `SECLENS_TOKEN` | Yes | - | API token for authentication |
| `RANSOMWARE_LIVE_API_KEY` | Yes | - | API key for `api-pro.ransomware.live` |
| `RANSOMWARE_LIVE_API_URL` | No | Recent victims endpoint | Override the source API URL |
| `RANSOMWARE_LIVE_BATCH_SIZE` | No | `50` | Batch size when pushing to SecLens |

## Notes

- The collector tracks the latest processed victim ID in `.cursor` to avoid re-pushing already seen items.
- The API key is intentionally read from environment variables and is not hardcoded in the repository.
