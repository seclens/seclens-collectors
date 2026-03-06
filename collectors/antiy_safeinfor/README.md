# Antiy SafeInfo Collector

Fetches daily security briefings from [Antiy SafeInfo](https://www.antiycloud.com/#/antiy/safeinfor).

## Source

- **Publisher:** Antiy (安天)
- **API:** https://www.antiycloud.com/api/dailyDetail/{date}
- **Content Type:** Daily security announcements and threat intelligence
- **Language:** Chinese (zh-CN)
- **Update Frequency:** Daily

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
0 */4 * * * cd /path/to/antiy_safeinfor && python collector.py >> /var/log/antiy-collector.log 2>&1
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECLENS_URL` | Yes | - | SecLens server URL |
| `SECLENS_TOKEN` | Yes | - | API token for authentication |
| `ANTIY_DAILY_TIME` | No | today (YYYYMMDD) | Override the date to fetch |
