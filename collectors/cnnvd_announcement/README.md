# CNNVD Announcement Collector

Fetches vulnerability announcements from the [China National Vulnerability Database (CNNVD)](https://www.cnnvd.org.cn/home/warn) warning section.

## Source

- **Publisher:** National Information Security Vulnerability Database (CNNVD)
- **Homepage:** https://www.cnnvd.org.cn
- **Content Type:** Vulnerability announcements and warnings
- **Language:** Chinese (zh-CN)
- **Update Frequency:** Multiple times daily

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
0 * * * * cd /path/to/cnnvd_announcement && python collector.py >> /var/log/cnnvd-announce.log 2>&1
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECLENS_URL` | Yes | - | SecLens server URL |
| `SECLENS_TOKEN` | Yes | - | API token for authentication |
