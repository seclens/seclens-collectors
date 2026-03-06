# MIIT CNVDB Collector

Collects vulnerability risk alerts from the [MIIT CNVDB](https://cnvdb.org.cn/) platform (Ministry of Industry and Information Technology).

## Source

- **Publisher:** MIIT Network Security Threat and Vulnerability Information Sharing Platform
- **Homepage:** https://cnvdb.org.cn/
- **Content Type:** Vulnerability warnings and policy bulletins
- **Language:** Chinese (zh)
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
0 * * * * cd /path/to/cnvdb && python collector.py >> /var/log/cnvdb.log 2>&1
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECLENS_URL` | Yes | - | SecLens server URL |
| `SECLENS_TOKEN` | Yes | - | API token for authentication |
