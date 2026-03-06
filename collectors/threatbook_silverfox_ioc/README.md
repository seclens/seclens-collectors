# ThreatBook SilverFox IOC Collector

Fetches hot IOC intelligence for the [SilverFox](https://s.threatbook.com/cybercrime/silverfox) malware family from ThreatBook, including IPs, domains, SHA256 hashes, and dropped file paths.

## Source

- **Publisher:** ThreatBook
- **Homepage:** https://s.threatbook.com/cybercrime/silverfox
- **Content Type:** IOC intelligence (IP, domain, hash, file path)
- **Language:** Chinese (zh-CN)
- **Update Frequency:** Hourly recommended

## Setup

```bash
pip install -r requirements.txt

export SECLENS_URL="https://your-seclens-server.com"
export SECLENS_TOKEN="your-api-token"

# Optional: enable SHA256 -> MD5/SHA1 enrichment
export THREATBOOK_CN_API_KEY="your-threatbook-api-key"
```

## Run

```bash
python collector.py
```

## Schedule

Recommended: every 1 hour.

```bash
# crontab
0 * * * * cd /path/to/threatbook_silverfox_ioc && python collector.py >> /var/log/silverfox-ioc.log 2>&1
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECLENS_URL` | Yes | - | SecLens server URL |
| `SECLENS_TOKEN` | Yes | - | API token for authentication |
| `THREATBOOK_CN_API_KEY` | No | - | ThreatBook API key for hash enrichment |
