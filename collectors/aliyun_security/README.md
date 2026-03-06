# Aliyun Security Bulletin Collector

Standalone collector that fetches security bulletins from the Aliyun public bulletin API and pushes them to a SecLens server.

## Data Source

- **API**: `https://t.aliyun.com/abs/bulletin/bulletinQuery`
- **Content**: Official Aliyun cloud security advisories, incident notices, and maintenance bulletins

## Usage

```bash
export SECLENS_URL="https://your-seclens-server.com"
export SECLENS_TOKEN="your-api-token"
pip install -r requirements.txt
python collector.py
```

## Proxy Support

Set standard environment variables to route outbound requests through a proxy:

```bash
export HTTPS_PROXY="http://proxy:8080"
```

## Schedule Recommendation

Run every **1 hour** (3600 seconds). Aliyun security bulletins are typically published a few times per week, so hourly polling provides timely coverage without excessive API calls.
