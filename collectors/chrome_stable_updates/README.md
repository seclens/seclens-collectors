# Chrome Stable Updates Collector

Fetches Chrome stable channel update posts from the [Chrome Releases blog](https://chromereleases.googleblog.com/).

## Source

- **Publisher:** Google
- **Feed URL:** https://chromereleases.googleblog.com/search/label/Stable%20updates
- **Content Type:** Browser stable channel release notes
- **Language:** English
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
0 */4 * * * cd /path/to/chrome_stable_updates && python collector.py >> /var/log/chrome-stable-collector.log 2>&1
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECLENS_URL` | Yes | - | SecLens server URL |
| `SECLENS_TOKEN` | Yes | - | API token for authentication |
| `CHROME_LIST_URL` | No | blog label URL | Override the listing page URL |
