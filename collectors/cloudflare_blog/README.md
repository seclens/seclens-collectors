# Cloudflare Blog Collector

Collects technical blog posts from the [Cloudflare Blog](https://blog.cloudflare.com/) homepage. Scrapes the listing page for recent posts, then fetches each post's detail page to extract full content, metadata, tags, and authors.

## Usage

```bash
export SECLENS_URL="https://your-seclens-server.com"
export SECLENS_TOKEN="your-api-token"
python collector.py
```

Proxy support is available via standard environment variables (`HTTPS_PROXY`, `HTTP_PROXY`).

## Schedule

Recommended: every 90 minutes (5400 seconds).

## Dependencies

```bash
pip install -r requirements.txt
```
