# HackerOne Blog Collector

Fetches security blog posts from the [HackerOne](https://www.hackerone.com/blog) official blog.

## Source

- **Publisher:** HackerOne
- **Feed URL:** https://www.hackerone.com/blog
- **Content Type:** Security blog posts, hacker community insights
- **Language:** English
- **Update Frequency:** Several times per week

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

Recommended: every 6 hours.

```bash
# crontab
0 */6 * * * cd /path/to/hackerone_blog && python collector.py >> /var/log/hackerone-blog-collector.log 2>&1
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECLENS_URL` | Yes | - | SecLens server URL |
| `SECLENS_TOKEN` | Yes | - | API token for authentication |
| `HACKERONE_LIST_URL` | No | https://www.hackerone.com/blog | Override the blog listing URL |
