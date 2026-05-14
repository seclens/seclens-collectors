# arXiv cs.CR Collector

Fetches recent papers from [arXiv](https://arxiv.org/) category **Computer Science > Cryptography and Security** (`cs.CR`) and pushes them to a SecLens server.

## Source

- **Publisher:** arXiv
- **Category:** `cs.CR`
- **RSS:** `https://rss.arxiv.org/rss/cs.CR`
- **API:** `https://export.arxiv.org/api/query?search_query=cat:cs.CR`
- **Content Type:** Security research papers
- **Language:** English

## API Key

No API key is required. arXiv RSS and API are public. Keep polling low-frequency and identify requests with a User-Agent.

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

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECLENS_URL` | Yes | - | SecLens server URL |
| `SECLENS_TOKEN` | Yes | - | API token for authentication |
| `ARXIV_API_URL` | No | `https://export.arxiv.org/api/query` | arXiv API endpoint |
| `ARXIV_SEARCH_QUERY` | No | `cat:cs.CR` | arXiv API search query |
| `ARXIV_MAX_RESULTS` | No | `50` | Number of recent entries to fetch |
| `ARXIV_SORT_BY` | No | `submittedDate` | arXiv sort field |
| `ARXIV_SORT_ORDER` | No | `descending` | arXiv sort order |
| `ARXIV_REQUEST_DELAY_SECONDS` | No | `3` | Polite delay after API fetch |

## Schedule

Recommended: once per day. The arXiv RSS category feed is updated daily, and the API documentation recommends caching query results rather than polling the same query frequently.
