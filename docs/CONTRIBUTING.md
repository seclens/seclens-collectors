# Contributing to SecLens Collectors

Thank you for your interest in contributing! SecLens Collectors is a community-driven project that aggregates security intelligence from various sources.

## How to Contribute a New Collector

### 1. Choose a Source

Pick a security information source that is not yet covered. Good candidates include:
- Vendor security advisories (e.g., Cisco PSIRT, VMware)
- Vulnerability databases (e.g., NVD, CERT/CC)
- Security blogs and news sites
- CERT/CSIRT bulletins
- Open-source project security pages

### 2. Create the Collector

Create a new directory under `collectors/`:

```
collectors/your_source_name/
  collector.py            # Main collector script
  manifest.json           # Source metadata for server-side registry sync
  requirements.txt        # Python dependencies
  config.example.yaml     # Configuration template
  README.md               # Source description and usage
  test_collector.py       # Tests (optional but appreciated)
```

### 3. Implement collector.py

Your collector should:

1. **Fetch** data from the source (HTTP, RSS, API, etc.)
2. **Normalize** it into the SecLens bulletin JSON format
3. **Push** it to the SecLens server via HTTP POST

Minimal example:

```python
"""My Source collector."""
import os
import sys
from datetime import datetime, timezone
import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from shared.manifest import load_manifest_for_slug

SECLENS_URL = os.environ.get("SECLENS_URL", "https://seclens.example.com")
SECLENS_TOKEN = os.environ["SECLENS_TOKEN"]
SOURCE_SLUG = "your_source_name"
manifest, manifest_hash, manifest_version = load_manifest_for_slug(SOURCE_SLUG)

def fetch():
    """Fetch data from source. Return raw items."""
    resp = requests.get("https://source-url.com/api/advisories", timeout=30)
    resp.raise_for_status()
    return resp.json()

def normalize(item):
    """Convert raw item to SecLens bulletin format."""
    return {
        "source": {
            "source_slug": "your_source_name",
            "external_id": item["id"],
            "origin_url": item.get("url"),
            "manifest": manifest,
            "manifest_hash": manifest_hash,
            "manifest_version": manifest_version,
        },
        "content": {
            "title": item["title"],
            "summary": item.get("description"),
            "published_at": item.get("published"),
            "language": "en",
        },
        "severity": item.get("severity"),
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "labels": [],
        "topics": ["advisory"],
    }

def push(bulletins):
    """Submit bulletins to SecLens server."""
    resp = requests.post(
        f"{SECLENS_URL}/v1/ingest/bulletins",
        json=bulletins,
        headers={"Authorization": f"Bearer {SECLENS_TOKEN}"},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()

if __name__ == "__main__":
    raw_items = fetch()
    bulletins = [normalize(item) for item in raw_items]
    if bulletins:
        result = push(bulletins)
        print(f"Pushed {len(bulletins)} items: {result}")
    else:
        print("No new items found")
```

`manifest`, `manifest_hash`, and `manifest_version` are strongly recommended so the server can auto-sync source metadata and version history.

### 4. Configuration

Use `config.example.yaml` to document all configurable values:

```yaml
# SecLens server connection
seclens_url: "https://seclens.example.com"
seclens_token: ""  # Get this from your SecLens admin

# Source-specific settings
feed_url: "https://source-url.com/rss"
fetch_limit: 50
```

Read config from environment variables (preferred) or a local config file.

### 5. Write a README

Each collector should have a README explaining:
- What source it collects from
- How to configure and run it
- Any special requirements (e.g., API keys, browser)
- Recommended schedule (how often to run)

### 6. Submit a Pull Request

- Fork this repository
- Create a branch: `git checkout -b add-your-source-name`
- Commit your changes
- Push and create a PR

## Guidelines

### Do

- Keep collectors simple and self-contained
- Use `external_id` for deduplication (article URL, advisory ID, etc.)
- Handle errors gracefully (network timeouts, malformed data)
- Respect source rate limits and robots.txt
- Include a user-agent string identifying the collector
- Log useful information to stdout/stderr

### Don't

- Don't import from the SecLens server codebase (`from app.*`)
- Don't hardcode credentials (use environment variables)
- Don't submit duplicates intentionally (the server deduplicates, but be efficient)
- Don't scrape sources that explicitly prohibit it
- Don't submit empty or garbage data

### Code Style

- Python collectors: follow PEP 8, use type hints where helpful
- Keep dependencies minimal (most collectors only need `requests`)
- Use `if __name__ == "__main__":` for the entry point

## Getting a Token

To test your collector against a SecLens server, you need an API token. Contact the server administrator or set up a local SecLens instance for development.

## Centralized Scheduling

This repository supports a centralized runner (`run_collectors.py`) so operators can enable/disable collectors through one profile file.

- Profile template: `profiles/default.example.json`
- Create working profile: `cp profiles/default.example.json profiles/default.json`
- Dry run: `python run_collectors.py --profile profiles/default.json --dry-run`
- Run selected collectors: `python run_collectors.py --profile profiles/default.json`

This avoids maintaining many independent cron entries.

## Questions?

Open an issue on this repository if you have questions about contributing.
