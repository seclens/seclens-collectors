# GitHub Advisory Database Collector

Standalone collector that fetches security advisories from the GitHub Advisory Database API and pushes them to a SecLens server.

Covers CVEs and GitHub-originated security advisories from the open source ecosystem, including package vulnerability details, CVSS scores, CWE classifications, and patch information.

## Usage

```bash
export SECLENS_URL="https://your-seclens-server.com"
export SECLENS_TOKEN="your-api-token"
python collector.py
```

Proxies can be configured via standard environment variables (`HTTPS_PROXY`, `HTTP_PROXY`).

## Schedule

Recommended: every 1 hour (3600s).
