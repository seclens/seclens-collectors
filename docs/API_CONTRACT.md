# SecLens Ingest API Contract

This document defines the data format for submitting security bulletins to a SecLens server.

## Endpoint

```
POST /v1/ingest/bulletins
```

## Authentication

```
Authorization: Bearer <your-api-token>
```

Tokens are issued by the SecLens server administrator. Each token may be restricted to specific `source_slug` values.

## Request

**Content-Type:** `application/json`

**Body:** A JSON array of bulletin objects.

### Bulletin Object Schema

```json
{
  "source": {
    "source_slug": "string (required)",
    "external_id": "string (optional, recommended)",
    "origin_url": "string (optional, valid URL)",
    "manifest": {"object (optional, recommended)"},
    "manifest_hash": "string (optional, recommended)",
    "manifest_version": "string (optional, recommended)"
  },
  "content": {
    "title": "string (required, max 500 chars)",
    "summary": "string (optional)",
    "body_text": "string (optional)",
    "published_at": "string (optional, ISO 8601 datetime)",
    "language": "string (optional, e.g. 'en', 'zh')"
  },
  "severity": "string (optional, e.g. 'Low', 'Medium', 'High', 'Critical')",
  "fetched_at": "string (optional, ISO 8601 datetime, defaults to server receive time)",
  "labels": ["string array (optional)"],
  "topics": ["string array (optional)"],
  "extra": {"object (optional, arbitrary metadata)"},
  "raw": {"object (optional, original data for debugging)"}
}
```

### Field Details

#### source (required)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `source_slug` | string | Yes | Unique identifier for this data source. Must match the slug registered on the server. Examples: `the_hacker_news`, `cnnvd_vulnerability` |
| `external_id` | string | No (recommended) | A stable unique ID from the original source. Used for deduplication together with `source_slug`. Examples: article URL, CVE ID, advisory number |
| `origin_url` | string | No | The canonical URL of the original bulletin |
| `manifest` | object | No (recommended) | Collector manifest metadata (name/version/ui/source info). Sent inline for server-side source registry sync |
| `manifest_hash` | string | No (recommended) | SHA-256 digest of canonicalized `manifest` JSON |
| `manifest_version` | string | No (recommended) | Manifest semantic version (usually same as `manifest.version`) |

#### content (required)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `title` | string | Yes | Bulletin title (max 500 characters) |
| `summary` | string | No | Brief description or abstract |
| `body_text` | string | No | Full article text (plain text or HTML) |
| `published_at` | string | No | Original publication time in ISO 8601 format (e.g. `2026-03-06T08:00:00Z`). If omitted, `fetched_at` is used |
| `language` | string | No | Content language code (ISO 639-1) |

#### Top-level fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `severity` | string | No | Severity level: `Info`, `Low`, `Medium`, `High`, `Critical`, or vendor-specific value |
| `fetched_at` | string | No | When this data was fetched. Defaults to server receive time if omitted |
| `labels` | string[] | No | Free-form tags (e.g. `["category:vulnerability", "os:linux"]`) |
| `topics` | string[] | No | Controlled topics (e.g. `["security-news", "advisory", "patch"]`) |
| `extra` | object | No | Arbitrary metadata (e.g. CVE IDs, affected products, CVSS scores) |
| `raw` | object | No | Original unprocessed data, useful for debugging |

## Response

**Status:** `202 Accepted`

```json
{
  "accepted": 5,
  "duplicates": 2
}
```

| Field | Description |
|-------|-------------|
| `accepted` | Number of new bulletins successfully stored |
| `duplicates` | Number of bulletins skipped (already exist, based on `source_slug` + `external_id`) |

## Error Responses

| Status | Meaning |
|--------|---------|
| `400` | Invalid request body or empty payload |
| `401` | Missing or invalid API token |
| `403` | Token not authorized for the given `source_slug` |
| `422` | Validation error (field format/length issues) |
| `429` | Rate limit exceeded |
| `500` | Server error |

## Deduplication

The server deduplicates based on `(source_slug, external_id)`. If a bulletin with the same combination already exists, it is counted as a duplicate and skipped.

**Important:** Always provide a stable `external_id` to avoid creating duplicate entries.

## Source Registry Sync

When `source.manifest` is present, server will upsert source metadata by `source_slug`.

- If `manifest_hash` is unchanged, server updates last-seen metadata only.
- If `manifest_hash` changes, server promotes/creates a new active source version.
- If manifest fields are omitted, ingest remains backward-compatible.

## Limits

| Limit | Value |
|-------|-------|
| Max bulletins per request | 200 |
| Max title length | 500 characters |
| Max request body size | 10 MB |
| Rate limit | Per-token, configured by admin |

## Examples

### Python

```python
import requests

url = "https://seclens.example.com/v1/ingest/bulletins"
token = "your-api-token"

bulletins = [
    {
        "source": {
            "source_slug": "my_source",
            "external_id": "article-123",
            "origin_url": "https://example.com/article/123",
            "manifest": {
                "name": "My Source Collector",
                "version": "1.0.0",
                "slug": "my_source"
            },
            "manifest_hash": "d34db33f...",
            "manifest_version": "1.0.0",
        },
        "content": {
            "title": "Critical RCE in Example Product",
            "summary": "A remote code execution vulnerability...",
            "published_at": "2026-03-06T08:00:00Z",
            "language": "en",
        },
        "severity": "Critical",
        "labels": ["cve:CVE-2026-1234"],
        "topics": ["advisory"],
    }
]

resp = requests.post(
    url,
    json=bulletins,
    headers={"Authorization": f"Bearer {token}"},
    timeout=30,
)
print(resp.json())  # {"accepted": 1, "duplicates": 0}
```

### curl

```bash
curl -X POST https://seclens.example.com/v1/ingest/bulletins \
  -H "Authorization: Bearer your-api-token" \
  -H "Content-Type: application/json" \
  -d '[{
    "source": {
      "source_slug": "my_source",
      "external_id": "123",
      "manifest": {"name": "My Source Collector", "version": "1.0.0", "slug": "my_source"},
      "manifest_hash": "d34db33f...",
      "manifest_version": "1.0.0"
    },
    "content": {"title": "Test Bulletin", "summary": "Testing..."}
  }]'
```
