# Usage Examples

## Python (requests)

```python
import requests

SECLENS_URL = "https://your-seclens-server.com"
SECLENS_TOKEN = "slct_your_token_here"

bulletins = [
    {
        "source": {
            "source_slug": "my_custom_source",
            "external_id": "CVE-2025-12345",
            "origin_url": "https://example.com/advisory/CVE-2025-12345",
        },
        "content": {
            "title": "Critical RCE in Example Software",
            "summary": "A remote code execution vulnerability was found...",
            "body_text": "Full description of the vulnerability...",
            "published_at": "2025-06-01T12:00:00Z",
            "language": "en",
        },
        "severity": "critical",
        "labels": ["cve", "rce"],
        "topics": ["vulnerability"],
    }
]

resp = requests.post(
    f"{SECLENS_URL}/v1/ingest/bulletins",
    json=bulletins,
    headers={
        "Authorization": f"Bearer {SECLENS_TOKEN}",
        "Content-Type": "application/json",
    },
    timeout=30,
)
resp.raise_for_status()
print(resp.json())  # {"accepted": 1, "duplicates": 0}
```

## curl

```bash
curl -X POST "https://your-seclens-server.com/v1/ingest/bulletins" \
  -H "Authorization: Bearer slct_your_token_here" \
  -H "Content-Type: application/json" \
  -d '[{
    "source": {
      "source_slug": "my_custom_source",
      "external_id": "advisory-001",
      "origin_url": "https://example.com/advisory/001"
    },
    "content": {
      "title": "Security Advisory 001",
      "summary": "Description of the issue",
      "published_at": "2025-06-01T12:00:00Z",
      "language": "en"
    },
    "severity": "high",
    "labels": ["security"],
    "topics": ["advisory"]
  }]'
```

## Go

```go
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
    "os"
    "time"
)

func main() {
    url := os.Getenv("SECLENS_URL") + "/v1/ingest/bulletins"
    token := os.Getenv("SECLENS_TOKEN")

    bulletins := []map[string]interface{}{
        {
            "source": map[string]interface{}{
                "source_slug": "my_go_collector",
                "external_id": "GO-2025-001",
                "origin_url":  "https://example.com/advisory/001",
            },
            "content": map[string]interface{}{
                "title":        "Security Advisory",
                "summary":      "Description",
                "published_at": time.Now().UTC().Format(time.RFC3339),
                "language":     "en",
            },
            "severity": "medium",
            "labels":   []string{"security"},
            "topics":   []string{"advisory"},
        },
    }

    body, _ := json.Marshal(bulletins)
    req, _ := http.NewRequest("POST", url, bytes.NewReader(body))
    req.Header.Set("Authorization", "Bearer "+token)
    req.Header.Set("Content-Type", "application/json")

    client := &http.Client{Timeout: 30 * time.Second}
    resp, err := client.Do(req)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error: %v\n", err)
        os.Exit(1)
    }
    defer resp.Body.Close()

    var result map[string]interface{}
    json.NewDecoder(resp.Body).Decode(&result)
    fmt.Printf("Status: %d, Result: %v\n", resp.StatusCode, result)
}
```

## Bash (with jq)

```bash
#!/bin/bash
set -euo pipefail

SECLENS_URL="${SECLENS_URL:?Required}"
SECLENS_TOKEN="${SECLENS_TOKEN:?Required}"

# Fetch from some source
DATA=$(curl -s "https://example.com/api/advisories")

# Transform with jq and push
echo "$DATA" | jq '[.[] | {
  source: {
    source_slug: "bash_collector",
    external_id: .id,
    origin_url: .url
  },
  content: {
    title: .title,
    summary: .description,
    published_at: .date,
    language: "en"
  },
  severity: .severity,
  labels: [.tags[]],
  topics: ["advisory"]
}]' | curl -s -X POST "${SECLENS_URL}/v1/ingest/bulletins" \
  -H "Authorization: Bearer ${SECLENS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d @-
```

## Batch Submission

The API accepts up to **200 bulletins per request**. For larger datasets, split into batches:

```python
import requests

MAX_BATCH = 200

def push_batched(bulletins, url, token):
    total = {"accepted": 0, "duplicates": 0}
    for i in range(0, len(bulletins), MAX_BATCH):
        batch = bulletins[i:i + MAX_BATCH]
        resp = requests.post(
            f"{url}/v1/ingest/bulletins",
            json=batch,
            headers={"Authorization": f"Bearer {token}"},
            timeout=30,
        )
        resp.raise_for_status()
        result = resp.json()
        total["accepted"] += result["accepted"]
        total["duplicates"] += result["duplicates"]
    return total
```
