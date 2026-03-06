# NVIDIA Security Bulletin Collector

Fetches security bulletins from the [NVIDIA Product Security](https://www.nvidia.com/en-us/security/) portal.

## Source

- **Publisher:** NVIDIA
- **API URL:** https://www.nvidia.com/content/dam/en-zz/Solutions/product-security/product-security.json
- **Content Type:** Security bulletins with CVE references and severity ratings
- **Language:** English
- **Update Frequency:** As bulletins are published

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

Recommended: every 1 hour.

```bash
# crontab
0 * * * * cd /path/to/nvidia_security_bulletin && python collector.py >> /var/log/nvidia-collector.log 2>&1
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECLENS_URL` | Yes | - | SecLens server URL |
| `SECLENS_TOKEN` | Yes | - | API token for authentication |
| `NVIDIA_API_URL` | No | NVIDIA product-security.json URL | Override the API URL |
