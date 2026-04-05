# CISA KEV Catalog Collector

Collects CISA Known Exploited Vulnerabilities via JSON feed.

## Env
- `SECLENS_URL`
- `SECLENS_TOKEN`
- `CISA_KEV_BATCH_SIZE` (optional, default `50`)
- `CISA_KEV_JSON_FEED_URL` (optional)
- `CISA_KEV_JSON_FEED_FALLBACK_URL` (optional, 用于主源被 403 时回退)
- `CISA_KEV_CATALOG_URL` (optional)

## Run
```bash
pip install -r collectors/cisa_kev_catalog/requirements.txt
python collectors/cisa_kev_catalog/collector.py
```
