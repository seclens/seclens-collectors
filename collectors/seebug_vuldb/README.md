# Seebug VulDB Collector

Collects latest vulnerability entries from Seebug VulDB list and detail pages.

## Env
- `SECLENS_URL`
- `SECLENS_TOKEN`
- `SEEBUG_VULDB_LIST_URL` (optional)
- `SEEBUG_VULDB_LIMIT` (optional)

## Run
```bash
pip install -r collectors/seebug_vuldb/requirements.txt
python collectors/seebug_vuldb/collector.py
```
