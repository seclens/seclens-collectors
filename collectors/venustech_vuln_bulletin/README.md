# Venustech Vulnerability Bulletin Collector

Collects security bulletins from Venustech announcement page.

## Env
- `SECLENS_URL`
- `SECLENS_TOKEN`
- `VENUSTECH_AQTG_URL` (optional)
- `VENUSTECH_AQTG_LIMIT` (optional)

## Run
```bash
pip install -r collectors/venustech_vuln_bulletin/requirements.txt
python collectors/venustech_vuln_bulletin/collector.py
```
