# Chaitin VulDB Collector

Collects latest vulnerabilities from Chaitin Stack API and sends them to SecLens.

## Env
- `SECLENS_URL`
- `SECLENS_TOKEN`
- `CHAITIN_VULDB_API_URL` (optional)

## Run
```bash
pip install -r collectors/chaitin_vuldb/requirements.txt
python collectors/chaitin_vuldb/collector.py
```
