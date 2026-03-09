# Seebug Paper RSS Collector

Collects Seebug Paper RSS posts and ingests them into SecLens.

## Env
- `SECLENS_URL`
- `SECLENS_TOKEN`
- `SEEBUG_PAPER_RSS_URL` (optional)
- `SEEBUG_PAPER_FETCH_BODY` (optional, default `false`)

## Note
- 当前默认仅使用 RSS 的标题/摘要入库，不抓取详情页正文。
- 原因：`paper.seebug.org/{id}` 常见 JS 挑战（521），普通 HTTP 客户端不稳定。
- 如需尝试抓正文，可显式设置 `SEEBUG_PAPER_FETCH_BODY=true`。

## Run
```bash
pip install -r collectors/seebug_paper_rss/requirements.txt
python collectors/seebug_paper_rss/collector.py
```
