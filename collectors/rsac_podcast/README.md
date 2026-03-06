# RSA Conference Podcast Collector

Fetches podcast episodes from [RSA Conference](https://soundcloud.com/rsa-conference) on SoundCloud.

## Source

- **Publisher:** RSA Conference
- **Feed URL:** https://soundcloud.com/rsa-conference/tracks
- **Content Type:** Podcast episodes, conference talks
- **Language:** English
- **Update Frequency:** Weekly / after events

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

Recommended: every 4 hours.

```bash
# crontab
0 */4 * * * cd /path/to/rsac_podcast && python collector.py >> /var/log/rsac-podcast-collector.log 2>&1
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECLENS_URL` | Yes | - | SecLens server URL |
| `SECLENS_TOKEN` | Yes | - | API token for authentication |
| `RSAC_LIST_URL` | No | soundcloud.com URL | Override the track list URL |

## Notes

- Uses a local `.cursor` cache file to avoid re-processing already-seen episodes
- Fetches track metadata via SoundCloud oEmbed API
- Default limit: 20 tracks per run
