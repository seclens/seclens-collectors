# macOS launchd deployment (local runner)

Equivalent to `docs/systemd/*` but for macOS.

## 1) Prepare runtime files

```bash
cp docs/launchd/run_collectors.sh /opt/seclens-collectors/scripts/run_collectors.sh
chmod +x /opt/seclens-collectors/scripts/run_collectors.sh

cp docs/launchd/seclens-collectors.plist ~/Library/LaunchAgents/com.seclens.collectors.runner.plist
```

## 2) Configure local env/profile

- Put `SECLENS_URL` and `SECLENS_TOKEN` in `/opt/seclens-collectors/.env`
- Set `PROFILE_PATH` in plist (or keep script default)

## 3) Load scheduler

```bash
launchctl bootout gui/$(id -u) ~/Library/LaunchAgents/com.seclens.collectors.runner.plist 2>/dev/null || true
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.seclens.collectors.runner.plist
launchctl enable gui/$(id -u)/com.seclens.collectors.runner
```

## 4) Verify

```bash
launchctl print gui/$(id -u)/com.seclens.collectors.runner
tail -f /opt/seclens-collectors/logs/run_collectors.log
```

Default run interval is every 300 seconds (5 minutes), matching `systemd timer` cadence.
