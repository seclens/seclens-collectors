from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from run_collectors import _resolve_schedule


class ResolveScheduleTests(unittest.TestCase):
    def _make_collector_dir(self, slug: str, schedule_seconds: int = 3600) -> Path:
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        collector_dir = Path(temp_dir.name) / slug
        collector_dir.mkdir(parents=True)
        (collector_dir / "manifest.json").write_text(
            json.dumps({"slug": slug, "schedule": schedule_seconds}),
            encoding="utf-8",
        )
        return collector_dir

    def test_new_collector_is_due_immediately(self) -> None:
        now_utc = datetime(2026, 4, 5, 4, 0, tzinfo=timezone.utc)
        collector_dir = self._make_collector_dir("new_source")

        schedule = _resolve_schedule(
            "new_source",
            collector_dir,
            {},
            None,
            now_utc,
        )

        self.assertTrue(schedule.due_now)
        self.assertEqual(schedule.next_due_at, now_utc)

    def test_schedule_change_reboots_due_time(self) -> None:
        now_utc = datetime(2026, 4, 5, 4, 0, tzinfo=timezone.utc)
        collector_dir = self._make_collector_dir("override_source")
        state_entry = {
            "interval_minutes": 60,
            "anchor_utc": "2026-01-01T00:00:00Z",
            "next_due_at": "2026-04-05T05:00:00Z",
        }
        profile = {
            "schedule_overrides": {
                "override_source": {"interval_minutes": 120},
            }
        }

        schedule = _resolve_schedule(
            "override_source",
            collector_dir,
            profile,
            state_entry,
            now_utc,
        )

        self.assertTrue(schedule.due_now)
        self.assertEqual(schedule.next_due_at, now_utc)

    def test_matching_state_keeps_saved_next_due(self) -> None:
        now_utc = datetime(2026, 4, 5, 4, 0, tzinfo=timezone.utc)
        collector_dir = self._make_collector_dir("stable_source")
        profile = {
            "schedule_overrides": {
                "stable_source": {"anchor_utc": "2026-01-01T00:15:00Z"},
            }
        }
        state_entry = {
            "interval_minutes": 60,
            "anchor_utc": "2026-01-01T00:15:00Z",
            "next_due_at": "2026-04-05T04:15:00Z",
        }

        schedule = _resolve_schedule(
            "stable_source",
            collector_dir,
            profile,
            state_entry,
            now_utc,
        )

        self.assertFalse(schedule.due_now)
        self.assertEqual(schedule.next_due_at.isoformat().replace("+00:00", "Z"), "2026-04-05T04:15:00Z")


if __name__ == "__main__":
    unittest.main()
