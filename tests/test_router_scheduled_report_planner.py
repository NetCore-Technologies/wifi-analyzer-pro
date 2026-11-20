"""Tests for timezone-aware router report schedule planning."""
from __future__ import annotations

import unittest

from wifi_analyzer_backend.feature_plugins.feature_184_router_scheduled_report_planner import run


class RouterScheduledReportPlannerTests(unittest.TestCase):
    def test_daily_schedule_returns_multiple_local_time_occurrences(self):
        result = run({
            "now": "2026-11-20T00:00:00Z",
            "schedules": [{
                "schedule_id": "daily-home",
                "report_id": "weekly-home",
                "timezone": "Australia/Sydney",
                "frequency": "daily",
                "local_time": "18:30",
            }],
            "occurrences_per_schedule": 3,
        })
        schedule = result["schedules"][0]
        self.assertEqual(schedule["status"], "scheduled")
        self.assertEqual(len(schedule["next_occurrences"]), 3)
        self.assertEqual(schedule["next_occurrences"][0]["scheduled_local"], "2026-11-20T18:30:00+11:00")
        self.assertEqual(schedule["next_occurrences"][0]["scheduled_at"], "2026-11-20T07:30:00+00:00")
        self.assertEqual(len(schedule["next_occurrences"][0]["occurrence_id"]), 64)

    def test_weekly_schedule_selects_only_requested_weekdays(self):
        result = run({
            "now": "2026-11-20T00:00:00Z",
            "schedules": [{
                "schedule_id": "mon-wed",
                "report_id": "office-weekly",
                "timezone": "UTC",
                "frequency": "weekly",
                "weekdays": [0, 2],
                "local_time": "09:15",
            }],
            "occurrences_per_schedule": 3,
        })
        values = [item["scheduled_local"] for item in result["schedules"][0]["next_occurrences"]]
        self.assertEqual(values, [
            "2026-11-23T09:15:00+00:00",
            "2026-11-25T09:15:00+00:00",
            "2026-11-30T09:15:00+00:00",
        ])

    def test_monthly_schedule_can_skip_or_clamp_short_month_dates(self):
        result = run({
            "now": "2026-02-27T00:00:00Z",
            "schedules": [
                {
                    "schedule_id": "monthly-skip", "report_id": "month-end",
                    "timezone": "UTC", "frequency": "monthly",
                    "day_of_month": 31, "month_day_policy": "skip", "local_time": "10:00",
                },
                {
                    "schedule_id": "monthly-clamp", "report_id": "month-end",
                    "timezone": "UTC", "frequency": "monthly",
                    "day_of_month": 31, "month_day_policy": "clamp", "local_time": "10:00",
                },
            ],
            "occurrences_per_schedule": 2,
        })
        by_id = {item["schedule_id"]: item for item in result["schedules"]}
        self.assertEqual(by_id["monthly-skip"]["next_occurrences"][0]["scheduled_local"], "2026-03-31T10:00:00+00:00")
        self.assertEqual(by_id["monthly-clamp"]["next_occurrences"][0]["scheduled_local"], "2026-02-28T10:00:00+00:00")

    def test_start_date_prevents_occurrences_before_schedule_activation(self):
        result = run({
            "now": "2026-11-20T00:00:00Z",
            "schedules": [{
                "schedule_id": "starts-later", "report_id": "home",
                "timezone": "UTC", "frequency": "daily",
                "local_time": "09:00", "start_date": "2026-11-23",
            }],
        })
        self.assertEqual(result["schedules"][0]["next_occurrences"][0]["scheduled_local"], "2026-11-23T09:00:00+00:00")

    def test_dst_spring_gap_shifts_forward_or_skips_by_policy(self):
        result = run({
            "now": "2026-10-03T00:00:00Z",
            "schedules": [
                {
                    "schedule_id": "shift-gap", "report_id": "dst",
                    "timezone": "Australia/Sydney", "frequency": "daily",
                    "local_time": "02:30", "nonexistent_time_policy": "shift_forward",
                },
                {
                    "schedule_id": "skip-gap", "report_id": "dst",
                    "timezone": "Australia/Sydney", "frequency": "daily",
                    "local_time": "02:30", "nonexistent_time_policy": "skip",
                },
            ],
            "occurrences_per_schedule": 1,
        })
        by_id = {item["schedule_id"]: item for item in result["schedules"]}
        self.assertEqual(by_id["shift-gap"]["next_occurrences"][0]["scheduled_local"], "2026-10-04T03:00:00+11:00")
        self.assertEqual(by_id["skip-gap"]["next_occurrences"][0]["scheduled_local"], "2026-10-05T02:30:00+11:00")

    def test_dst_ambiguous_fall_time_selects_earlier_or_later_fold(self):
        result = run({
            "now": "2026-10-31T00:00:00Z",
            "schedules": [
                {
                    "schedule_id": "fold-earlier", "report_id": "dst",
                    "timezone": "America/New_York", "frequency": "daily",
                    "local_time": "01:30", "ambiguous_time_policy": "earlier",
                },
                {
                    "schedule_id": "fold-later", "report_id": "dst",
                    "timezone": "America/New_York", "frequency": "daily",
                    "local_time": "01:30", "ambiguous_time_policy": "later",
                },
            ],
            "occurrences_per_schedule": 1,
        })
        by_id = {item["schedule_id"]: item for item in result["schedules"]}
        earlier = by_id["fold-earlier"]["next_occurrences"][0]
        later = by_id["fold-later"]["next_occurrences"][0]
        self.assertEqual(earlier["scheduled_at"], "2026-11-01T05:30:00+00:00")
        self.assertEqual(later["scheduled_at"], "2026-11-01T06:30:00+00:00")
        self.assertEqual((earlier["dst_fold"], later["dst_fold"]), (0, 1))

    def test_disabled_schedule_is_reported_without_occurrences(self):
        result = run({
            "now": "2026-11-20T00:00:00Z",
            "schedules": [{
                "schedule_id": "disabled", "report_id": "home",
                "timezone": "UTC", "frequency": "daily",
                "local_time": "09:00", "enabled": False,
            }],
        })
        self.assertEqual(result["summary"]["disabled_schedule_count"], 1)
        self.assertEqual(result["schedules"][0]["status"], "disabled")
        self.assertEqual(result["schedules"][0]["next_occurrences"], [])

    def test_occurrence_keys_are_stable_and_schedules_are_sorted(self):
        payload = {
            "now": "2026-11-20T00:00:00Z",
            "schedules": [
                {"schedule_id": "z-schedule", "report_id": "z", "timezone": "UTC",
                 "frequency": "daily", "local_time": "09:00"},
                {"schedule_id": "a-schedule", "report_id": "a", "timezone": "UTC",
                 "frequency": "daily", "local_time": "09:00"},
            ],
        }
        first = run(payload)
        second = run(payload)
        self.assertEqual([item["schedule_id"] for item in first["schedules"]], ["a-schedule", "z-schedule"])
        self.assertEqual(first["schedules"][0]["next_occurrences"][0]["occurrence_id"],
                         second["schedules"][0]["next_occurrences"][0]["occurrence_id"])

    def test_rejects_invalid_timezone_recurrence_time_and_duplicate_schedule_ids(self):
        base = {"schedule_id": "invalid", "report_id": "home", "timezone": "UTC",
                "frequency": "daily", "local_time": "09:00"}
        with self.assertRaisesRegex(ValueError, "recognized IANA timezone"):
            run({"now": "2026-11-20T00:00:00Z", "schedules": [{**base, "timezone": "Mars/Olympus"}]})
        with self.assertRaisesRegex(ValueError, "HH:MM"):
            run({"now": "2026-11-20T00:00:00Z", "schedules": [{**base, "local_time": "9am"}]})
        with self.assertRaisesRegex(ValueError, "at least one day"):
            run({"now": "2026-11-20T00:00:00Z", "schedules": [{**base, "frequency": "weekly"}]})
        with self.assertRaisesRegex(ValueError, "unique"):
            run({"now": "2026-11-20T00:00:00Z", "schedules": [base, base]})

    def test_rejects_naive_now_and_invalid_weekday_or_month_policies(self):
        base = {"schedule_id": "valid", "report_id": "home", "timezone": "UTC",
                "frequency": "daily", "local_time": "09:00"}
        with self.assertRaisesRegex(ValueError, "timezone offset"):
            run({"now": "2026-11-20T00:00:00", "schedules": [base]})
        with self.assertRaisesRegex(ValueError, "weekday integers"):
            run({"now": "2026-11-20T00:00:00Z", "schedules": [
                {**base, "frequency": "weekly", "weekdays": ["Monday"]},
            ]})
        with self.assertRaisesRegex(ValueError, "month_day_policy"):
            run({"now": "2026-11-20T00:00:00Z", "schedules": [
                {**base, "frequency": "monthly", "day_of_month": 31, "month_day_policy": "roll"},
            ]})

    def test_enforces_schedule_and_occurrence_bounds(self):
        base = {"report_id": "home", "timezone": "UTC", "frequency": "daily", "local_time": "09:00"}
        with self.assertRaisesRegex(ValueError, "from 1 to 100"):
            run({"now": "2026-11-20T00:00:00Z", "schedules": [
                {**base, "schedule_id": f"schedule-{index}"} for index in range(101)
            ]})
        with self.assertRaisesRegex(ValueError, "from 1 to 10"):
            run({"now": "2026-11-20T00:00:00Z", "occurrences_per_schedule": 11,
                 "schedules": [{**base, "schedule_id": "daily"}]})


if __name__ == "__main__":
    unittest.main()
