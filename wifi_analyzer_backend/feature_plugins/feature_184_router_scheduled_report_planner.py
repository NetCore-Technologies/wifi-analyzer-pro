"""Plan timezone-aware scheduled report occurrences without running background jobs."""
from __future__ import annotations

import hashlib
import json
import re
from calendar import monthrange
from datetime import date, datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_SCHEDULES = 100
MAX_OCCURRENCES = 10
MAX_TOTAL_OCCURRENCES = 1000
MAX_SCAN_DAYS = 3660
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
TIME_TEXT = re.compile(r"^(?:[01]\d|2[0-3]):[0-5]\d$")


def _id(value: object, field: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError(f"{field} must be a 1 to 64 character identifier")
    return value


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a timezone offset")
    return parsed.astimezone(timezone.utc)


def _schedule(raw: object, index: int) -> dict:
    field = f"schedules[{index}]"
    if not isinstance(raw, dict):
        raise ValueError(f"{field} must be an object")
    schedule_id = _id(raw.get("schedule_id"), f"{field}.schedule_id")
    report_id = _id(raw.get("report_id"), f"{field}.report_id")
    timezone_name = raw.get("timezone")
    if not isinstance(timezone_name, str) or not timezone_name or len(timezone_name) > 64:
        raise ValueError(f"{field}.timezone must be an IANA timezone name")
    try:
        zone = ZoneInfo(timezone_name)
    except (ZoneInfoNotFoundError, ValueError) as error:
        raise ValueError(f"{field}.timezone is not a recognized IANA timezone") from error
    frequency = raw.get("frequency")
    if not isinstance(frequency, str) or frequency not in {"daily", "weekly", "monthly"}:
        raise ValueError(f"{field}.frequency must be daily, weekly or monthly")
    local_time = raw.get("local_time")
    if not isinstance(local_time, str) or not TIME_TEXT.fullmatch(local_time):
        raise ValueError(f"{field}.local_time must use HH:MM 24-hour format")
    hour, minute = (int(part) for part in local_time.split(":"))
    enabled = raw.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ValueError(f"{field}.enabled must be a boolean")

    weekdays = raw.get("weekdays", [])
    if not isinstance(weekdays, list) or len(weekdays) > 7:
        raise ValueError(f"{field}.weekdays must be a list of weekday integers")
    if any(isinstance(day, bool) or not isinstance(day, int) or not 0 <= day <= 6 for day in weekdays):
        raise ValueError(f"{field}.weekdays entries must be integers from 0 (Monday) to 6 (Sunday)")
    if len(weekdays) != len(set(weekdays)):
        raise ValueError(f"{field}.weekdays entries must be unique")
    if frequency == "weekly" and not weekdays:
        raise ValueError(f"{field}.weekdays must contain at least one day for weekly schedules")
    if frequency != "weekly" and weekdays:
        raise ValueError(f"{field}.weekdays are only valid for weekly schedules")

    day_of_month = raw.get("day_of_month")
    if frequency == "monthly":
        if isinstance(day_of_month, bool) or not isinstance(day_of_month, int) or not 1 <= day_of_month <= 31:
            raise ValueError(f"{field}.day_of_month must be an integer from 1 to 31 for monthly schedules")
    elif day_of_month is not None:
        raise ValueError(f"{field}.day_of_month is only valid for monthly schedules")
    month_policy = raw.get("month_day_policy", "skip")
    if not isinstance(month_policy, str) or month_policy not in {"skip", "clamp"}:
        raise ValueError(f"{field}.month_day_policy must be skip or clamp")
    ambiguous_policy = raw.get("ambiguous_time_policy", "earlier")
    if not isinstance(ambiguous_policy, str) or ambiguous_policy not in {"earlier", "later"}:
        raise ValueError(f"{field}.ambiguous_time_policy must be earlier or later")
    gap_policy = raw.get("nonexistent_time_policy", "shift_forward")
    if not isinstance(gap_policy, str) or gap_policy not in {"shift_forward", "skip"}:
        raise ValueError(f"{field}.nonexistent_time_policy must be shift_forward or skip")

    start_date = raw.get("start_date")
    if start_date is not None:
        if not isinstance(start_date, str):
            raise ValueError(f"{field}.start_date must use YYYY-MM-DD format")
        try:
            start_date = date.fromisoformat(start_date)
        except ValueError as error:
            raise ValueError(f"{field}.start_date must use YYYY-MM-DD format") from error
    return {
        "schedule_id": schedule_id,
        "report_id": report_id,
        "timezone_name": timezone_name,
        "zone": zone,
        "frequency": frequency,
        "local_time": local_time,
        "hour": hour,
        "minute": minute,
        "enabled": enabled,
        "weekdays": set(weekdays),
        "day_of_month": day_of_month,
        "month_day_policy": month_policy,
        "ambiguous_time_policy": ambiguous_policy,
        "nonexistent_time_policy": gap_policy,
        "start_date": start_date,
    }


def _resolve_local(local_naive: datetime, zone: ZoneInfo, ambiguous: str,
                   nonexistent: str) -> datetime | None:
    candidates = []
    for fold in (0, 1):
        candidate = local_naive.replace(tzinfo=zone, fold=fold)
        utc_value = candidate.astimezone(timezone.utc)
        round_trip = utc_value.astimezone(zone).replace(tzinfo=None)
        if round_trip == local_naive and all(existing[0] != utc_value for existing in candidates):
            candidates.append((utc_value, candidate))
    if candidates:
        candidates.sort(key=lambda item: item[0])
        selected = candidates[0] if ambiguous == "earlier" else candidates[-1]
        return selected[1]
    if nonexistent == "skip":
        return None
    # A spring-forward gap is normally one hour; the bounded loop also covers
    # historical 30-minute and 24-hour civil-time transitions.
    for shift in range(1, 181):
        shifted = local_naive + timedelta(minutes=shift)
        for fold in (0, 1):
            candidate = shifted.replace(tzinfo=zone, fold=fold)
            utc_value = candidate.astimezone(timezone.utc)
            if utc_value.astimezone(zone).replace(tzinfo=None) == shifted:
                return candidate
    return None


def _matches_day(schedule: dict, day: date) -> tuple[bool, date | None]:
    if schedule["start_date"] and day < schedule["start_date"]:
        return False, None
    frequency = schedule["frequency"]
    if frequency == "daily":
        return True, day
    if frequency == "weekly":
        return day.weekday() in schedule["weekdays"], day
    requested = schedule["day_of_month"]
    last_day = monthrange(day.year, day.month)[1]
    if requested <= last_day:
        return day.day == requested, day
    if schedule["month_day_policy"] == "clamp":
        return day.day == last_day, day
    return False, None


def _occurrence(schedule: dict, local: datetime, aware: datetime) -> dict:
    utc_value = aware.astimezone(timezone.utc)
    material = json.dumps([
        schedule["schedule_id"], schedule["report_id"],
        schedule["timezone_name"], local.isoformat(),
    ], separators=(",", ":"))
    occurrence_id = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return {
        "occurrence_id": occurrence_id,
        "schedule_id": schedule["schedule_id"],
        "report_id": schedule["report_id"],
        "scheduled_local": aware.isoformat(),
        "scheduled_at": utc_value.isoformat(),
        "timezone": schedule["timezone_name"],
        "utc_offset": aware.strftime("%z"),
        "dst_fold": aware.fold,
    }


def _next_occurrences(schedule: dict, now: datetime, count: int) -> list[dict]:
    zone = schedule["zone"]
    local_now = now.astimezone(zone)
    day = local_now.date()
    results = []
    for offset in range(MAX_SCAN_DAYS + 1):
        candidate_day = day + timedelta(days=offset)
        matches, _ = _matches_day(schedule, candidate_day)
        if not matches:
            continue
        naive = datetime.combine(candidate_day, time(schedule["hour"], schedule["minute"]))
        aware = _resolve_local(
            naive, zone,
            schedule["ambiguous_time_policy"],
            schedule["nonexistent_time_policy"],
        )
        if aware is None:
            continue
        utc_value = aware.astimezone(timezone.utc)
        if utc_value <= now:
            continue
        results.append(_occurrence(schedule, naive, aware))
        if len(results) >= count:
            break
    return results


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    try:
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValueError("schedule input must contain JSON-compatible finite values") from error
    if len(encoded.encode("utf-8")) > MAX_INPUT_BYTES:
        raise ValueError(f"schedule input exceeds the {MAX_INPUT_BYTES}-byte input limit")
    now = _timestamp(payload.get("now"), "now")
    raw_schedules = payload.get("schedules")
    if not isinstance(raw_schedules, list) or not 1 <= len(raw_schedules) <= MAX_SCHEDULES:
        raise ValueError(f"schedules must contain from 1 to {MAX_SCHEDULES} records")
    schedules = [_schedule(item, index) for index, item in enumerate(raw_schedules)]
    ids = [item["schedule_id"] for item in schedules]
    if len(ids) != len(set(ids)):
        raise ValueError("schedule_id values must be unique")
    occurrence_count = payload.get("occurrences_per_schedule", 3)
    if (isinstance(occurrence_count, bool) or not isinstance(occurrence_count, int)
            or not 1 <= occurrence_count <= MAX_OCCURRENCES):
        raise ValueError(f"occurrences_per_schedule must be an integer from 1 to {MAX_OCCURRENCES}")

    planned = []
    for schedule in sorted(schedules, key=lambda item: item["schedule_id"]):
        if not schedule["enabled"]:
            planned.append({
                "schedule_id": schedule["schedule_id"],
                "report_id": schedule["report_id"],
                "enabled": False,
                "timezone": schedule["timezone_name"],
                "frequency": schedule["frequency"],
                "next_occurrences": [],
                "status": "disabled",
            })
            continue
        occurrences = _next_occurrences(schedule, now, occurrence_count)
        planned.append({
            "schedule_id": schedule["schedule_id"],
            "report_id": schedule["report_id"],
            "enabled": True,
            "timezone": schedule["timezone_name"],
            "frequency": schedule["frequency"],
            "next_occurrences": occurrences,
            "status": "scheduled" if occurrences else "no_occurrence_in_horizon",
            "month_day_policy": schedule["month_day_policy"] if schedule["frequency"] == "monthly" else None,
            "ambiguous_time_policy": schedule["ambiguous_time_policy"],
            "nonexistent_time_policy": schedule["nonexistent_time_policy"],
        })
    total_occurrences = sum(len(item["next_occurrences"]) for item in planned)
    if total_occurrences > MAX_TOTAL_OCCURRENCES:
        raise ValueError(f"planned occurrences exceed the {MAX_TOTAL_OCCURRENCES}-item output limit")
    return {
        "status": "planned",
        "evaluated_at": now.isoformat(),
        "summary": {
            "schedule_count": len(planned),
            "enabled_schedule_count": sum(item["enabled"] for item in planned),
            "disabled_schedule_count": sum(not item["enabled"] for item in planned),
            "planned_occurrence_count": total_occurrences,
            "schedules_without_occurrence_count": sum(
                item["enabled"] and not item["next_occurrences"] for item in planned
            ),
        },
        "schedules": planned,
        "note": (
            "This is a deterministic schedule preview only. It does not run reports, create background jobs, "
            "persist schedules, or send notifications. Use occurrence_id as an idempotency key in a separately "
            "controlled scheduler/worker. DST gaps are shifted or skipped per policy; repeated local times use "
            "the configured earlier/later occurrence."
        ),
    }


FEATURE = {
    "id": "F184",
    "slug": "router_scheduled_report_planner",
    "name": "Timezone-aware router scheduled report planner",
    "category": "Router operations",
    "description": (
        "Validate daily, weekly and monthly router report schedules and calculate bounded future occurrences "
        "with IANA timezone, DST ambiguity/gap and short-month policies."
    ),
    "parameters": {
        "now": "timezone-aware evaluation timestamp",
        "schedules": "1 to 100 local report schedule definitions",
        "occurrences_per_schedule": "number of future occurrences to preview, from 1 to 10",
    },
    "run": run,
}
