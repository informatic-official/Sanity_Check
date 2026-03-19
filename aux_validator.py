"""Validation for aux_info.json."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any

from .config import ValidationConfig
from .utils import (
    ValidationResult,
    datetime_to_epoch_ms,
    epoch_us_to_ms,
    is_valid_uuid_v7,
    is_valid_vin,
    parse_iso_datetime_utc,
)


def validate_aux_structure(data: Any, result: ValidationResult) -> dict[str, Any] | None:
    """Validate aux_info top-level structure and required fields."""
    if not isinstance(data, dict):
        result.error("aux_info.json must be a JSON object")
        return None

    required_fields = {
        "version",
        "session-name",
        "session-uuid",
        "start-time",
        "start-timestamp-utc-us",
        "end-time",
        "end-timestamp-utc-us",
        "duration",
        "vin",
        "car-id",
        "car-line",
        "rev-release",
        "ncd-version",
        "project",
    }
    missing = sorted(required_fields - data.keys())
    if missing:
        result.error("aux_info.json missing required fields: " + ", ".join(missing))

    return data


def validate_aux_content(
    aux_data: dict[str, Any],
    session_dir: Path,
    session_dt: datetime,
    session_uuid: str,
    config: ValidationConfig,
    result: ValidationResult,
) -> tuple[int | None, int | None]:
    """Validate business content and return start/end timestamps in microseconds."""
    aux_session_name = aux_data.get("session-name")
    aux_session_uuid = aux_data.get("session-uuid")

    session_uuid_v7_ok = isinstance(aux_session_uuid, str) and is_valid_uuid_v7(aux_session_uuid)
    result.check("aux_info.session-uuid is UUID v7", session_uuid_v7_ok, f"value={aux_session_uuid}")
    if not session_uuid_v7_ok:
        result.error(
            "aux_info.json: session-uuid must be a valid UUID v7, "
            f"got={aux_session_uuid}"
        )

    session_name_match = aux_session_name == session_dir.name
    result.check(
        "aux_info.session-name matches folder",
        session_name_match,
        f"aux={aux_session_name}, folder={session_dir.name}",
    )
    if not session_name_match:
        result.error(
            "aux_info.json: session-name does not match session folder name, "
            f"aux={aux_session_name}, folder={session_dir.name}"
        )

    session_uuid_match = aux_session_uuid == session_uuid
    result.check(
        "aux_info.session-uuid matches folder UUID",
        session_uuid_match,
        f"aux={aux_session_uuid}, folder={session_uuid}",
    )
    if not session_uuid_match:
        result.error(
            "aux_info.json: session-uuid does not match session folder UUID, "
            f"aux={aux_session_uuid}, folder={session_uuid}"
        )

    start_time = aux_data.get("start-time")
    start_timestamp = aux_data.get("start-timestamp-utc-us")
    end_time = aux_data.get("end-time")
    end_timestamp = aux_data.get("end-timestamp-utc-us")
    duration = aux_data.get("duration")

    parsed_start = parse_iso_datetime_utc(start_time) if isinstance(start_time, str) else None
    parsed_end = parse_iso_datetime_utc(end_time) if isinstance(end_time, str) else None

    start_time_valid = parsed_start is not None
    end_time_valid = parsed_end is not None
    result.check("aux_info.start-time ISO parse", start_time_valid, f"value={start_time}")
    result.check("aux_info.end-time ISO parse", end_time_valid, f"value={end_time}")
    if not start_time_valid:
        result.error(f"aux_info.json: start-time is not a valid ISO datetime, got={start_time}")
    if not end_time_valid:
        result.error(f"aux_info.json: end-time is not a valid ISO datetime, got={end_time}")

    start_ts_int = isinstance(start_timestamp, int)
    end_ts_int = isinstance(end_timestamp, int)
    duration_num = isinstance(duration, (int, float))
    result.check(
        "aux_info.start-timestamp-utc-us type",
        start_ts_int,
        f"value={start_timestamp}, type={type(start_timestamp).__name__}",
    )
    result.check(
        "aux_info.end-timestamp-utc-us type",
        end_ts_int,
        f"value={end_timestamp}, type={type(end_timestamp).__name__}",
    )
    result.check(
        "aux_info.duration type",
        duration_num,
        f"value={duration}, type={type(duration).__name__}",
    )
    if not start_ts_int:
        result.error(f"aux_info.json: start-timestamp-utc-us must be integer, got={start_timestamp}")
    if not end_ts_int:
        result.error(f"aux_info.json: end-timestamp-utc-us must be integer, got={end_timestamp}")
    if not duration_num:
        result.error(f"aux_info.json: duration must be numeric, got={duration}")

    if parsed_start is not None and isinstance(start_timestamp, int):
        start_time_ms = datetime_to_epoch_ms(parsed_start)
        start_ts_ms = epoch_us_to_ms(start_timestamp)
        start_match = start_time_ms == start_ts_ms
        result.check(
            "aux_info.start-time matches start-timestamp-utc-us at millisecond precision",
            start_match,
            f"start-time-ms={start_time_ms}, start-timestamp-utc-us={start_timestamp}, start-timestamp-ms={start_ts_ms}",
        )
        if not start_match:
            result.error(
                "aux_info.json: start-time does not match start-timestamp-utc-us at millisecond precision, "
                f"start-time-ms={start_time_ms}, start-timestamp-utc-us={start_timestamp}, "
                f"start-timestamp-ms={start_ts_ms}, start-time='{start_time}'"
            )

    if parsed_end is not None and isinstance(end_timestamp, int):
        end_time_ms = datetime_to_epoch_ms(parsed_end)
        end_ts_ms = epoch_us_to_ms(end_timestamp)
        end_match = end_time_ms == end_ts_ms
        result.check(
            "aux_info.end-time matches end-timestamp-utc-us at millisecond precision",
            end_match,
            f"end-time-ms={end_time_ms}, end-timestamp-utc-us={end_timestamp}, end-timestamp-ms={end_ts_ms}",
        )
        if not end_match:
            result.error(
                "aux_info.json: end-time does not match end-timestamp-utc-us at millisecond precision, "
                f"end-time-ms={end_time_ms}, end-timestamp-utc-us={end_timestamp}, "
                f"end-timestamp-ms={end_ts_ms}, end-time='{end_time}'"
            )

    if (
        isinstance(start_timestamp, int)
        and isinstance(end_timestamp, int)
        and isinstance(duration, (int, float))
    ):
        duration_expected_seconds = (end_timestamp - start_timestamp) / 1_000_000
        duration_match = abs(float(duration) - duration_expected_seconds) <= 1e-6
        result.check(
            "aux_info.duration matches timestamp delta",
            duration_match,
            f"duration={duration}, expected={duration_expected_seconds}, start={start_timestamp}, end={end_timestamp}",
        )
        if not duration_match:
            result.error(
                "aux_info.json: duration mismatch, "
                f"duration={duration}, expected={duration_expected_seconds}, "
                f"start-timestamp-utc-us={start_timestamp}, end-timestamp-utc-us={end_timestamp}"
            )

    def _start_time_precision_ms(start_text: str) -> int:
        """Infer start-time precision from fractional digits in ISO string."""
        match = re.search(r"\.(\d+)(?:Z|[+-]\d{2}:?\d{2})?$", start_text)
        if not match:
            return 1_000
        digits = len(match.group(1))
        if digits <= 0:
            return 1_000
        if digits == 1:
            return 100
        if digits == 2:
            return 10
        return 1

    def _truncate_to_unit_ms(epoch_ms: int, unit_ms: int) -> int:
        """Truncate epoch milliseconds to the target precision unit."""
        return (epoch_ms // unit_ms) * unit_ms

    if parsed_start is not None and parsed_end is not None:
        end_after_start = parsed_end >= parsed_start
        result.check(
            "aux_info.end-time >= start-time",
            end_after_start,
            f"start={parsed_start.isoformat()}, end={parsed_end.isoformat()}",
        )
        if not end_after_start:
            result.error("aux_info.json: end-time must be >= start-time")

        folder_ms = datetime_to_epoch_ms(session_dt)
        start_ms = datetime_to_epoch_ms(parsed_start)
        folder_precision_ms = 1_000
        start_precision_ms = _start_time_precision_ms(start_time) if isinstance(start_time, str) else 1
        compare_unit_ms = max(folder_precision_ms, start_precision_ms)
        folder_aligned_ms = _truncate_to_unit_ms(folder_ms, compare_unit_ms)
        start_aligned_ms = _truncate_to_unit_ms(start_ms, compare_unit_ms)
        folder_matches_start = folder_aligned_ms == start_aligned_ms
        result.check(
            "session folder timestamp matches aux start-time at lower precision",
            folder_matches_start,
            (
                f"folder={session_dt.isoformat()}, start={parsed_start.isoformat()}, "
                f"unit-ms={compare_unit_ms}, folder-aligned-ms={folder_aligned_ms}, "
                f"start-aligned-ms={start_aligned_ms}"
            ),
        )
        if not folder_matches_start:
            result.error(
                "aux_info.json: session folder timestamp must match start-time using lower precision alignment, "
                f"folder={session_dt.isoformat()}, start={parsed_start.isoformat()}, "
                f"unit-ms={compare_unit_ms}, folder-aligned-ms={folder_aligned_ms}, "
                f"start-aligned-ms={start_aligned_ms}"
            )

    if parsed_start is not None:
        if parsed_start < config.min_session_datetime_utc:
            result.error("aux_info.json: start-time is earlier than allowed minimum")
        if parsed_start > config.max_session_datetime_utc:
            result.error("aux_info.json: start-time is in the future")

    vin = aux_data.get("vin")
    vin_valid = isinstance(vin, str) and is_valid_vin(vin)
    result.check("aux_info.vin ISO-3779 valid", vin_valid, f"vin={vin}")
    if not vin_valid:
        result.error(f"aux_info.json: vin is invalid (ISO 3779 check failed), got={vin}")

    car_id = aux_data.get("car-id")
    car_line = aux_data.get("car-line")
    if not isinstance(car_id, str):
        result.error("aux_info.json: car-id must be string")

    if not isinstance(car_line, str):
        result.error("aux_info.json: car-line must be string")
    elif car_line not in config.valid_car_lines:
        result.error(
            "aux_info.json: car-line not in allowed list: "
            + ", ".join(sorted(config.valid_car_lines))
        )

    rev_release = aux_data.get("rev-release")
    if not isinstance(rev_release, str) or rev_release not in config.supported_rev_releases:
        result.error(
            "aux_info.json: rev-release not supported: "
            + ", ".join(sorted(config.supported_rev_releases))
        )

    ncd_version = aux_data.get("ncd-version")
    ncd_ok = isinstance(ncd_version, str) and ncd_version in config.expected_ncd_versions
    result.check(
        "aux_info.ncd-version in expected list",
        ncd_ok,
        f"value={ncd_version}, expected={sorted(config.expected_ncd_versions)}",
    )
    if not ncd_ok:
        result.error(
            "aux_info.json: ncd-version not expected, "
            f"got={ncd_version}, expected={sorted(config.expected_ncd_versions)}"
        )

    project = aux_data.get("project")
    if project != config.expected_project:
        result.error(f"aux_info.json: project must be `{config.expected_project}`")

    if isinstance(start_timestamp, int) and isinstance(end_timestamp, int):
        return start_timestamp, end_timestamp
    return None, None
