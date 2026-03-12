"""Validation for aux_info.json."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from .config import ValidationConfig
from .utils import (
    ValidationResult,
    datetime_to_epoch_us,
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
    """Validate business content and return start/end timestamps in us."""
    aux_session_name = aux_data.get("session-name")
    aux_session_uuid = aux_data.get("session-uuid")

    if not isinstance(aux_session_uuid, str) or not is_valid_uuid_v7(aux_session_uuid):
        result.error("aux_info.json: session-uuid must be a valid UUID v7")

    if aux_session_name != session_dir.name:
        result.error("aux_info.json: session-name does not match session folder name")

    if aux_session_uuid != session_uuid:
        result.error("aux_info.json: session-uuid does not match session folder UUID")

    start_time = aux_data.get("start-time")
    start_timestamp = aux_data.get("start-timestamp-utc-us")
    end_time = aux_data.get("end-time")
    end_timestamp = aux_data.get("end-timestamp-utc-us")
    duration = aux_data.get("duration")

    parsed_start = parse_iso_datetime_utc(start_time) if isinstance(start_time, str) else None
    parsed_end = parse_iso_datetime_utc(end_time) if isinstance(end_time, str) else None

    if parsed_start is None:
        result.error("aux_info.json: start-time is not a valid ISO datetime")
    if parsed_end is None:
        result.error("aux_info.json: end-time is not a valid ISO datetime")

    if not isinstance(start_timestamp, int):
        result.error("aux_info.json: start-timestamp-utc-us must be integer")
    if not isinstance(end_timestamp, int):
        result.error("aux_info.json: end-timestamp-utc-us must be integer")
    if not isinstance(duration, (int, float)):
        result.error("aux_info.json: duration must be numeric")

    if parsed_start is not None and isinstance(start_timestamp, int):
        if datetime_to_epoch_us(parsed_start) != start_timestamp:
            result.error("aux_info.json: start-time does not match start-timestamp-utc-us")

    if parsed_end is not None and isinstance(end_timestamp, int):
        if datetime_to_epoch_us(parsed_end) != end_timestamp:
            result.error("aux_info.json: end-time does not match end-timestamp-utc-us")

    if (
        isinstance(start_timestamp, int)
        and isinstance(end_timestamp, int)
        and isinstance(duration, (int, float))
    ):
        duration_expected_seconds = (end_timestamp - start_timestamp) / 1_000_000
        if abs(float(duration) - duration_expected_seconds) > 1e-6:
            result.error(
                "aux_info.json: duration must equal "
                "(end-timestamp-utc-us - start-timestamp-utc-us) / 1_000_000"
            )

    if parsed_start is not None and parsed_end is not None:
        if parsed_end < parsed_start:
            result.error("aux_info.json: end-time must be >= start-time")
        if not (parsed_start >= session_dt):
            result.error(
                "aux_info.json: session folder timestamp must be earlier than start-time"
            )

    if parsed_start is not None:
        if parsed_start < config.min_session_datetime_utc:
            result.error("aux_info.json: start-time is earlier than allowed minimum")
        if parsed_start > config.max_session_datetime_utc:
            result.error("aux_info.json: start-time is in the future")

    vin = aux_data.get("vin")
    if not isinstance(vin, str) or not is_valid_vin(vin):
        result.error("aux_info.json: vin is invalid (ISO 3779 check failed)")

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
    if not isinstance(ncd_version, str) or ncd_version not in config.expected_ncd_versions:
        result.error(
            "aux_info.json: ncd-version not expected: "
            + ", ".join(sorted(config.expected_ncd_versions))
        )

    project = aux_data.get("project")
    if project != config.expected_project:
        result.error(f"aux_info.json: project must be `{config.expected_project}`")

    if isinstance(start_timestamp, int) and isinstance(end_timestamp, int):
        return start_timestamp, end_timestamp
    return None, None
