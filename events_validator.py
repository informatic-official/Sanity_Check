"""Validation for events.json."""

from __future__ import annotations

from typing import Any

from .utils import ValidationResult, is_valid_uuid_v7


def validate_events_structure(data: Any, result: ValidationResult) -> list[dict[str, Any]] | None:
    """Validate events.json list structure."""
    if not isinstance(data, list):
        result.error("events.json must be an array")
        return None

    for index, item in enumerate(data):
        if not isinstance(item, dict):
            result.error(f"events.json: event[{index}] must be an object")
            continue
        for key in ("session_uuid", "begin_timestamp", "end_timestamp"):
            if key not in item:
                result.error(f"events.json: event[{index}] missing `{key}`")

    return data


def validate_events_content(
    events: list[dict[str, Any]],
    expected_session_uuid: str,
    start_timestamp_us: int | None,
    end_timestamp_us: int | None,
    result: ValidationResult,
) -> None:
    """Validate events semantic rules."""
    for index, event in enumerate(events):
        event_uuid = event.get("session_uuid")
        begin_ts = event.get("begin_timestamp")
        end_ts = event.get("end_timestamp")

        if not isinstance(event_uuid, str) or not is_valid_uuid_v7(event_uuid):
            result.error(f"events.json: event[{index}] session_uuid must be valid UUID v7")
        elif event_uuid != expected_session_uuid:
            result.error(
                f"events.json: event[{index}] session_uuid does not match session folder UUID"
            )

        if not isinstance(begin_ts, int) or not isinstance(end_ts, int):
            result.error(
                f"events.json: event[{index}] begin_timestamp/end_timestamp must be integers"
            )
            continue

        if begin_ts != end_ts:
            result.error(
                f"events.json: event[{index}] begin_timestamp must equal end_timestamp"
            )

        if start_timestamp_us is not None and end_timestamp_us is not None:
            if not (start_timestamp_us <= begin_ts <= end_timestamp_us):
                result.error(
                    f"events.json: event[{index}] timestamp is outside session start/end window"
                )
