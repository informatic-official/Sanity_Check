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

        event_uuid_v7 = isinstance(event_uuid, str) and is_valid_uuid_v7(event_uuid)
        result.check(
            f"events[{index}].session_uuid is UUID v7",
            event_uuid_v7,
            f"value={event_uuid}",
        )
        if not event_uuid_v7:
            result.error(
                f"events.json: event[{index}] session_uuid must be valid UUID v7, got={event_uuid}"
            )
        else:
            uuid_match = event_uuid == expected_session_uuid
            result.check(
                f"events[{index}].session_uuid matches folder UUID",
                uuid_match,
                f"event={event_uuid}, folder={expected_session_uuid}",
            )
            if not uuid_match:
                result.error(
                    f"events.json: event[{index}] session_uuid does not match session folder UUID"
                )

        ts_types_ok = isinstance(begin_ts, int) and isinstance(end_ts, int)
        result.check(
            f"events[{index}] timestamp field types",
            ts_types_ok,
            f"begin={begin_ts} ({type(begin_ts).__name__}), end={end_ts} ({type(end_ts).__name__})",
        )
        if not ts_types_ok:
            result.error(
                f"events.json: event[{index}] begin_timestamp/end_timestamp must be integers, "
                f"got begin={begin_ts}, end={end_ts}"
            )
            continue

        begin_end_equal = begin_ts == end_ts
        result.check(
            f"events[{index}] begin_timestamp equals end_timestamp",
            begin_end_equal,
            f"begin={begin_ts}, end={end_ts}",
        )
        if not begin_end_equal:
            result.error(
                f"events.json: event[{index}] begin_timestamp must equal end_timestamp, "
                f"begin={begin_ts}, end={end_ts}"
            )

        if start_timestamp_us is not None and end_timestamp_us is not None:
            in_window = start_timestamp_us <= begin_ts <= end_timestamp_us
            result.check(
                f"events[{index}] timestamp within aux start/end window",
                in_window,
                f"event={begin_ts}, start={start_timestamp_us}, end={end_timestamp_us}",
            )
            if not in_window:
                result.error(
                    f"events.json: event[{index}] timestamp is outside session start/end window, "
                    f"event={begin_ts}, start={start_timestamp_us}, end={end_timestamp_us}"
                )
