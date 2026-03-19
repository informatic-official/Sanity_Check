"""Default validation configuration."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


BASE_VALID_CAR_LINES = {"174"}
BASE_SUPPORTED_REV_RELEASES = {"rev-25.01"}
BASE_EXPECTED_NCD_VERSIONS = {"25.05"}

DEFAULTS_FILE_PATH = Path(__file__).with_name("defaults.json")


def base_default_lists() -> dict[str, set[str]]:
    """Return built-in immutable defaults as new sets."""
    return {
        "valid_car_lines": set(BASE_VALID_CAR_LINES),
        "supported_rev_releases": set(BASE_SUPPORTED_REV_RELEASES),
        "expected_ncd_versions": set(BASE_EXPECTED_NCD_VERSIONS),
    }


def load_default_lists() -> dict[str, set[str]]:
    """Load default lists from defaults.json, fallback to built-ins."""
    defaults = base_default_lists()
    if not DEFAULTS_FILE_PATH.exists():
        return defaults

    try:
        with DEFAULTS_FILE_PATH.open("r", encoding="utf-8") as file_obj:
            raw = json.load(file_obj)
    except (OSError, json.JSONDecodeError):
        return defaults

    if not isinstance(raw, dict):
        return defaults

    for key in defaults:
        value = raw.get(key)
        if isinstance(value, list):
            defaults[key] = {str(item) for item in value if str(item)}
    return defaults


def save_default_lists(defaults: dict[str, set[str]]) -> None:
    """Persist default lists to defaults.json."""
    normalized = {
        "valid_car_lines": sorted(defaults.get("valid_car_lines", set())),
        "supported_rev_releases": sorted(defaults.get("supported_rev_releases", set())),
        "expected_ncd_versions": sorted(defaults.get("expected_ncd_versions", set())),
    }
    with DEFAULTS_FILE_PATH.open("w", encoding="utf-8") as file_obj:
        json.dump(normalized, file_obj, ensure_ascii=True, indent=2)
        file_obj.write("\n")


def add_default_values(list_name: str, values: list[str]) -> tuple[list[str], list[str]]:
    """Add values into one default list and persist changes.

    Returns (added_values, already_existing_values).
    """
    defaults = load_default_lists()
    if list_name not in defaults:
        raise ValueError(f"Unsupported default list: {list_name}")

    cleaned_values = [value.strip() for value in values if value.strip()]
    existing = defaults[list_name]
    added: list[str] = []
    already: list[str] = []
    for value in cleaned_values:
        if value in existing:
            already.append(value)
        else:
            existing.add(value)
            added.append(value)

    save_default_lists(defaults)
    return added, already


@dataclass(frozen=True)
class ValidationConfig:
    """Validation knobs for business-specific rules."""

    valid_car_lines: set[str] = field(default_factory=lambda: set(BASE_VALID_CAR_LINES))
    supported_rev_releases: set[str] = field(
        default_factory=lambda: set(BASE_SUPPORTED_REV_RELEASES)
    )
    expected_ncd_versions: set[str] = field(
        default_factory=lambda: set(BASE_EXPECTED_NCD_VERSIONS)
    )
    expected_project: str = "gen7"
    min_session_datetime_utc: datetime = datetime(2020, 1, 1, tzinfo=timezone.utc)
    max_session_datetime_utc: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc).replace(microsecond=0)
    )
