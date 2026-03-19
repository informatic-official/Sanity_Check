"""Utility helpers for validators."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID


SESSION_DIR_PATTERN = re.compile(
    r"^session_(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})_"
    r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$"
)


@dataclass
class ValidationResult:
    """Collects validation findings."""

    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    infos: list[str] = field(default_factory=list)
    verbose: bool = False

    def error(self, message: str) -> None:
        self.errors.append(message)

    def warning(self, message: str) -> None:
        self.warnings.append(message)

    def info(self, message: str) -> None:
        self.infos.append(message)

    def check(self, name: str, passed: bool, detail: str | None = None) -> None:
        """Record per-rule pass/fail detail in verbose mode."""
        if not self.verbose:
            return
        status = "PASS" if passed else "FAIL"
        suffix = f" | {detail}" if detail else ""
        self.infos.append(f"{status}: {name}{suffix}")

    @property
    def ok(self) -> bool:
        return not self.errors


def parse_session_folder_name(session_path: Path) -> tuple[datetime, str] | None:
    """Parse folder name `session_<timestamp>_<uuid>` and return UTC datetime + UUID."""
    match = SESSION_DIR_PATTERN.match(session_path.name)
    if not match:
        return None
    timestamp_text, uuid_text = match.groups()
    try:
        dt = datetime.strptime(timestamp_text, "%Y-%m-%d_%H-%M-%S").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return None
    return dt, uuid_text


def is_valid_uuid(text: str) -> bool:
    """Check canonical UUID format."""
    try:
        parsed = UUID(text)
    except ValueError:
        return False
    return str(parsed) == text.lower()


def is_valid_uuid_v7(text: str) -> bool:
    """Check UUID format and version=7."""
    try:
        parsed = UUID(text)
    except ValueError:
        return False
    return str(parsed) == text.lower() and parsed.version == 7


def parse_iso_datetime_utc(text: str) -> datetime | None:
    """Parse ISO datetime text and normalize to UTC."""
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def datetime_to_epoch_us(dt: datetime) -> int:
    """Convert datetime to unix epoch in microseconds."""
    return int(dt.timestamp() * 1_000_000)


def datetime_to_epoch_ms(dt: datetime) -> int:
    """Convert datetime to unix epoch in milliseconds."""
    return int(dt.timestamp() * 1_000)


def epoch_us_to_ms(epoch_us: int) -> int:
    """Convert unix epoch microseconds to milliseconds by truncation."""
    return epoch_us // 1_000


def load_json_file(path: Path) -> Any:
    """Load JSON from file path."""
    import json

    with path.open("r", encoding="utf-8") as file_obj:
        return json.load(file_obj)


_VIN_TRANSLITERATION = {
    **{str(i): i for i in range(10)},
    "A": 1,
    "B": 2,
    "C": 3,
    "D": 4,
    "E": 5,
    "F": 6,
    "G": 7,
    "H": 8,
    "J": 1,
    "K": 2,
    "L": 3,
    "M": 4,
    "N": 5,
    "P": 7,
    "R": 9,
    "S": 2,
    "T": 3,
    "U": 4,
    "V": 5,
    "W": 6,
    "X": 7,
    "Y": 8,
    "Z": 9,
}

_VIN_WEIGHTS = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2]


def is_valid_vin(vin: str) -> bool:
    """Validate VIN with ISO 3779 checksum and character rules."""
    if len(vin) != 17:
        return False
    vin = vin.upper()
    if any(char in {"I", "O", "Q"} for char in vin):
        return False
    if not re.fullmatch(r"[A-HJ-NPR-Z0-9]{17}", vin):
        return False

    total = 0
    for index, char in enumerate(vin):
        value = _VIN_TRANSLITERATION.get(char)
        if value is None:
            return False
        total += value * _VIN_WEIGHTS[index]

    check_digit = total % 11
    expected = "X" if check_digit == 10 else str(check_digit)
    return vin[8] == expected
