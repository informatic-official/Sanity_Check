"""Default validation configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass(frozen=True)
class ValidationConfig:
    """Validation knobs for business-specific rules."""

    valid_car_lines: set[str] = field(default_factory=lambda: {"174"})
    supported_rev_releases: set[str] = field(default_factory=lambda: {"rev-26.01"})
    expected_ncd_versions: set[str] = field(default_factory=lambda: {"26.01"})
    expected_project: str = "gen7"
    min_session_datetime_utc: datetime = datetime(2020, 1, 1, tzinfo=timezone.utc)
    max_session_datetime_utc: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc).replace(microsecond=0)
    )
