"""CLI entrypoint for session validation."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .aux_validator import validate_aux_content, validate_aux_structure
from .config import ValidationConfig, load_default_lists
from .events_validator import validate_events_content, validate_events_structure
from .manifest_validator import validate_manifest_content, validate_manifest_structure
from .utils import ValidationResult, load_json_file, parse_session_folder_name


def validate_session_folder_and_files(
    session_dir: Path, result: ValidationResult
) -> tuple[Path | None, Path | None, Path | None, tuple | None]:
    """Validate folder naming and required meta files existence."""
    parsed = parse_session_folder_name(session_dir)
    result.check(
        "session folder name schema",
        parsed is not None,
        f"folder={session_dir.name}",
    )
    if parsed is None:
        result.error(
            "Session folder name must follow `session_<YYYY-MM-DD_HH-MM-SS>_<uuid>`"
        )
        return None, None, None, None

    manifest_path = session_dir / "recording_manifest.json"
    aux_path = session_dir / "meta-data" / "aux_info.json"
    events_path = session_dir / "meta-data" / "events.json"

    for required in (manifest_path, aux_path, events_path):
        result.check("required file exists", required.exists(), f"path={required}")
        if not required.exists():
            result.error(f"Required file missing: {required}")

    return manifest_path, aux_path, events_path, parsed


def run_validation(
    session_dir: Path, config: ValidationConfig, verbose: bool = False
) -> ValidationResult:
    """Run all validation checks for one session directory."""
    result = ValidationResult(verbose=verbose)

    manifest_path, aux_path, events_path, parsed = validate_session_folder_and_files(
        session_dir, result
    )
    if parsed is None or manifest_path is None or aux_path is None or events_path is None:
        return result

    session_dt, folder_uuid = parsed

    timestamp_range_ok = (
        config.min_session_datetime_utc
        <= session_dt
        <= config.max_session_datetime_utc
    )
    result.check(
        "session folder timestamp within configured range",
        timestamp_range_ok,
        f"folder={session_dt.isoformat()}, min={config.min_session_datetime_utc.isoformat()}, max={config.max_session_datetime_utc.isoformat()}",
    )
    if not timestamp_range_ok:
        result.error("Session folder timestamp is outside configured allowed range")

    try:
        manifest_raw = load_json_file(manifest_path)
    except Exception as exc:  # noqa: BLE001
        result.error(f"Failed to load recording_manifest.json: {exc}")
        manifest_raw = None

    try:
        aux_raw = load_json_file(aux_path)
    except Exception as exc:  # noqa: BLE001
        result.error(f"Failed to load aux_info.json: {exc}")
        aux_raw = None

    try:
        events_raw = load_json_file(events_path)
    except Exception as exc:  # noqa: BLE001
        result.error(f"Failed to load events.json: {exc}")
        events_raw = None

    if manifest_raw is not None:
        manifest = validate_manifest_structure(manifest_raw, result)
        if manifest is not None:
            session_info = manifest.get("session_info", {})
            session_name_match = session_info.get("session_name") == session_dir.name
            result.check(
                "manifest session_name matches folder",
                session_name_match,
                f"manifest={session_info.get('session_name')}, folder={session_dir.name}",
            )
            if not session_name_match:
                result.error(
                    "recording_manifest.json: session_info.session_name mismatch with folder"
                )
            session_uuid_match = session_info.get("session_uuid") == folder_uuid
            result.check(
                "manifest session_uuid matches folder UUID",
                session_uuid_match,
                f"manifest={session_info.get('session_uuid')}, folder={folder_uuid}",
            )
            if not session_uuid_match:
                result.error(
                    "recording_manifest.json: session_info.session_uuid mismatch with folder"
                )
            validate_manifest_content(session_dir, manifest, result)

    if manifest_raw is not None and aux_raw is not None:
        session_info = manifest_raw.get("session_info")
        manifest_vin = session_info.get("vin") if isinstance(session_info, dict) else None
        aux_vin = aux_raw.get("vin") if isinstance(aux_raw, dict) else None
        if isinstance(manifest_vin, str) and isinstance(aux_vin, str):
            result.check(
                "manifest VIN matches aux VIN",
                manifest_vin == aux_vin,
                f"manifest={manifest_vin}, aux={aux_vin}",
            )
            if manifest_vin != aux_vin:
                result.error(
                    "VIN mismatch: recording_manifest.json session_info.vin "
                    f"({manifest_vin}) != aux_info.json vin ({aux_vin})"
                )

    start_timestamp_us = None
    end_timestamp_us = None
    if aux_raw is not None:
        aux = validate_aux_structure(aux_raw, result)
        if aux is not None:
            start_timestamp_us, end_timestamp_us = validate_aux_content(
                aux, session_dir, session_dt, folder_uuid, config, result
            )

    if events_raw is not None:
        events = validate_events_structure(events_raw, result)
        if events is not None:
            validate_events_content(
                events,
                folder_uuid,
                start_timestamp_us,
                end_timestamp_us,
                result,
            )

    return result


def build_parser() -> argparse.ArgumentParser:
    """Build command-line parser."""
    parser = argparse.ArgumentParser(description="Validate recording session folder")
    parser.add_argument("session_dir", type=Path, help="Path to session_<timestamp>_<uuid>")
    parser.add_argument(
        "--valid-car-lines",
        nargs="*",
        default=None,
        help="Allowed car-line values",
    )
    parser.add_argument(
        "--supported-rev-releases",
        nargs="*",
        default=None,
        help="Allowed rev-release values",
    )
    parser.add_argument(
        "--expected-ncd-versions",
        nargs="*",
        default=None,
        help="Allowed ncd-version values",
    )
    parser.add_argument(
        "--expected-project",
        default="gen7",
        help="Expected project string",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print detailed PASS/FAIL information for each validation rule",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Alias of --verbose",
    )
    return parser


def main() -> int:
    """CLI main."""
    parser = build_parser()
    args = parser.parse_args()

    session_dir = args.session_dir
    if not session_dir.exists() or not session_dir.is_dir():
        print(f"ERROR: session directory not found: {session_dir}")
        return 2

    defaults = load_default_lists()
    valid_car_lines = (
        set(args.valid_car_lines)
        if args.valid_car_lines is not None
        else defaults["valid_car_lines"]
    )
    supported_rev_releases = (
        set(args.supported_rev_releases)
        if args.supported_rev_releases is not None
        else defaults["supported_rev_releases"]
    )
    expected_ncd_versions = (
        set(args.expected_ncd_versions)
        if args.expected_ncd_versions is not None
        else defaults["expected_ncd_versions"]
    )

    config = ValidationConfig(
        valid_car_lines=valid_car_lines,
        supported_rev_releases=supported_rev_releases,
        expected_ncd_versions=expected_ncd_versions,
        expected_project=args.expected_project,
    )
    verbose_mode = bool(args.verbose or args.debug)
    result = run_validation(session_dir, config, verbose=verbose_mode)

    if result.errors:
        print("Validation FAILED")
        for message in result.errors:
            print(f"  ERROR: {message}")
    else:
        print("Validation PASSED")

    for message in result.warnings:
        print(f"  WARN: {message}")
    for message in result.infos:
        print(f"  INFO: {message}")

    return 1 if result.errors else 0


if __name__ == "__main__":
    sys.exit(main())
