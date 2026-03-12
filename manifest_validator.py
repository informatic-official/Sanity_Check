"""Validation for recording_manifest.json."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .utils import ValidationResult, is_valid_uuid


def validate_manifest_structure(data: Any, result: ValidationResult) -> dict[str, Any] | None:
    """Validate high-level JSON structure and required keys."""
    if not isinstance(data, dict):
        result.error("recording_manifest.json must be a JSON object")
        return None

    session_info = data.get("session_info")
    files = data.get("files")

    if not isinstance(session_info, dict):
        result.error("recording_manifest.json: `session_info` must be an object")
    if not isinstance(files, list):
        result.error("recording_manifest.json: `files` must be an array")

    required_session_fields = {
        "schema_type",
        "schema_version",
        "time_generated",
        "timestamp_generated",
        "session_name",
        "session_uuid",
        "batch_uuid",
        "vin",
        "recording_state",
    }
    if isinstance(session_info, dict):
        missing = sorted(required_session_fields - session_info.keys())
        if missing:
            result.error(
                "recording_manifest.json: missing fields in session_info: "
                + ", ".join(missing)
            )

        session_uuid = session_info.get("session_uuid")
        if isinstance(session_uuid, str) and not is_valid_uuid(session_uuid):
            result.error("recording_manifest.json: session_info.session_uuid invalid UUID")

    if isinstance(files, list):
        for index, entry in enumerate(files):
            if not isinstance(entry, dict):
                result.error(f"recording_manifest.json: files[{index}] must be an object")
                continue
            for field in ("storage_partition_id", "path", "expected_size"):
                if field not in entry:
                    result.error(f"recording_manifest.json: files[{index}] missing `{field}`")
            if "path" in entry and not isinstance(entry.get("path"), str):
                result.error(f"recording_manifest.json: files[{index}].path must be string")
            if "expected_size" in entry and not isinstance(entry.get("expected_size"), int):
                result.error(
                    f"recording_manifest.json: files[{index}].expected_size must be integer"
                )

    return data


def validate_manifest_content(session_dir: Path, manifest: dict[str, Any], result: ValidationResult) -> None:
    """Validate referenced files existence, size, and detect unreferenced files."""
    files = manifest.get("files")
    if not isinstance(files, list):
        return

    referenced_rel_paths: set[str] = set()
    for index, entry in enumerate(files):
        if not isinstance(entry, dict):
            continue
        rel_path = entry.get("path")
        expected_size = entry.get("expected_size")
        if not isinstance(rel_path, str) or not isinstance(expected_size, int):
            continue

        normalized = rel_path.replace("\\", "/")
        referenced_rel_paths.add(normalized)
        absolute_path = session_dir / Path(normalized)

        if not absolute_path.exists():
            result.error(
                f"recording_manifest.json: referenced file does not exist: {normalized}"
            )
            continue

        if not absolute_path.is_file():
            result.error(
                f"recording_manifest.json: referenced path is not a file: {normalized}"
            )
            continue

        actual_size = absolute_path.stat().st_size
        if actual_size != expected_size:
            result.error(
                "recording_manifest.json: size mismatch for "
                f"{normalized}, expected={expected_size}, actual={actual_size}"
            )

    actual_rel_files: set[str] = set()
    for path in session_dir.rglob("*"):
        if path.is_file():
            actual_rel = path.relative_to(session_dir).as_posix()
            if actual_rel == "recording_manifest.json":
                continue
            actual_rel_files.add(actual_rel)

    additional = sorted(actual_rel_files - referenced_rel_paths)
    for rel_path in additional:
        result.warning(
            "recording_manifest.json: file exists in session but not referenced in manifest: "
            f"{rel_path}"
        )
