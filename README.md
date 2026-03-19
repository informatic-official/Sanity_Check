# Session Validator

Lightweight Python validator for recording session folders with this structure:

- `session_<UTC_TIMESTAMP>_<UUID>/recording_manifest.json`
- `session_<UTC_TIMESTAMP>_<UUID>/meta-data/aux_info.json`
- `session_<UTC_TIMESTAMP>_<UUID>/meta-data/events.json`

## What it validates

### 1) Session folder naming

- Folder name matches: `session_<YYYY-MM-DD_HH-MM-SS>_<UUID>`
- Timestamp format is valid
- UUID format is valid
- Folder timestamp is within a configurable UTC time range

### 2) Required files existence

- `recording_manifest.json`
- `meta-data/aux_info.json`
- `meta-data/events.json`

### 3) JSON formal structure checks

- Basic required keys and expected value types in all three meta files

### 4) recording_manifest.json content checks

- Session name / UUID match folder name
- VIN in `recording_manifest.json` matches VIN in `aux_info.json`
- Referenced files exist
- Referenced files match `expected_size`
- Additional files in session folder not referenced by manifest are reported as warnings

### 5) aux_info.json content checks

- `session-uuid` is valid UUID v7
- `session-name` and `session-uuid` match the session folder
- `start-time` ↔ `start-timestamp-utc-us` consistency
- `end-time` ↔ `end-timestamp-utc-us` consistency
- UTC-string and epoch comparison is normalized to millisecond precision
- `duration == (end-timestamp-utc-us - start-timestamp-utc-us) / 1_000_000`
- Session folder timestamp matches `start-time` using lower precision alignment
- VIN validation using ISO 3779 checksum
- `car-line` is in allowed list
- `rev-release` is in supported list
- `ncd-version` is in expected list
- `project` matches expected value (`gen7` by default)

### 6) events.json content checks

- Event `session_uuid` is valid UUID v7
- Event `session_uuid` matches the session folder UUID
- `begin_timestamp == end_timestamp`
- Event timestamps are within the session `[start, end]` window from `aux_info.json`

## Requirements

- Python 3.10+ (tested on Python 3.14)

## Run

From the workspace root (example for this repository):

```powershell
python -m session_validator.validate_session "C:\path\to\session_<UTC_TIMESTAMP>_<UUID>"
```

## Configurable options

You can override business-specific lists from CLI:

```powershell
python -m session_validator.validate_session "<session_dir>" \
  --valid-car-lines 174 177 \
  --supported-rev-releases rev-26.01 rev-26.02 \
  --expected-ncd-versions 26.01 26.02 \
  --expected-project gen7 \
  --verbose
```

Defaults are defined in `config.py`:

- `valid_car_lines = {"174"}`
- `supported_rev_releases = {"rev-25.01"}`
- `expected_ncd_versions = {"25.05"}`
- `expected_project = "gen7"`

Persistent default-list management from terminal:

```powershell
python -m session_validator.manage_defaults list
python -m session_validator.manage_defaults add --target car-line 177 178
python -m session_validator.manage_defaults add --target ncd-version 26.01
python -m session_validator.manage_defaults add --target rev-release rev-26.01
```

Notes:

- Managed values are saved in `session_validator/defaults.json`.
- `validate_session` uses these persisted defaults when corresponding CLI list options are not provided.

Debug/verbose output:

- `--verbose`: print detailed per-rule PASS/FAIL checks with concrete values
- `--debug`: alias of `--verbose`

## Exit code

- `0`: Validation passed (no errors)
- `1`: Validation failed (one or more errors)
- `2`: Invalid CLI usage (for example, session folder not found)

## Notes

- Warnings do not fail validation (for example, additional unreferenced files).
- The validator focuses on schema-like structural checks and business-rule checks requested for session sanity verification.
