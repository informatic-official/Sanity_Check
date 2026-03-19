"""CLI for managing persistent default validation lists."""

from __future__ import annotations

import argparse
import sys

from .config import DEFAULTS_FILE_PATH, add_default_values, load_default_lists

LIST_NAME_MAP = {
    "car-line": "valid_car_lines",
    "ncd-version": "expected_ncd_versions",
    "rev-release": "supported_rev_releases",
}


def build_parser() -> argparse.ArgumentParser:
    """Create CLI parser."""
    parser = argparse.ArgumentParser(description="Manage validator default lists")
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list", help="Show current default lists")
    list_parser.add_argument(
        "--target",
        choices=sorted(LIST_NAME_MAP.keys()),
        help="Optional single list to print",
    )

    add_parser = subparsers.add_parser("add", help="Add values into one default list")
    add_parser.add_argument(
        "--target",
        required=True,
        choices=sorted(LIST_NAME_MAP.keys()),
        help="Which list to update",
    )
    add_parser.add_argument(
        "values",
        nargs="+",
        help="One or more values to add",
    )
    return parser


def cmd_list(target: str | None) -> int:
    """Handle list command."""
    defaults = load_default_lists()
    if target is not None:
        key = LIST_NAME_MAP[target]
        print(f"{target}: {sorted(defaults[key])}")
        return 0

    print(f"defaults_file: {DEFAULTS_FILE_PATH}")
    for label, key in LIST_NAME_MAP.items():
        print(f"{label}: {sorted(defaults[key])}")
    return 0


def cmd_add(target: str, values: list[str]) -> int:
    """Handle add command."""
    key = LIST_NAME_MAP[target]
    added, already = add_default_values(key, values)
    if added:
        print(f"Added to {target}: {added}")
    if already:
        print(f"Already existed in {target}: {already}")
    if not added and not already:
        print("No valid values to add")
        return 1
    print(f"Saved defaults to: {DEFAULTS_FILE_PATH}")
    return 0


def main() -> int:
    """Entry point."""
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "list":
        return cmd_list(args.target)
    if args.command == "add":
        return cmd_add(args.target, args.values)
    return 2


if __name__ == "__main__":
    sys.exit(main())
