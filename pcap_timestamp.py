#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PCAP / PCAPNG Time Range Extraction Script
==========================================

Purpose:
--------
This script reads a .pcap or .pcapng capture file and extracts:

    • Timestamp of the first packet
    • Timestamp of the last packet
    • Total capture duration in seconds

Output format:
--------------
    First packet: <ISO8601 datetime> (<epoch seconds>)
    Last packet:  <ISO8601 datetime> (<epoch seconds>)
    Duration:     <seconds>

Core Concepts Covered:
----------------------
    • Binary file parsing
    • struct module usage
    • Endianness detection (big-endian vs little-endian)
    • PCAP file format structure
    • PCAPNG block-based structure
    • Timestamp resolution handling
"""

import os
import struct
import sys
from datetime import datetime, timezone


# ==========================================================
# Custom Exception for Capture Parsing Errors
# ==========================================================
class CaptureParseError(Exception):
    """
    Raised when the capture file is malformed, truncated,
    or does not conform to the expected PCAP/PCAPNG format.
    """
    pass


# ==========================================================
# Helper: Exact Byte Reader
# ==========================================================
def _read_exact(f, n: int) -> bytes:
    """
    Read exactly 'n' bytes from file object 'f'.

    Why is this necessary?
    ----------------------
    f.read(n) may return fewer than n bytes without raising an error
    (for example at end-of-file). For binary protocol parsing,
    incomplete reads indicate corruption or truncation.

    Raises:
        EOFError if fewer than n bytes are read.
    """
    data = f.read(n)
    if len(data) != n:
        raise EOFError("Unexpected end of file while reading binary structure.")
    return data


# ==========================================================
# Helper: Convert Epoch Timestamp to ISO8601 UTC
# ==========================================================
def _to_utc_iso(ts: float) -> str:
    """
    Convert a UNIX epoch timestamp (seconds) to
    an ISO8601 formatted UTC datetime string.
    """
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


# ==========================================================
# PCAP Parsing
# ==========================================================
def _parse_pcap_time_bounds(path: str) -> dict:
    """
    Parse a classic PCAP file.

    PCAP File Layout:
    -----------------
        Global Header (24 bytes)
        Packet Header (16 bytes)
        Packet Data (variable)
        Packet Header
        Packet Data
        ...

    Packet Header Structure (16 bytes):
        uint32 ts_sec
        uint32 ts_frac (microseconds or nanoseconds)
        uint32 incl_len
        uint32 orig_len
    """

    with open(path, "rb") as f:

        # --------------------------------------------------
        # 1. Read Global Header (fixed size: 24 bytes)
        # --------------------------------------------------
        global_header = _read_exact(f, 24)

        # --------------------------------------------------
        # 2. Detect Endianness via Magic Number
        # --------------------------------------------------
        # The first 4 bytes determine:
        #   - byte order
        #   - timestamp precision (microsecond / nanosecond)

        magic_be = struct.unpack(">I", global_header[:4])[0]
        magic_le = struct.unpack("<I", global_header[:4])[0]

        if magic_be in (0xA1B2C3D4, 0xA1B23C4D):
            endian = ">"
            magic = magic_be
        elif magic_le in (0xA1B2C3D4, 0xA1B23C4D):
            endian = "<"
            magic = magic_le
        else:
            raise CaptureParseError("Invalid PCAP magic number.")

        # Determine timestamp resolution
        # 0xA1B23C4D indicates nanosecond resolution
        is_nanosecond = (magic == 0xA1B23C4D)

        # --------------------------------------------------
        # 3. Prepare Packet Header Struct (precompiled)
        # --------------------------------------------------
        # Using struct.Struct improves performance
        # when unpacking many packet headers.
        packet_header_struct = struct.Struct(endian + "IIII")

        first_ts = None
        last_ts = None

        # --------------------------------------------------
        # 4. Iterate Over All Packets
        # --------------------------------------------------
        while True:
            header_bytes = f.read(16)
            if not header_bytes:
                break

            if len(header_bytes) != 16:
                raise CaptureParseError("Truncated packet header detected.")

            ts_sec, ts_frac, incl_len, _orig_len = \
                packet_header_struct.unpack(header_bytes)

            # Skip packet payload
            if incl_len:
                payload = f.read(incl_len)
                if len(payload) != incl_len:
                    raise CaptureParseError("Truncated packet payload.")

            # Compute full timestamp in seconds
            scale = 1_000_000_000 if is_nanosecond else 1_000_000
            timestamp = ts_sec + (ts_frac / scale)

            if first_ts is None:
                first_ts = timestamp
            last_ts = timestamp

        if first_ts is None:
            raise CaptureParseError("No packets found in PCAP file.")

        return {
            "first_timestamp": first_ts,
            "last_timestamp": last_ts,
            "first_datetime": _to_utc_iso(first_ts),
            "last_datetime": _to_utc_iso(last_ts),
            "duration_seconds": float(last_ts - first_ts),
        }


# ==========================================================
# PCAPNG Parsing (Simplified Time Extraction)
# ==========================================================
def _parse_pcapng_time_bounds(path: str) -> dict:
    """
    Parse a PCAPNG file and extract timestamp bounds.

    PCAPNG is block-based:
        - Section Header Block (SHB)
        - Interface Description Block (IDB)
        - Enhanced Packet Block (EPB)
        - Others...

    Only EPB blocks contain timestamps.
    """

    with open(path, "rb") as f:

        # --------------------------------------------------
        # 1. Read Section Header Block (minimum 28 bytes)
        # --------------------------------------------------
        shb = f.read(28)
        if len(shb) < 28:
            raise CaptureParseError("Truncated PCAPNG file.")

        block_type = struct.unpack("<I", shb[:4])[0]
        if block_type != 0x0A0D0D0A:
            raise CaptureParseError("Invalid PCAPNG Section Header Block.")

        # Detect endianness using byte-order magic
        byte_order_magic = shb[8:12]
        if byte_order_magic == b"\x1a\x2b\x3c\x4d":
            endian = ">"
        elif byte_order_magic == b"\x4d\x3c\x2b\x1a":
            endian = "<"
        else:
            raise CaptureParseError("Invalid PCAPNG byte-order magic.")

        first_ts = None
        last_ts = None

        # --------------------------------------------------
        # 2. Iterate Through Blocks
        # --------------------------------------------------
        while True:
            header = f.read(8)
            if not header:
                break

            block_type, block_length = \
                struct.unpack(endian + "II", header)

            body = _read_exact(f, block_length - 8)
            block_body = body[: block_length - 12]

            # Enhanced Packet Block
            if block_type == 0x00000006:

                iface_id, ts_high, ts_low, cap_len, _orig_len = \
                    struct.unpack_from(endian + "IIIII", block_body, 0)

                # Combine 64-bit timestamp
                ts_64 = (ts_high << 32) | ts_low

                # Default PCAPNG resolution = 1e-6 seconds
                timestamp = ts_64 * 1e-6

                if first_ts is None:
                    first_ts = timestamp
                last_ts = timestamp

        if first_ts is None:
            raise CaptureParseError("No timestamped packets found in PCAPNG.")

        return {
            "first_timestamp": first_ts,
            "last_timestamp": last_ts,
            "first_datetime": _to_utc_iso(first_ts),
            "last_datetime": _to_utc_iso(last_ts),
            "duration_seconds": float(last_ts - first_ts),
        }


# ==========================================================
# Public Entry Function
# ==========================================================
def get_capture_time_bounds(path: str) -> dict:
    """
    Dispatch parsing based on file extension.
    """
    ext = os.path.splitext(path.lower())[1]

    if ext == ".pcap":
        return _parse_pcap_time_bounds(path)
    elif ext == ".pcapng":
        return _parse_pcapng_time_bounds(path)
    else:
        raise CaptureParseError("Unsupported capture file format.")


# ==========================================================
# CLI Entry Point
# ==========================================================
def main(argv: list[str]) -> int:
    """
    Command-line usage:

        python script.py capture.pcap
        python script.py capture.pcapng
    """

    if len(argv) != 2:
        print(f"Usage: {argv[0]} <capture.pcap|capture.pcapng>")
        return 2

    try:
        result = get_capture_time_bounds(argv[1])

        print(f"First packet: {result['first_datetime']} ({result['first_timestamp']})")
        print(f"Last packet:  {result['last_datetime']} ({result['last_timestamp']})")
        print(f"Duration:     {result['duration_seconds']:.2f} seconds")

        return 0

    except Exception as e:
        print(f"Error: {e}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
