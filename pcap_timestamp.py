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
    • Timestamp resolution handling (microsecond & nanosecond)
    • IDB if_tsresol option parsing per interface
    • OPB (Obsolete Packet Block) support
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
# Constants
# ==========================================================
# PCAPNG Block Types
_BT_SHB  = 0x0A0D0D0A  # Section Header Block
_BT_IDB  = 0x00000001  # Interface Description Block
_BT_OPB  = 0x00000002  # Obsolete Packet Block
_BT_SPB  = 0x00000003  # Simple Packet Block (no timestamp)
_BT_EPB  = 0x00000006  # Enhanced Packet Block

# PCAPNG Option Codes
_OPT_ENDOFOPT  = 0
_IDB_OPT_TSRESOL = 9   # if_tsresol option in IDB

# Default PCAPNG timestamp resolution: 10^-6 (microseconds)
_DEFAULT_TSRESOL_EXPONENT = 6
_MAX_SANE_BLOCK_LENGTH = 256 * 1024 * 1024  # 256 MB sanity cap


# ==========================================================
# Helper: Exact Byte Reader
# ==========================================================
def _read_exact(f, n: int) -> bytes:
    """
    Read exactly 'n' bytes from file object 'f'.

    f.read(n) may return fewer than n bytes without raising an error
    (e.g. at end-of-file). For binary protocol parsing, incomplete
    reads indicate corruption or truncation.

    Raises:
        EOFError if fewer than n bytes are read.
    """
    data = f.read(n)
    if len(data) != n:
        raise EOFError(f"Expected {n} bytes, got {len(data)} (truncated file).")
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
# Helper: Decode if_tsresol option value → scale factor
# ==========================================================
def _tsresol_to_scale(tsresol_byte: int) -> float:
    """
    Convert a single if_tsresol byte to the corresponding
    number of timestamp units per second.

    PCAPNG spec:
        bit 7 == 0 → resolution = 10^(-tsresol_byte & 0x7F)   (decimal)
        bit 7 == 1 → resolution = 2^(-(tsresol_byte & 0x7F))  (binary)

    Returns the divisor to convert raw ts_64 → seconds.
    e.g., tsresol=6 → 1_000_000 (microseconds)
          tsresol=9 → 1_000_000_000 (nanoseconds)
    """
    magnitude = tsresol_byte & 0x7F
    if tsresol_byte & 0x80:
        return float(1 << magnitude)   # 2^magnitude
    else:
        return float(10 ** magnitude)  # 10^magnitude


# ==========================================================
# Helper: Parse PCAPNG Options TLV list
# ==========================================================
def _parse_options(data: bytes, endian: str) -> dict:
    """
    Parse the options section of a PCAPNG block.

    Options are encoded as TLV (Type-Length-Value) records,
    each padded to a 4-byte boundary:
        uint16 option_code
        uint16 option_length
        uint8[option_length] option_value  (+ padding)

    Returns a dict mapping option_code → list of raw value bytes.
    """
    options: dict[int, list[bytes]] = {}
    offset = 0
    fmt = endian + "HH"
    fmt_size = struct.calcsize(fmt)

    while offset + fmt_size <= len(data):
        code, length = struct.unpack_from(fmt, data, offset)
        offset += fmt_size

        if code == _OPT_ENDOFOPT:
            break

        value = data[offset: offset + length]
        options.setdefault(code, []).append(value)

        # Advance past value + 4-byte padding
        padded = (length + 3) & ~3
        offset += padded

    return options


# ==========================================================
# PCAP Parsing
# ==========================================================
def _parse_pcap_time_bounds(path: str) -> dict:
    """
    Parse a classic PCAP file and return timestamp bounds.

    PCAP File Layout:
    -----------------
        Global Header (24 bytes)
        [ Packet Header (16 bytes) + Packet Data (incl_len bytes) ] * N

    Global Header (24 bytes):
        uint32 magic_number
        uint16 version_major
        uint16 version_minor
        int32  thiszone
        uint32 sigfigs
        uint32 snaplen
        uint32 network

    Packet Header (16 bytes):
        uint32 ts_sec
        uint32 ts_frac   (microseconds or nanoseconds)
        uint32 incl_len  (captured length)
        uint32 orig_len  (original length)
    """
    with open(path, "rb") as f:

        # --------------------------------------------------
        # 1. Read & Validate Global Header (24 bytes)
        # --------------------------------------------------
        global_header = _read_exact(f, 24)

        magic_raw = global_header[:4]
        magic_be = struct.unpack(">I", magic_raw)[0]
        magic_le = struct.unpack("<I", magic_raw)[0]

        if magic_be in (0xA1B2C3D4, 0xA1B23C4D):
            endian = ">"
            magic = magic_be
        elif magic_le in (0xA1B2C3D4, 0xA1B23C4D):
            endian = "<"
            magic = magic_le
        else:
            raise CaptureParseError(
                f"Invalid PCAP magic number: 0x{magic_raw.hex().upper()}"
            )

        # 0xA1B23C4D → nanosecond resolution; 0xA1B2C3D4 → microsecond
        is_nanosecond = (magic == 0xA1B23C4D)
        scale = 1_000_000_000 if is_nanosecond else 1_000_000

        # Extract snaplen from global header for sanity-checking incl_len
        snaplen = struct.unpack(endian + "I", global_header[16:20])[0]
        # A snaplen of 0 means "no limit" in some tools; use a safe upper bound
        max_incl_len = snaplen if snaplen > 0 else 262144

        # --------------------------------------------------
        # 2. Precompile Packet Header Struct for Performance
        # --------------------------------------------------
        pkt_hdr_struct = struct.Struct(endian + "IIII")

        first_ts = None
        last_ts = None

        # --------------------------------------------------
        # 3. Iterate Over All Packets
        # --------------------------------------------------
        while True:
            # FIX: use try/except EOFError for clean loop termination
            # instead of manually checking len(header_bytes)
            try:
                header_bytes = _read_exact(f, 16)
            except EOFError:
                break

            ts_sec, ts_frac, incl_len, _orig_len = \
                pkt_hdr_struct.unpack(header_bytes)

            # FIX: Guard against corrupt incl_len allocating huge memory
            if incl_len > max_incl_len:
                raise CaptureParseError(
                    f"Packet incl_len ({incl_len}) exceeds snaplen "
                    f"({max_incl_len}). File may be corrupt."
                )

            # OPT: seek past payload instead of reading it into memory
            if incl_len:
                f.seek(incl_len, os.SEEK_CUR)

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
# PCAPNG Parsing
# ==========================================================
def _parse_pcapng_time_bounds(path: str) -> dict:
    """
    Parse a PCAPNG file and extract timestamp bounds.

    PCAPNG is block-based. Each block has the layout:
        uint32 Block Type
        uint32 Block Total Length   (entire block including these two fields
                                     AND the trailing copy of Block Total Length)
        uint8[...] Block Body
        uint32 Block Total Length   (trailing copy for backward traversal)

    Block types handled:
        SHB (0x0A0D0D0A) – Section Header, sets endianness
        IDB (0x00000001) – Interface Description, may carry if_tsresol
        EPB (0x00000006) – Enhanced Packet Block, primary packet carrier
        OPB (0x00000002) – Obsolete Packet Block, also carries timestamps
        SPB (0x00000003) – Simple Packet Block, NO timestamp → skipped

    FIX: Previously the SHB trailing bytes were not consumed, which
    shifted the file pointer and corrupted all subsequent block reads.

    FIX: IDB if_tsresol option is now parsed per-interface so that
    nanosecond-resolution captures are handled correctly.

    FIX: OPB timestamps are now extracted.
    """
    with open(path, "rb") as f:

        # --------------------------------------------------
        # 1. Read & Validate Section Header Block
        # --------------------------------------------------
        # We need at least 12 bytes to read block_type + block_length
        # + byte_order_magic before we know endianness.
        shb_prefix = _read_exact(f, 12)

        block_type = struct.unpack("<I", shb_prefix[:4])[0]
        if block_type != _BT_SHB:
            raise CaptureParseError(
                f"Expected Section Header Block (0x0A0D0D0A), "
                f"got 0x{block_type:08X}."
            )

        # Byte-order magic at offset 8 determines endianness
        bom = shb_prefix[8:12]
        if bom == b"\x1a\x2b\x3c\x4d":
            endian = ">"
        elif bom == b"\x4d\x3c\x2b\x1a":
            endian = "<"
        else:
            raise CaptureParseError(
                f"Invalid PCAPNG byte-order magic: {bom.hex()}"
            )

        # Now re-read block_length with correct endianness
        shb_length = struct.unpack(endian + "I", shb_prefix[4:8])[0]
        if shb_length < 28:
            raise CaptureParseError(
                f"SHB block_length {shb_length} is too small (minimum 28)."
            )

        # FIX: Consume the remainder of SHB so the file pointer is correct.
        # Already read 12 bytes; skip the rest (including trailing length copy).
        f.seek(shb_length - 12, os.SEEK_CUR)

        # --------------------------------------------------
        # 2. Per-interface timestamp resolution table
        # --------------------------------------------------
        # Maps interface_id (0-based) → divisor (units per second)
        iface_tsresol: dict[int, float] = {}

        def _get_tsresol(iface_id: int) -> float:
            """Return divisor for given interface, defaulting to 1e6 (µs)."""
            return iface_tsresol.get(
                iface_id,
                10 ** _DEFAULT_TSRESOL_EXPONENT
            )

        first_ts = None
        last_ts = None

        # --------------------------------------------------
        # 3. Iterate Through All Blocks
        # --------------------------------------------------
        blk_hdr_struct = struct.Struct(endian + "II")

        while True:
            hdr = f.read(8)
            if not hdr:
                break  # Clean EOF
            if len(hdr) != 8:
                raise CaptureParseError("Truncated block header.")

            block_type, block_length = blk_hdr_struct.unpack(hdr)

            # FIX: Sanity-check block_length before any allocation
            if block_length < 12:
                raise CaptureParseError(
                    f"Block length {block_length} is impossibly small "
                    f"(minimum 12 bytes for type+length+length)."
                )
            if block_length > _MAX_SANE_BLOCK_LENGTH:
                raise CaptureParseError(
                    f"Block length {block_length} exceeds sanity cap "
                    f"({_MAX_SANE_BLOCK_LENGTH} bytes). File may be corrupt."
                )

            # FIX: PCAPNG block lengths must be a multiple of 4
            if block_length % 4 != 0:
                raise CaptureParseError(
                    f"Block length {block_length} is not 4-byte aligned."
                )

            # Read remainder of block (body + trailing length copy)
            remainder = _read_exact(f, block_length - 8)

            # Block body = remainder minus the trailing 4-byte length copy
            block_body = remainder[: block_length - 12]

            # ----------------------------------------------
            # SHB inside the stream → new section, reset iface table
            # ----------------------------------------------
            if block_type == _BT_SHB:
                iface_tsresol.clear()
                continue

            # ----------------------------------------------
            # IDB – parse if_tsresol option
            # ----------------------------------------------
            elif block_type == _BT_IDB:
                # IDB body: uint16 LinkType, uint16 Reserved, uint32 SnapLen
                # followed by options
                iface_id = len(iface_tsresol)  # interfaces are 0-indexed in order
                options_data = block_body[8:]   # skip fixed 8-byte IDB fields
                opts = _parse_options(options_data, endian)

                if _IDB_OPT_TSRESOL in opts:
                    tsresol_bytes = opts[_IDB_OPT_TSRESOL][0]
                    if tsresol_bytes:
                        iface_tsresol[iface_id] = _tsresol_to_scale(
                            tsresol_bytes[0]
                        )
                # If not present, _get_tsresol() will return the default 1e6

            # ----------------------------------------------
            # EPB – Enhanced Packet Block
            # ----------------------------------------------
            elif block_type == _BT_EPB:
                if len(block_body) < 20:
                    raise CaptureParseError("EPB body too short.")

                iface_id, ts_high, ts_low, _cap_len, _orig_len = \
                    struct.unpack_from(endian + "IIIII", block_body, 0)

                ts_64 = (ts_high << 32) | ts_low
                timestamp = ts_64 / _get_tsresol(iface_id)

                if first_ts is None:
                    first_ts = timestamp
                last_ts = timestamp

            # ----------------------------------------------
            # OPB – Obsolete Packet Block (FIX: was not handled before)
            # ----------------------------------------------
            elif block_type == _BT_OPB:
                # OPB body: uint16 InterfaceID, uint16 DropsCount,
                #           uint32 ts_high, uint32 ts_low,
                #           uint32 cap_len, uint32 orig_len
                if len(block_body) < 16:
                    raise CaptureParseError("OPB body too short.")

                iface_id_raw, _drops, ts_high, ts_low = \
                    struct.unpack_from(endian + "HHII", block_body, 0)

                ts_64 = (ts_high << 32) | ts_low
                timestamp = ts_64 / _get_tsresol(iface_id_raw)

                if first_ts is None:
                    first_ts = timestamp
                last_ts = timestamp

            # SPB has no timestamp – skip silently (already consumed by seek)

        if first_ts is None:
            raise CaptureParseError(
                "No timestamped packets found in PCAPNG file."
            )

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

    Returns a dict with keys:
        first_timestamp   (float, UNIX epoch)
        last_timestamp    (float, UNIX epoch)
        first_datetime    (str, ISO8601 UTC)
        last_datetime     (str, ISO8601 UTC)
        duration_seconds  (float)
    """
    ext = os.path.splitext(path.lower())[1]

    if ext == ".pcap":
        return _parse_pcap_time_bounds(path)
    elif ext == ".pcapng":
        return _parse_pcapng_time_bounds(path)
    else:
        raise CaptureParseError(
            f"Unsupported file extension '{ext}'. "
            "Expected .pcap or .pcapng"
        )


# ==========================================================
# CLI Entry Point
# ==========================================================
def main(argv: list[str]) -> int:
    """
    Command-line usage:

        python pcap_timestamp.py capture.pcap
        python pcap_timestamp.py capture.pcapng
    """
    if len(argv) != 2:
        print(f"Usage: {argv[0]} <capture.pcap|capture.pcapng>")
        return 2

    try:
        result = get_capture_time_bounds(argv[1])

        print(f"First packet: {result['first_datetime']} "
              f"({result['first_timestamp']})")
        print(f"Last packet:  {result['last_datetime']} "
              f"({result['last_timestamp']})")
        print(f"Duration:     {result['duration_seconds']:.6f} seconds")

        return 0

    except (CaptureParseError, EOFError, OSError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
