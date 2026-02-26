#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PCAP / PCAPNG Time Range Extraction Script
==========================================

This script reads a .pcap or .pcapng capture file and extracts:
    • Timestamp of the first packet (by file order)
    • Timestamp of the last packet (by file order)
    • Total capture duration in seconds

Output format:
    First packet: <ISO8601 datetime> (<epoch seconds>)
    Last packet:  <ISO8601 datetime> (<epoch seconds>)
    Duration:     <seconds>

Highlights / Robustness Features:
    • Magic-number based format detection (extension is only a fallback)
    • PCAP: supports microsecond and nanosecond variants; skips payload via seek
    • PCAPNG: block-stream parsing with:
        - SHB re-detection inside the stream (multi-section files)
        - per-interface if_tsresol handling (decimal + binary)
        - block trailer-length validation
        - large packet blocks handled without reading full payload into memory
    • Defensive checks: 4-byte alignment, minimum sizes, sanity caps
    • Out-of-order timestamp detection with explicit warning
"""

import os
import struct
import sys
from datetime import datetime, timezone


# ==========================================================
# Custom Exception for Capture Parsing Errors
# ==========================================================
class CaptureParseError(Exception):
    """Raised when the capture file is malformed, truncated, or unexpected."""
    pass


# ==========================================================
# Constants
# ==========================================================
# PCAPNG Block Types
_BT_SHB = 0x0A0D0D0A  # Section Header Block
_BT_IDB = 0x00000001  # Interface Description Block
_BT_OPB = 0x00000002  # Obsolete Packet Block
_BT_SPB = 0x00000003  # Simple Packet Block (no timestamp)
_BT_EPB = 0x00000006  # Enhanced Packet Block

# PCAPNG Option Codes
_OPT_ENDOFOPT = 0
_IDB_OPT_TSRESOL = 9  # if_tsresol option in IDB

# Default PCAPNG timestamp resolution: 10^-6 (microseconds)
_DEFAULT_TSRESOL_EXPONENT = 6
_MAX_SANE_BLOCK_LENGTH = 256 * 1024 * 1024  # 256 MB sanity cap


# ==========================================================
# Helper: Exact Byte Reader
# ==========================================================
def _read_exact(f, n: int) -> bytes:
    """Read exactly n bytes or raise EOFError."""
    data = f.read(n)
    if len(data) != n:
        raise EOFError(f"Expected {n} bytes, got {len(data)} (truncated file).")
    return data


# ==========================================================
# Helper: Convert Epoch Timestamp to ISO8601 UTC
# ==========================================================
def _to_utc_iso(ts: float) -> str:
    """Convert UNIX epoch seconds to ISO8601 UTC string."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


# ==========================================================
# Helper: Decode if_tsresol option value → scale factor (units per second)
# ==========================================================
def _tsresol_to_scale(tsresol_byte: int) -> float:
    """
    Convert a single if_tsresol byte to units-per-second.

    PCAPNG spec:
        bit 7 == 0 → resolution = 10^(-m) where m = (byte & 0x7F)
        bit 7 == 1 → resolution = 2^(-m)  where m = (byte & 0x7F)

    We return the divisor to convert raw ts_64 → seconds:
        seconds = ts_64 / divisor
    """
    magnitude = tsresol_byte & 0x7F
    if tsresol_byte & 0x80:
        # binary resolution: 2^-m seconds per tick => ticks per second = 2^m
        return float(1 << magnitude)
    else:
        # decimal resolution: 10^-m seconds per tick => ticks per second = 10^m
        return float(10 ** magnitude)


# ==========================================================
# Helper: Parse PCAPNG Options TLV list
# ==========================================================
def _parse_options(data: bytes, endian: str) -> dict:
    """
    Parse PCAPNG options encoded as TLV with 32-bit padding.

    Returns: dict mapping option_code -> list[raw_value_bytes]
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

        # Advance past value + padding to 4-byte boundary
        padded = (length + 3) & ~3
        offset += padded

    return options


# ==========================================================
# Helper: sniff format by magic number
# ==========================================================
def _sniff_capture_format(path: str) -> str:
    """
    Return "pcap" or "pcapng" based on file magic number.
    Falls back to extension only if magic is unknown.
    """
    with open(path, "rb") as f:
        b = f.read(4)
        if len(b) < 4:
            raise CaptureParseError("File too small to be a valid capture.")

        # PCAPNG: block type of SHB at file start
        if b == b"\x0a\x0d\x0d\x0a":
            return "pcapng"

        # PCAP magic numbers (microsecond / nanosecond, both endians)
        if b in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4",  # us
                 b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):  # ns
            return "pcap"

    # fallback: extension (outside with-block; file already closed above)
    ext = os.path.splitext(path.lower())[1]
    if ext == ".pcapng":
        return "pcapng"
    if ext == ".pcap":
        return "pcap"
    raise CaptureParseError("Unsupported/unknown capture format (magic + extension).")


# ==========================================================
# PCAP Parsing
# ==========================================================
def _parse_pcap_time_bounds(path: str) -> dict:
    """Parse classic PCAP and return timestamp bounds (first/last by file order)."""
    with open(path, "rb") as f:
        gh = _read_exact(f, 24)
        magic_raw = gh[:4]
        magic_be = struct.unpack(">I", magic_raw)[0]
        magic_le = struct.unpack("<I", magic_raw)[0]

        if magic_be in (0xA1B2C3D4, 0xA1B23C4D):
            endian = ">"
            magic = magic_be
        elif magic_le in (0xA1B2C3D4, 0xA1B23C4D):
            endian = "<"
            magic = magic_le
        else:
            raise CaptureParseError(f"Invalid PCAP magic number: 0x{magic_raw.hex().upper()}")

        # 0xA1B23C4D → nanosecond; 0xA1B2C3D4 → microsecond
        is_nanosecond = (magic == 0xA1B23C4D)
        scale = 1_000_000_000 if is_nanosecond else 1_000_000

        snaplen = struct.unpack(endian + "I", gh[16:20])[0]
        max_incl_len = snaplen if snaplen > 0 else 262144

        pkt_hdr_struct = struct.Struct(endian + "IIII")
        first_ts = None
        last_ts = None

        while True:
            try:
                header_bytes = _read_exact(f, 16)
            except EOFError:
                break

            ts_sec, ts_frac, incl_len, _orig_len = pkt_hdr_struct.unpack(header_bytes)

            if incl_len > max_incl_len:
                raise CaptureParseError(
                    f"Packet incl_len ({incl_len}) exceeds snaplen ({max_incl_len}). File may be corrupt."
                )

            if incl_len:
                f.seek(incl_len, os.SEEK_CUR)

            timestamp = ts_sec + (ts_frac / scale)

            if first_ts is None:
                first_ts = timestamp
            last_ts = timestamp

        if first_ts is None:
            raise CaptureParseError("No packets found in PCAP file.")

        if last_ts < first_ts:
            import warnings
            warnings.warn(
                f"Out-of-order timestamps detected: last packet ({last_ts}) is "
                f"earlier than first ({first_ts}). Duration clamped to 0.",
                stacklevel=2,
            )
        duration = max(0.0, float(last_ts - first_ts))

        return {
            "first_timestamp": first_ts,
            "last_timestamp": last_ts,
            "first_datetime": _to_utc_iso(first_ts),
            "last_datetime": _to_utc_iso(last_ts),
            "duration_seconds": duration,
        }


# ==========================================================
# PCAPNG Parsing
# ==========================================================
def _parse_pcapng_time_bounds(path: str, *, strict_iface: bool = False) -> dict:
    """
    Parse a PCAPNG file and return timestamp bounds (first/last by file order).

    strict_iface:
        If True, raise if an EPB/OPB references an unknown interface_id.
        If False (default), fall back to default tsresol for unknown iface IDs.
    """
    with open(path, "rb") as f:
        # ---- Read initial SHB prefix to determine endianness ----
        shb_prefix = _read_exact(f, 12)

        block_type = struct.unpack("<I", shb_prefix[:4])[0]
        if block_type != _BT_SHB:
            raise CaptureParseError(
                f"Expected Section Header Block (0x0A0D0D0A), got 0x{block_type:08X}."
            )

        bom = shb_prefix[8:12]
        if bom == b"\x1a\x2b\x3c\x4d":
            endian = ">"
        elif bom == b"\x4d\x3c\x2b\x1a":
            endian = "<"
        else:
            raise CaptureParseError(f"Invalid PCAPNG byte-order magic: {bom.hex()}")

        shb_length = struct.unpack(endian + "I", shb_prefix[4:8])[0]
        if shb_length < 28:
            raise CaptureParseError(f"SHB block_length {shb_length} is too small (minimum 28).")
        if shb_length % 4 != 0:
            raise CaptureParseError(f"SHB block_length {shb_length} is not 4-byte aligned.")
        if shb_length > _MAX_SANE_BLOCK_LENGTH:
            raise CaptureParseError(f"SHB block_length {shb_length} exceeds sanity cap.")

        # Read remainder of SHB (body remainder + trailer length) and validate trailer
        shb_rem = _read_exact(f, shb_length - 12)
        trailer = struct.unpack(endian + "I", shb_rem[-4:])[0]
        if trailer != shb_length:
            raise CaptureParseError("SHB trailer length mismatch.")

        # ---- per-interface ts resolution table + iface counter ----
        iface_tsresol: dict[int, float] = {}
        next_iface_id = 0

        def _default_divisor() -> float:
            return float(10 ** _DEFAULT_TSRESOL_EXPONENT)

        def _get_divisor(iface_id: int) -> float:
            if iface_id in iface_tsresol:
                return iface_tsresol[iface_id]
            if strict_iface:
                raise CaptureParseError(f"Unknown interface_id {iface_id} referenced before IDB.")
            return _default_divisor()

        first_ts = None
        last_ts = None

        blk_hdr_struct = struct.Struct(endian + "II")

        # ---- stream through all following blocks ----
        while True:
            hdr = f.read(8)
            if not hdr:
                break
            if len(hdr) != 8:
                raise CaptureParseError("Truncated block header.")

            block_type, block_length = blk_hdr_struct.unpack(hdr)

            if block_length < 12:
                raise CaptureParseError(f"Block length {block_length} is too small (min 12).")
            if block_length % 4 != 0:
                raise CaptureParseError(f"Block length {block_length} is not 4-byte aligned.")
            if block_length > _MAX_SANE_BLOCK_LENGTH:
                raise CaptureParseError(
                    f"Block length {block_length} exceeds sanity cap ({_MAX_SANE_BLOCK_LENGTH})."
                )

            body_len = block_length - 12  # excludes 8-byte header and 4-byte trailer

            # ---------- Section Header Block (may appear mid-stream) ----------
            if block_type == _BT_SHB:
                body = _read_exact(f, body_len)
                trailer_bytes = _read_exact(f, 4)

                # FIX: Determine the NEW endianness from BOM *before* validating
                # the trailer. If the new section flips byte order, using the old
                # endian to unpack the trailer would produce a wrong value and
                # raise a false "trailer mismatch" error.
                bom2 = body[:4]
                if bom2 == b"\x1a\x2b\x3c\x4d":
                    new_endian = ">"
                elif bom2 == b"\x4d\x3c\x2b\x1a":
                    new_endian = "<"
                else:
                    raise CaptureParseError(f"Invalid SHB BOM in stream: {bom2.hex()}")

                # Validate trailer with the (potentially updated) endian
                trailer_len = struct.unpack(new_endian + "I", trailer_bytes)[0]
                if trailer_len != block_length:
                    raise CaptureParseError("Block length trailer mismatch (SHB).")

                # Commit endian change and rebuild the block-header struct
                endian = new_endian
                blk_hdr_struct = struct.Struct(endian + "II")
                iface_tsresol.clear()
                next_iface_id = 0
                continue

            # ---------- Interface Description Block ----------
            if block_type == _BT_IDB:
                body = _read_exact(f, body_len)
                trailer_bytes = _read_exact(f, 4)
                trailer_len = struct.unpack(endian + "I", trailer_bytes)[0]
                if trailer_len != block_length:
                    raise CaptureParseError("Block length trailer mismatch (IDB).")

                if len(body) < 8:
                    raise CaptureParseError("IDB body too short.")

                iface_id = next_iface_id
                next_iface_id += 1

                # default divisor for interfaces without explicit if_tsresol
                iface_tsresol[iface_id] = _default_divisor()

                # options after fixed 8-byte header
                opts = _parse_options(body[8:], endian)
                if _IDB_OPT_TSRESOL in opts:
                    tsresol_bytes = opts[_IDB_OPT_TSRESOL][0]
                    if tsresol_bytes:
                        iface_tsresol[iface_id] = _tsresol_to_scale(tsresol_bytes[0])

                continue

            # ---------- Enhanced Packet Block ----------
            if block_type == _BT_EPB:
                if body_len < 20:
                    raise CaptureParseError("EPB body too short.")
                epb_prefix = _read_exact(f, 20)
                remaining = body_len - 20
                if remaining:
                    f.seek(remaining, os.SEEK_CUR)
                trailer_bytes = _read_exact(f, 4)
                trailer_len = struct.unpack(endian + "I", trailer_bytes)[0]
                if trailer_len != block_length:
                    raise CaptureParseError("Block length trailer mismatch (EPB).")

                iface_id, ts_high, ts_low, _cap_len, _orig_len = struct.unpack(endian + "IIIII", epb_prefix)
                ts_64 = (ts_high << 32) | ts_low
                timestamp = ts_64 / _get_divisor(iface_id)

                if first_ts is None:
                    first_ts = timestamp
                last_ts = timestamp
                continue

            # ---------- Obsolete Packet Block ----------
            if block_type == _BT_OPB:
                # OPB fixed fields (20 bytes per spec): iface_id(2), drops(2), ts_high(4), ts_low(4), cap_len(4), orig_len(4)
                if body_len < 20:
                    raise CaptureParseError("OPB body too short.")
                opb_prefix = _read_exact(f, 20)
                remaining = body_len - 20
                if remaining:
                    f.seek(remaining, os.SEEK_CUR)
                trailer_bytes = _read_exact(f, 4)
                trailer_len = struct.unpack(endian + "I", trailer_bytes)[0]
                if trailer_len != block_length:
                    raise CaptureParseError("Block length trailer mismatch (OPB).")

                iface_id_raw, _drops, ts_high, ts_low, _cap_len, _orig_len = struct.unpack(endian + "HHIIII", opb_prefix)
                ts_64 = (ts_high << 32) | ts_low
                timestamp = ts_64 / _get_divisor(iface_id_raw)

                if first_ts is None:
                    first_ts = timestamp
                last_ts = timestamp
                continue

            # ---------- Other blocks (incl. SPB etc.): skip, but validate trailer ----------
            if body_len:
                f.seek(body_len, os.SEEK_CUR)
            trailer_bytes = _read_exact(f, 4)
            trailer_len = struct.unpack(endian + "I", trailer_bytes)[0]
            if trailer_len != block_length:
                raise CaptureParseError("Block length trailer mismatch (unknown block).")

        if first_ts is None:
            raise CaptureParseError("No timestamped packets found in PCAPNG file.")

        if last_ts < first_ts:
            import warnings
            warnings.warn(
                f"Out-of-order timestamps detected: last packet ({last_ts}) is "
                f"earlier than first ({first_ts}). Duration clamped to 0.",
                stacklevel=2,
            )
        duration = max(0.0, float(last_ts - first_ts))

        return {
            "first_timestamp": first_ts,
            "last_timestamp": last_ts,
            "first_datetime": _to_utc_iso(first_ts),
            "last_datetime": _to_utc_iso(last_ts),
            "duration_seconds": duration,
        }


# ==========================================================
# Public Entry Function
# ==========================================================
def get_capture_time_bounds(path: str) -> dict:
    """
    Return a dict with keys:
        first_timestamp   (float, UNIX epoch)
        last_timestamp    (float, UNIX epoch)
        first_datetime    (str, ISO8601 UTC)
        last_datetime     (str, ISO8601 UTC)
        duration_seconds  (float)
    """
    fmt = _sniff_capture_format(path)
    if fmt == "pcap":
        return _parse_pcap_time_bounds(path)
    if fmt == "pcapng":
        return _parse_pcapng_time_bounds(path)
    raise CaptureParseError("Unsupported capture format.")


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

        print(f"First packet: {result['first_datetime']} ({result['first_timestamp']})")
        print(f"Last packet:  {result['last_datetime']} ({result['last_timestamp']})")
        print(f"Duration:     {result['duration_seconds']:.6f} seconds")
        return 0

    except (CaptureParseError, EOFError, OSError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
