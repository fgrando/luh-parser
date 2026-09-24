#!/usr/bin/env python3
"""
luh_dump.py - Parse an ARINC 665 Load Upload Header (.LUH) file and print it.

The LUH is the load header used by ARINC 615 / 615A data loaders. Its binary
layout is defined in ARINC 665 (Loadable Software Standards), supplements
-2 (format version 0x8003) and -3 and later (format version 0x8004).

Layout conventions:
  * All integers are big-endian.
  * All pointers and the header file length count 16-bit words from the
    start of the file. A pointer of 0 means the section is absent.
  * Strings are a 16-bit character count followed by the characters, padded
    with one 0x00 byte when the count is odd (so the next field is aligned
    to 16 bits).

Standard library only. Python 3.6+.

Usage:
  python luh_dump.py FILE.LUH            human-readable dump
  python luh_dump.py FILE.LUH --json     JSON dump
  python luh_dump.py FILE.LUH --full     do not truncate hex dumps
  python luh_dump.py FILE.LUH --verify   also verify the data/support files
                                         located in the same directory

Exit codes: 0 OK, 1 malformed LUH, 2 I/O error, 3 header CRC mismatch,
            4 file verification failed (missing file, length or CRC error).
"""

import argparse
import binascii
import hashlib
import json
import os
import struct
import sys

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FORMAT_VERSIONS = {
    0x8003: "ARINC 665-2",
    0x8004: "ARINC 665-3 or later",
}

# Check Value Type codes (ARINC 665-3 and later)
CHECK_VALUE_TYPES = {
    0: "Not used",
    1: "CRC-8",
    2: "CRC-16",
    3: "CRC-32",
    4: "MD5",
    5: "SHA-1",
    6: "SHA-256",
    7: "SHA-512",
}

# Expected value sizes in bytes; used to decide how the length field counts.
CHECK_VALUE_SIZES = {1: 1, 2: 2, 3: 4, 4: 16, 5: 20, 6: 32, 7: 64}

HEX_PREVIEW_BYTES = 64


class LuhError(Exception):
    """Raised when the file is truncated or structurally invalid."""


# ---------------------------------------------------------------------------
# CRC
# ---------------------------------------------------------------------------

def crc16_ccitt(data, crc=0xFFFF):
    """CRC-16/CCITT-FALSE: poly 0x1021, init 0xFFFF, no reflection, no xorout."""
    return binascii.crc_hqx(data, crc)


def _crc32_msb_table(poly=0x04C11DB7):
    table = []
    for i in range(256):
        c = i << 24
        for _ in range(8):
            c = ((c << 1) ^ poly) if (c & 0x80000000) else (c << 1)
            c &= 0xFFFFFFFF
        table.append(c)
    return table


_CRC32_MSB_TABLE = _crc32_msb_table()


# Streaming accumulators with a common interface: update(), copy(), hexdigest()

class Crc16Acc(object):
    name = "CRC-16/CCITT-FALSE"

    def __init__(self, crc=0xFFFF):
        self.crc = crc

    def update(self, chunk):
        self.crc = binascii.crc_hqx(chunk, self.crc)

    def copy(self):
        return Crc16Acc(self.crc)

    def value(self):
        return self.crc

    def hexdigest(self):
        return "%04X" % self.crc


class Crc32MsbAcc(object):
    """CRC-32 poly 0x04C11DB7, init/xorout 0xFFFFFFFF, not reflected (BZIP2).
    Pure Python: roughly 1-3 MB/s."""
    name = "CRC-32/BZIP2"

    def __init__(self, crc=0xFFFFFFFF):
        self.crc = crc

    def update(self, chunk):
        crc = self.crc
        t = _CRC32_MSB_TABLE
        for b in chunk:
            crc = ((crc << 8) & 0xFFFFFFFF) ^ t[(crc >> 24) ^ b]
        self.crc = crc

    def copy(self):
        return Crc32MsbAcc(self.crc)

    def value(self):
        return self.crc ^ 0xFFFFFFFF

    def hexdigest(self):
        return "%08X" % self.value()


class Crc32LsbAcc(object):
    """Standard reflected CRC-32 (zlib / ISO-HDLC)."""
    name = "CRC-32/ISO-HDLC"

    def __init__(self, crc=0):
        self.crc = crc

    def update(self, chunk):
        self.crc = binascii.crc32(chunk, self.crc)

    def copy(self):
        return Crc32LsbAcc(self.crc)

    def value(self):
        return self.crc & 0xFFFFFFFF

    def hexdigest(self):
        return "%08X" % self.value()


class HashAcc(object):
    def __init__(self, algo, h=None):
        self.algo = algo
        self.name = algo.upper()
        self.h = h if h is not None else hashlib.new(algo)

    def update(self, chunk):
        self.h.update(chunk)

    def copy(self):
        return HashAcc(self.algo, self.h.copy())

    def hexdigest(self):
        return self.h.hexdigest().upper()


HASH_ALGOS = {4: "md5", 5: "sha1", 6: "sha256", 7: "sha512"}


def check_value_candidates(cv_type):
    """Accumulators that may produce a check value of the given type.
    CRC-32 has two candidates because the exact variant is an assumption."""
    if cv_type == 2:
        return [Crc16Acc()]
    if cv_type == 3:
        return [Crc32MsbAcc(), Crc32LsbAcc()]
    if cv_type in HASH_ALGOS:
        return [HashAcc(HASH_ALGOS[cv_type])]
    return []


# ---------------------------------------------------------------------------
# Low-level reader
# ---------------------------------------------------------------------------

class Reader(object):
    def __init__(self, data):
        self.data = data

    def _need(self, off, size, what):
        if off < 0 or off + size > len(self.data):
            raise LuhError("%s at byte offset 0x%X (size %d) exceeds file size %d"
                           % (what, off, size, len(self.data)))

    def u16(self, off, what="u16"):
        self._need(off, 2, what)
        return struct.unpack_from(">H", self.data, off)[0]

    def u32(self, off, what="u32"):
        self._need(off, 4, what)
        return struct.unpack_from(">I", self.data, off)[0]

    def u64(self, off, what="u64"):
        self._need(off, 8, what)
        return struct.unpack_from(">Q", self.data, off)[0]

    def raw(self, off, size, what="bytes"):
        self._need(off, size, what)
        return self.data[off:off + size]

    def string(self, off, what="string"):
        """Return (text, next_offset). Next offset is 16-bit aligned."""
        n = self.u16(off, what + " length")
        raw = self.raw(off + 2, n, what)
        text = raw.decode("latin-1")
        return text, off + 2 + n + (n & 1)

    def check_value(self, off, what="check value"):
        """
        Return (dict_or_None, next_offset).

        Length 0 means no check value (and no type field follows).
        Otherwise the length is normally the size of the whole field in
        bytes (length + type + value). If the length instead matches the
        bare value size for the declared type, that interpretation is used
        and flagged.
        """
        length = self.u16(off, what + " length")
        if length == 0:
            return None, off + 2
        ctype = self.u16(off + 2, what + " type")
        expected = CHECK_VALUE_SIZES.get(ctype)
        note = None
        if expected is not None and length - 4 != expected and length == expected:
            value_len = length
            end = off + 4 + length
            note = "length field counted value bytes only"
        else:
            value_len = max(length - 4, 0)
            end = off + length
        value = self.raw(off + 4, value_len, what + " value")
        cv = {
            "length": length,
            "type": ctype,
            "type_name": CHECK_VALUE_TYPES.get(ctype, "Unknown"),
            "value": value.hex().upper(),
        }
        if note:
            cv["note"] = note
        return cv, end + (end & 1)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def parse_luh(data):
    r = Reader(data)
    warnings = []
    out = {"warnings": warnings}

    file_len_words = r.u32(0, "Header File Length")
    file_len_bytes = file_len_words * 2
    version = r.u16(4, "Load File Format Version")
    part_flags = r.u16(6, "Part Flags / Spare")
    v3 = version >= 0x8004

    if version not in FORMAT_VERSIONS:
        warnings.append("Unknown format version 0x%04X; parsing with %s layout"
                        % (version, "665-3" if v3 else "665-2"))
    if file_len_bytes != len(data):
        warnings.append("Header File Length says %d bytes, actual file is %d bytes"
                        % (file_len_bytes, len(data)))

    out["header"] = {
        "file_length_words": file_len_words,
        "file_length_bytes": file_len_bytes,
        "format_version": version,
        "format_version_name": FORMAT_VERSIONS.get(version, "Unknown"),
        ("part_flags" if v3 else "spare"): part_flags,
    }

    ptr = {
        "load_pn": r.u32(8),
        "target_hw_ids": r.u32(12),
        "data_files": r.u32(16),
        "support_files": r.u32(20),
        "user_defined_data": r.u32(24),
    }
    if v3:
        ptr["load_type"] = r.u32(28)
        ptr["target_hw_id_positions"] = r.u32(32)
        ptr["load_check_value"] = r.u32(36)
    out["pointers_words"] = ptr

    # --- Load Part Number -------------------------------------------------
    if ptr["load_pn"]:
        out["load_pn"], _ = r.string(ptr["load_pn"] * 2, "Load PN")
    else:
        out["load_pn"] = None
        warnings.append("Pointer to Load PN is 0")

    # --- Load Type (665-3+) ------------------------------------------------
    if v3 and ptr["load_type"]:
        desc, off = r.string(ptr["load_type"] * 2, "Load Type Description")
        out["load_type"] = {"description": desc, "id": r.u16(off, "Load Type ID")}
    elif v3:
        out["load_type"] = None

    # --- Target Hardware IDs ----------------------------------------------
    thw = []
    if ptr["target_hw_ids"]:
        off = ptr["target_hw_ids"] * 2
        n = r.u16(off, "Number of Target HW IDs")
        off += 2
        for i in range(n):
            s, off = r.string(off, "Target HW ID #%d" % (i + 1))
            thw.append(s)
    out["target_hw_ids"] = thw

    # --- Target Hardware IDs with Positions (665-3+) ------------------------
    if v3:
        thw_pos = []
        if ptr["target_hw_id_positions"]:
            off = ptr["target_hw_id_positions"] * 2
            n = r.u16(off, "Number of Target HW ID with Positions")
            off += 2
            for i in range(n):
                hwid, off = r.string(off, "Target HW ID (positions) #%d" % (i + 1))
                npos = r.u16(off, "Number of Positions")
                off += 2
                positions = []
                for j in range(npos):
                    p, off = r.string(off, "Position #%d" % (j + 1))
                    positions.append(p)
                thw_pos.append({"target_hw_id": hwid, "positions": positions})
        out["target_hw_id_positions"] = thw_pos

    # --- Data Files --------------------------------------------------------
    data_files = []
    if ptr["data_files"]:
        off = ptr["data_files"] * 2
        n = r.u16(off, "Number of Data Files")
        off += 2
        for i in range(n):
            tag = "Data File #%d" % (i + 1)
            start = off
            nxt = r.u16(off, tag + " next pointer")
            off += 2
            name, off = r.string(off, tag + " name")
            pn, off = r.string(off, tag + " PN")
            length_words = r.u32(off, tag + " length")
            off += 4
            crc = r.u16(off, tag + " CRC")
            off += 2
            entry = {
                "name": name,
                "pn": pn,
                "length_words": length_words,
                "crc16": crc,
            }
            if v3:
                entry["length_bytes"] = r.u64(off, tag + " length in bytes")
                off += 8
                entry["check_value"], off = r.check_value(off, tag + " check value")
            data_files.append(entry)
            if nxt:
                off = start + nxt * 2
            elif i != n - 1:
                warnings.append("%s has next pointer 0 but is not the last entry" % tag)
    else:
        warnings.append("Pointer to Data Files is 0")
    out["data_files"] = data_files

    # --- Support Files -----------------------------------------------------
    support_files = []
    if ptr["support_files"]:
        off = ptr["support_files"] * 2
        n = r.u16(off, "Number of Support Files")
        off += 2
        for i in range(n):
            tag = "Support File #%d" % (i + 1)
            start = off
            nxt = r.u16(off, tag + " next pointer")
            off += 2
            name, off = r.string(off, tag + " name")
            pn, off = r.string(off, tag + " PN")
            length = r.u32(off, tag + " length")
            off += 4
            crc = r.u16(off, tag + " CRC")
            off += 2
            entry = {"name": name, "pn": pn, "length_bytes": length, "crc16": crc}
            if v3:
                entry["check_value"], off = r.check_value(off, tag + " check value")
            support_files.append(entry)
            if nxt:
                off = start + nxt * 2
            elif i != n - 1:
                warnings.append("%s has next pointer 0 but is not the last entry" % tag)
    out["support_files"] = support_files

    # --- Trailer positions -------------------------------------------------
    trailer_base = min(file_len_bytes, len(data))
    hdr_crc_off = trailer_base - 6
    load_crc_off = trailer_base - 4

    # --- User Defined Data -------------------------------------------------
    if ptr["user_defined_data"]:
        udd_start = ptr["user_defined_data"] * 2
        udd_end = hdr_crc_off
        if v3 and ptr["load_check_value"] and ptr["load_check_value"] * 2 > udd_start:
            udd_end = ptr["load_check_value"] * 2
        out["user_defined_data"] = r.raw(udd_start, max(udd_end - udd_start, 0),
                                         "User Defined Data")
    else:
        out["user_defined_data"] = b""

    # --- Load Check Value (665-3+) ------------------------------------------
    if v3:
        if ptr["load_check_value"]:
            out["load_check_value"], _ = r.check_value(ptr["load_check_value"] * 2,
                                                       "Load Check Value")
        else:
            out["load_check_value"] = None

    # --- CRCs --------------------------------------------------------------
    header_crc = r.u16(hdr_crc_off, "Header File CRC")
    computed = crc16_ccitt(data[:hdr_crc_off])
    out["header_crc"] = {
        "stored": header_crc,
        "computed": computed,
        "match": header_crc == computed,
    }
    out["load_crc32"] = r.u32(load_crc_off, "Load CRC")

    return out



# ---------------------------------------------------------------------------
# File verification
# ---------------------------------------------------------------------------

CHUNK = 1 << 20


def _find_file(directory, name, listing):
    path = os.path.join(directory, name)
    if os.path.isfile(path):
        return path
    alt = listing.get(name.lower())          # case-insensitive fallback
    return os.path.join(directory, alt) if alt else None


def _check(label, ok, detail):
    return {"check": label, "ok": ok, "detail": detail}


def verify_files(luh, luh_path, data):
    """
    Verify the files listed in the LUH against the files in its directory.

    Per file : presence, length, CRC-16, check value (665-3).
    Load     : 32-bit Load CRC, Load Check Value (665-3).

    The exact Load CRC / Load Check Value coverage and the CRC-32 variant are
    not hard-coded; every candidate is computed and the matching one reported.
    """
    directory = os.path.dirname(os.path.abspath(luh_path))
    listing = {n.lower(): n for n in os.listdir(directory)}
    v3 = luh["header"]["format_version"] >= 0x8004
    file_len = min(luh["header"]["file_length_bytes"], len(data))

    res = {"directory": directory, "files": [], "load": [], "ok": True}

    # Load CRC candidates: {algorithm} x {with / without header}
    load_accs = {}
    for cls in (Crc32MsbAcc, Crc32LsbAcc):
        with_hdr = cls()
        with_hdr.update(data[:file_len - 4])   # header up to the Load CRC field
        load_accs[(cls.name, "header + data files")] = with_hdr
        load_accs[(cls.name, "data files")] = cls()

    lcv = luh.get("load_check_value")
    lcv_accs = {}
    if lcv:
        for acc in check_value_candidates(lcv["type"]):
            lcv_accs[(acc.name, "data files")] = acc

    all_present = True
    snapshots = {}

    groups = (("data", luh["data_files"]), ("support", luh["support_files"]))
    for kind, entries in groups:
        if kind == "support":
            # Freeze the "data files only" coverage before feeding support files
            for k, a in list(load_accs.items()):
                snapshots[k] = a.copy()
            for k, a in list(lcv_accs.items()):
                snapshots[("lcv",) + k] = a.copy()
            load_accs = {(k[0], k[1].replace("data files", "data + support files")): a
                         for k, a in load_accs.items()}
            lcv_accs = {(k[0], k[1].replace("data files", "data + support files")): a
                        for k, a in lcv_accs.items()}

        for e in entries:
            fr = {"kind": kind, "name": e["name"], "path": None, "checks": []}
            res["files"].append(fr)
            path = _find_file(directory, e["name"], listing)
            if not path:
                fr["checks"].append(_check("present", False, "not found"))
                res["ok"] = False
                all_present = False
                continue
            fr["path"] = path
            size = os.path.getsize(path)

            # Length
            if kind == "data":
                want_words = (size + 1) // 2
                ok = e["length_words"] == want_words
                fr["checks"].append(_check(
                    "length (words)", ok,
                    "LUH %d, file %d bytes = %d words" % (e["length_words"], size, want_words)))
                if "length_bytes" in e:
                    ok2 = e["length_bytes"] == size
                    fr["checks"].append(_check(
                        "length (bytes)", ok2, "LUH %d, file %d" % (e["length_bytes"], size)))
                    ok = ok and ok2
            else:
                ok = e["length_bytes"] == size
                fr["checks"].append(_check(
                    "length (bytes)", ok, "LUH %d, file %d" % (e["length_bytes"], size)))
            if not ok:
                res["ok"] = False

            # Stream the file once through every accumulator
            crc16 = Crc16Acc()
            cv = e.get("check_value")
            cv_accs = check_value_candidates(cv["type"]) if cv else []
            feeders = [crc16] + cv_accs + list(load_accs.values()) + list(lcv_accs.values())
            with open(path, "rb") as fh:
                while True:
                    chunk = fh.read(CHUNK)
                    if not chunk:
                        break
                    for a in feeders:
                        a.update(chunk)

            # CRC-16
            got = crc16.value()
            if got == e["crc16"]:
                fr["checks"].append(_check("CRC-16", True, "0x%04X" % got))
            else:
                padded = binascii.crc_hqx(b"\x00", got) if size & 1 else None
                if padded == e["crc16"]:
                    fr["checks"].append(_check(
                        "CRC-16", True, "0x%04X (with 0x00 pad byte to even length)" % padded))
                else:
                    fr["checks"].append(_check(
                        "CRC-16", False, "LUH 0x%04X, computed 0x%04X" % (e["crc16"], got)))
                    res["ok"] = False

            # Check value (665-3)
            if cv:
                if not cv_accs:
                    fr["checks"].append(_check(
                        "check value", None, "%s not supported, skipped" % cv["type_name"]))
                else:
                    match = [a.name for a in cv_accs if a.hexdigest() == cv["value"]]
                    if match:
                        fr["checks"].append(_check("check value", True,
                                                   "%s = %s" % (match[0], cv["value"])))
                    else:
                        fr["checks"].append(_check(
                            "check value", False, "LUH %s, computed %s" % (
                                cv["value"], " / ".join("%s %s" % (a.name, a.hexdigest())
                                                        for a in cv_accs))))
                        res["ok"] = False

    for k, a in load_accs.items():
        snapshots[k] = a
    for k, a in lcv_accs.items():
        snapshots[("lcv",) + k] = a

    # Load CRC
    if not all_present:
        res["load"].append(_check("Load CRC", None, "skipped: file(s) missing"))
        if lcv:
            res["load"].append(_check("Load Check Value", None, "skipped: file(s) missing"))
        return res

    stored = "%08X" % luh["load_crc32"]
    hits = ["%s over %s" % (k[0], k[1]) for k, a in snapshots.items()
            if k[0] != "lcv" and a.hexdigest() == stored]
    if hits:
        res["load"].append(_check("Load CRC", True, "0x%s matched %s" % (stored, "; ".join(hits))))
    else:
        res["load"].append(_check("Load CRC", False,
                                  "0x%s matched no candidate algorithm/coverage" % stored))
        res["ok"] = False

    # Load Check Value (665-3)
    if v3:
        if not lcv:
            res["load"].append(_check("Load Check Value", None, "not present in LUH"))
        elif lcv["type"] not in (2, 3) and lcv["type"] not in HASH_ALGOS:
            res["load"].append(_check("Load Check Value", None,
                                      "%s not supported, skipped" % lcv["type_name"]))
        else:
            hits = ["%s over %s" % (k[1], k[2]) for k, a in snapshots.items()
                    if k[0] == "lcv" and a.hexdigest() == lcv["value"]]
            if hits:
                res["load"].append(_check("Load Check Value", True,
                                          "matched %s" % "; ".join(hits)))
            else:
                res["load"].append(_check(
                    "Load Check Value", False,
                    "%s matched no candidate coverage (data / data + support files)"
                    % lcv["type_name"]))
                res["ok"] = False

    return res


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def hexdump(data, full=False, indent="    "):
    if not data:
        return indent + "(empty)"
    shown = data if full else data[:HEX_PREVIEW_BYTES]
    lines = []
    for i in range(0, len(shown), 16):
        chunk = shown[i:i + 16]
        hx = " ".join("%02X" % b for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append("%s%08X  %-47s  |%s|" % (indent, i, hx, asc))
    if len(shown) < len(data):
        lines.append("%s... %d more bytes (use --full)" % (indent, len(data) - len(shown)))
    return "\n".join(lines)


def fmt_cv(cv):
    if cv is None:
        return "none"
    s = "%s (type %d): %s" % (cv["type_name"], cv["type"], cv["value"] or "-")
    if "note" in cv:
        s += "  [%s]" % cv["note"]
    return s


def print_report(path, luh, full=False):
    h = luh["header"]
    p = luh["pointers_words"]
    w = print

    w("=" * 72)
    w("LUH file: %s" % path)
    w("=" * 72)
    w("Header File Length   : %d words (%d bytes)"
      % (h["file_length_words"], h["file_length_bytes"]))
    w("Format Version       : 0x%04X (%s)" % (h["format_version"], h["format_version_name"]))
    if "part_flags" in h:
        w("Part Flags           : 0x%04X" % h["part_flags"])
    else:
        w("Spare                : 0x%04X" % h["spare"])

    w("")
    w("Pointers (16-bit words / byte offset):")
    for k, v in p.items():
        w("  %-24s: %6d  (0x%06X)" % (k, v, v * 2))

    w("")
    w("Load Part Number     : %s" % luh["load_pn"])
    if "load_type" in luh:
        lt = luh["load_type"]
        if lt:
            w("Load Type            : %s (ID 0x%04X)" % (lt["description"], lt["id"]))
        else:
            w("Load Type            : (none)")

    w("")
    w("Target Hardware IDs (%d):" % len(luh["target_hw_ids"]))
    for s in luh["target_hw_ids"]:
        w("  - %s" % s)

    if "target_hw_id_positions" in luh:
        w("")
        w("Target Hardware IDs with Positions (%d):" % len(luh["target_hw_id_positions"]))
        for e in luh["target_hw_id_positions"]:
            w("  - %s: %s" % (e["target_hw_id"], ", ".join(e["positions"]) or "(none)"))

    w("")
    w("Data Files (%d):" % len(luh["data_files"]))
    for i, f in enumerate(luh["data_files"], 1):
        w("  [%d] %s" % (i, f["name"]))
        w("      PN           : %s" % f["pn"])
        w("      Length       : %d words (%d bytes)" % (f["length_words"], f["length_words"] * 2))
        if "length_bytes" in f:
            w("      Length bytes : %d" % f["length_bytes"])
        w("      CRC-16       : 0x%04X" % f["crc16"])
        if "check_value" in f:
            w("      Check Value  : %s" % fmt_cv(f["check_value"]))

    w("")
    w("Support Files (%d):" % len(luh["support_files"]))
    for i, f in enumerate(luh["support_files"], 1):
        w("  [%d] %s" % (i, f["name"]))
        w("      PN           : %s" % f["pn"])
        w("      Length       : %d bytes" % f["length_bytes"])
        w("      CRC-16       : 0x%04X" % f["crc16"])
        if "check_value" in f:
            w("      Check Value  : %s" % fmt_cv(f["check_value"]))

    w("")
    w("User Defined Data (%d bytes):" % len(luh["user_defined_data"]))
    w(hexdump(luh["user_defined_data"], full))

    if "load_check_value" in luh:
        w("")
        w("Load Check Value     : %s" % fmt_cv(luh["load_check_value"]))

    c = luh["header_crc"]
    w("")
    w("Header File CRC      : 0x%04X  (computed 0x%04X, CRC-16/CCITT) -> %s"
      % (c["stored"], c["computed"], "OK" if c["match"] else "MISMATCH"))
    w("Load CRC (32-bit)    : 0x%08X  %s" % (
        luh["load_crc32"],
        "(see file verification)" if "verification" in luh
        else "(not verified, use --verify)"))

    v = luh.get("verification")
    if v:
        mark = {True: "OK  ", False: "FAIL", None: "SKIP"}
        w("")
        w("File verification (directory: %s)" % v["directory"])
        for f in v["files"]:
            w("  %s file %s" % (f["kind"].capitalize(), f["name"]))
            for c in f["checks"]:
                w("    [%s] %-16s %s" % (mark[c["ok"]], c["check"], c["detail"]))
        w("  Load")
        for c in v["load"]:
            w("    [%s] %-16s %s" % (mark[c["ok"]], c["check"], c["detail"]))
        w("  Result: %s" % ("PASS" if v["ok"] else "FAIL"))

    if luh["warnings"]:
        w("")
        w("Warnings:")
        for m in luh["warnings"]:
            w("  ! %s" % m)


def to_json(luh):
    d = dict(luh)
    d["user_defined_data"] = luh["user_defined_data"].hex().upper()
    return json.dumps(d, indent=2)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description="Parse and print an ARINC 665 LUH file.")
    ap.add_argument("file", help="path to the .LUH file")
    ap.add_argument("--json", action="store_true", help="print JSON instead of text")
    ap.add_argument("--full", action="store_true", help="do not truncate hex dumps")
    ap.add_argument("--verify", action="store_true",
                    help="verify the data/support files in the LUH's directory")
    args = ap.parse_args(argv)

    try:
        with open(args.file, "rb") as fh:
            data = fh.read()
    except OSError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2

    if len(data) < 34:
        print("error: file too small to be an LUH (%d bytes)" % len(data), file=sys.stderr)
        return 1

    try:
        luh = parse_luh(data)
    except LuhError as e:
        print("error: malformed LUH: %s" % e, file=sys.stderr)
        return 1

    if args.verify:
        try:
            luh["verification"] = verify_files(luh, args.file, data)
        except OSError as e:
            print("error: verification failed: %s" % e, file=sys.stderr)
            return 2

    if args.json:
        print(to_json(luh))
    else:
        print_report(args.file, luh, args.full)

    if not luh["header_crc"]["match"]:
        return 3
    if args.verify and not luh["verification"]["ok"]:
        return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())