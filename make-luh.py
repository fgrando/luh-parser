#!/usr/bin/env python3
"""
make_dummy_luh.py - Generate a dummy ARINC 665 load (LUH + data/support files)
for testing luh_dump.py. Standard library only. Python 3.6+.

All content is fake and deterministic (same output on every run).

Usage:
  python make_dummy_luh.py                      -> ./dummy_load_665-3/
  python make_dummy_luh.py --version 2          -> ./dummy_load_665-2/
  python make_dummy_luh.py --out DIR
  python make_dummy_luh.py --corrupt            also flip one byte in a data
                                                file after the LUH is written
                                                (verification must then FAIL)

Assumptions (same as luh_dump.py, not confirmed against the spec text):
  * Header CRC / file CRC-16 : CRC-16/CCITT-FALSE
  * CRC-32 (Load CRC, CRC-32 check values): poly 0x04C11DB7, init and xorout
    0xFFFFFFFF, not reflected; Load CRC covers the header (up to the Load CRC
    field) followed by the data files
  * Load Check Value: covers the data files followed by the support files
  * Check value length field counts length + type + value bytes
"""

import argparse
import binascii
import hashlib
import os
import struct

# ---------------------------------------------------------------------------
# CRC helpers
# ---------------------------------------------------------------------------


def crc16(data):
    return binascii.crc_hqx(data, 0xFFFF)


def _table():
    t = []
    for i in range(256):
        c = i << 24
        for _ in range(8):
            c = (((c << 1) ^ 0x04C11DB7) if c & 0x80000000 else (c << 1)) & 0xFFFFFFFF
        t.append(c)
    return t


_T = _table()


def crc32_msb(data):
    crc = 0xFFFFFFFF
    for b in data:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ _T[(crc >> 24) ^ b]
    return crc ^ 0xFFFFFFFF


# ---------------------------------------------------------------------------
# Field encoders
# ---------------------------------------------------------------------------


def u16(v):
    return struct.pack(">H", v)


def u32(v):
    return struct.pack(">I", v)


def u64(v):
    return struct.pack(">Q", v)


def string(text):
    b = text.encode("latin-1")
    return u16(len(b)) + b + (b"\x00" if len(b) & 1 else b"")


def check_value(cv_type, value):
    if cv_type == 0:
        return u16(0)
    return u16(4 + len(value)) + u16(cv_type) + value


def part_number(mfr, serial):
    """ARINC 665 style PN 'MMMCC-SSSS-SSSS'. Check characters = XOR of the
    manufacturer and serial characters, as 2 hex digits (inference)."""
    x = 0
    for ch in (mfr + serial):
        x ^= ord(ch)
    return "%s%02X-%s-%s" % (mfr, x, serial[:4], serial[4:])


# ---------------------------------------------------------------------------
# Dummy content
# ---------------------------------------------------------------------------


def dummy_bytes(seed, size):
    """Deterministic pseudo-random bytes."""
    out = bytearray()
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(("%s:%d" % (seed, counter)).encode()).digest()
        counter += 1
    return bytes(out[:size])


def build_files():
    mfr = "ZZZ"  # clearly fake manufacturer code
    data_files = [
        # name, PN, content, 665-3 check value type (3=CRC-32, 6=SHA-256)
        ("APP_EXEC.BIN", part_number(mfr, "00010001"), dummy_bytes("app", 40001), 3),
        ("APP_CONF.BIN", part_number(mfr, "00010002"), dummy_bytes("cfg", 512), 6),
        ("APP_DB.BIN",   part_number(mfr, "00010003"), dummy_bytes("db", 4096), 3),
    ]
    support_files = [
        ("RELEASE_NOTES.TXT", part_number(mfr, "00019001"),
         b"Dummy load for parser testing.\r\nNot flight software.\r\n", 5),
    ]
    load_pn = part_number(mfr, "00010000")
    return load_pn, data_files, support_files


def compute_cv(cv_type, data):
    if cv_type == 3:
        return u32(crc32_msb(data))
    if cv_type == 5:
        return hashlib.sha1(data).digest()
    if cv_type == 6:
        return hashlib.sha256(data).digest()
    raise ValueError(cv_type)


# ---------------------------------------------------------------------------
# LUH builder
# ---------------------------------------------------------------------------


def build_luh(version, load_pn, data_files, support_files):
    v3 = version == 3
    fixed_len = 40 if v3 else 28          # bytes before the first section
    body = bytearray()
    ptr = {}

    def add(key, blob):
        ptr[key] = (fixed_len + len(body)) // 2
        body.extend(blob)

    add("load_pn", string(load_pn))

    if v3:
        add("load_type", string("Operational Software") + u16(0x0001))

    add("thw", u16(2) + string("ZZZ-LRU-100") + string("ZZZ-LRU-200"))

    if v3:
        add("thw_pos",
            u16(1) + string("ZZZ-LRU-100") + u16(2) + string("L") + string("R"))

    # Data files
    blob = u16(len(data_files))
    for i, (name, pn, content, cvt) in enumerate(data_files):
        entry = string(name) + string(pn) + u32((len(content) + 1) // 2) + u16(crc16(content))
        if v3:
            entry += u64(len(content)) + check_value(cvt, compute_cv(cvt, content))
        last = i == len(data_files) - 1
        blob += u16(0 if last else (2 + len(entry)) // 2) + entry
    add("data", blob)

    # Support files
    blob = u16(len(support_files))
    for i, (name, pn, content, cvt) in enumerate(support_files):
        entry = string(name) + string(pn) + u32(len(content)) + u16(crc16(content))
        if v3:
            entry += check_value(cvt, compute_cv(cvt, content))
        last = i == len(support_files) - 1
        blob += u16(0 if last else (2 + len(entry)) // 2) + entry
    add("support", blob)

    add("udd", b"DUMMY-USER-DATA\x00" + bytes(range(16)))

    if v3:
        load_data = b"".join(f[2] for f in data_files) + b"".join(f[2] for f in support_files)
        add("lcv", check_value(6, hashlib.sha256(load_data).digest()))

    total = fixed_len + len(body) + 6      # + header CRC (2) + load CRC (4)
    hdr = u32(total // 2) + u16(0x8004 if v3 else 0x8003) + u16(0x0000)
    hdr += u32(ptr["load_pn"]) + u32(ptr["thw"]) + u32(ptr["data"])
    hdr += u32(ptr["support"]) + u32(ptr["udd"])
    if v3:
        hdr += u32(ptr["load_type"]) + u32(ptr["thw_pos"]) + u32(ptr["lcv"])
    assert len(hdr) == fixed_len

    luh = hdr + bytes(body)
    luh += u16(crc16(luh))
    load_crc = crc32_msb(luh + b"".join(f[2] for f in data_files))
    luh += u32(load_crc)
    assert len(luh) == total
    return luh


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    ap = argparse.ArgumentParser(description="Generate a dummy ARINC 665 load.")
    ap.add_argument("--version", type=int, choices=(2, 3), default=3,
                    help="ARINC 665 supplement layout (default 3)")
    ap.add_argument("--out", help="output directory (default ./dummy_load_665-N)")
    ap.add_argument("--corrupt", action="store_true",
                    help="flip one byte in the first data file after building the LUH")
    args = ap.parse_args()

    out = args.out or "dummy_load_665-%d" % args.version
    os.makedirs(out, exist_ok=True)

    load_pn, data_files, support_files = build_files()
    luh = build_luh(args.version, load_pn, data_files, support_files)

    luh_name = load_pn + ".LUH"
    with open(os.path.join(out, luh_name), "wb") as fh:
        fh.write(luh)
    for name, _pn, content, _cvt in data_files + support_files:
        if args.corrupt and name == data_files[0][0]:
            content = bytearray(content)
            content[100] ^= 0xFF
            content = bytes(content)
        with open(os.path.join(out, name), "wb") as fh:
            fh.write(content)

    print("Wrote %s (%d bytes) + %d data / %d support files to %s"
          % (luh_name, len(luh), len(data_files), len(support_files), os.path.abspath(out)))
    if args.corrupt:
        print("Corrupted: %s (byte 100 flipped)" % data_files[0][0])
    print("Test with: python luh_dump.py \"%s\" --verify" % os.path.join(out, luh_name))


if __name__ == "__main__":
    main()