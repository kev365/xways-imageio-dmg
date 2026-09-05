#!/usr/bin/env python3
"""make_test_dmg.py - synthesize a UDIF (.dmg) from a raw disk image.

Builds a structurally faithful UDIF container (data fork of chunk payloads,
XML plist with a blkx array, 512-byte koly trailer) so the reader's chunk
types and block-map logic can be exercised without a Mac:

    python make_test_dmg.py image.raw out.dmg --type zlib
    python make_test_dmg.py image.raw out.dmg --type mixed --shuffle --parts 3

--type     raw | zlib | bzip2 | lzma | adc | lzfse | mixed
           (mixed cycles through every type per chunk; lzfse needs `pip install lzfse`)
--chunk    chunk size in bytes (default 1 MiB); must be a multiple of 512
--parts    split the image into N blkx partition entries (default 1)
--shuffle  write chunk payloads to the data fork in random order (hdiutil does
           something similar), so file offsets are non-monotonic
--no-zero  do not turn all-zero chunks into zero-fill (type 0) entries

These are *synthetic* images: they prove the decoders and block map, not
hdiutil compatibility. Keep a set of real hdiutil samples for that.
"""
import argparse
import base64
import bz2
import lzma
import os
import random
import struct
import sys
import zlib
from xml.sax.saxutils import escape

ZERO, RAW, IGNORE = 0x00000000, 0x00000001, 0x00000002
ADC, ZLIB, BZIP2, LZFSE, LZMA = 0x80000004, 0x80000005, 0x80000006, 0x80000007, 0x80000008
TERM = 0xFFFFFFFF
SECTOR = 512

try:
    import lzfse as _lzfse  # type: ignore
except Exception:  # pragma: no cover
    _lzfse = None


def adc_encode_literal(data: bytes) -> bytes:
    """ADC with literal runs only (valid ADC, just not compressed)."""
    out = bytearray()
    for i in range(0, len(data), 128):
        run = data[i:i + 128]
        out.append(0x80 | (len(run) - 1))
        out += run
    return bytes(out)


def encode(chunk_type: int, data: bytes) -> bytes:
    if chunk_type == RAW:
        return data
    if chunk_type == ZLIB:
        return zlib.compress(data, 6)
    if chunk_type == BZIP2:
        return bz2.compress(data, 9)
    if chunk_type == LZMA:
        return lzma.compress(data, format=lzma.FORMAT_XZ, check=lzma.CHECK_CRC32)
    if chunk_type == ADC:
        return adc_encode_literal(data)
    if chunk_type == LZFSE:
        if _lzfse is None:
            raise SystemExit("lzfse type requires `pip install lzfse`")
        return _lzfse.compress(data)
    raise ValueError(chunk_type)


TYPE_NAMES = {"raw": RAW, "zlib": ZLIB, "bzip2": BZIP2, "lzma": LZMA, "adc": ADC, "lzfse": LZFSE}
MIXED_CYCLE = [ZLIB, BZIP2, LZMA, ADC, RAW]


def build_mish(sector_number: int, sector_count: int, data_offset: int, descriptor: int, chunks) -> bytes:
    """chunks: list of (type, rel_sector, sector_count, rel_comp_offset, comp_len)."""
    entries = b"".join(struct.pack(">IIQQQQ", t, 0, s, c, o, l) for (t, s, c, o, l) in chunks)
    entries += struct.pack(">IIQQQQ", TERM, 0, sector_count, 0, 0, 0)
    hdr = struct.pack(">4sIQQQII", b"mish", 1, sector_number, sector_count, data_offset, 2048, descriptor)
    hdr += b"\0" * 24                                   # reserved
    hdr += struct.pack(">II", 2, 32) + b"\0" * 128     # checksum: type 2 (CRC32), 32 bits, zeroed
    hdr += struct.pack(">I", len(chunks) + 1)
    assert len(hdr) == 204
    return hdr + entries


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("dst")
    ap.add_argument("--type", default="zlib", choices=list(TYPE_NAMES) + ["mixed"])
    ap.add_argument("--chunk", type=int, default=1 << 20)
    ap.add_argument("--parts", type=int, default=1)
    ap.add_argument("--shuffle", action="store_true")
    ap.add_argument("--no-zero", action="store_true")
    ap.add_argument("--seed", type=int, default=1)
    a = ap.parse_args()
    if a.chunk % SECTOR:
        raise SystemExit("--chunk must be a multiple of 512")

    with open(a.src, "rb") as f:
        image = f.read()
    if len(image) % SECTOR:
        image += b"\0" * (SECTOR - len(image) % SECTOR)
    total_sectors = len(image) // SECTOR

    # Split into partitions of roughly equal sector counts (chunk-aligned).
    chunk_sectors = a.chunk // SECTOR
    part_bounds = []
    per = max(chunk_sectors, (total_sectors // a.parts) // chunk_sectors * chunk_sectors)
    start = 0
    for i in range(a.parts):
        end = total_sectors if i == a.parts - 1 else min(total_sectors, start + per)
        if end > start:
            part_bounds.append((start, end))
        start = end

    # Plan every chunk: (part_idx, abs_sector, count, type, payload)
    rng = random.Random(a.seed)
    plan = []
    cycle_i = 0
    for pi, (ps, pe) in enumerate(part_bounds):
        s = ps
        while s < pe:
            c = min(chunk_sectors, pe - s)
            data = image[s * SECTOR:(s + c) * SECTOR]
            if not a.no_zero and data.count(0) == len(data):
                plan.append((pi, s, c, ZERO, b""))
            else:
                t = TYPE_NAMES[a.type] if a.type != "mixed" else MIXED_CYCLE[cycle_i % len(MIXED_CYCLE)]
                cycle_i += 1
                plan.append((pi, s, c, t, encode(t, data)))
            s += c

    # Lay out the data fork.
    order = list(range(len(plan)))
    if a.shuffle:
        rng.shuffle(order)
    offsets = {}
    fork = bytearray()
    for idx in order:
        _, _, _, t, payload = plan[idx]
        if t == ZERO:
            offsets[idx] = 0
            continue
        offsets[idx] = len(fork)
        fork += payload

    # blkx entries (one mish per partition; chunk sector numbers relative to the partition).
    blkx = []
    for pi, (ps, pe) in enumerate(part_bounds):
        chunks = [(t, s - ps, c, offsets[i], len(p)) for i, (p_i, s, c, t, p) in enumerate(plan) if p_i == pi]
        mish = build_mish(ps, pe - ps, 0, pi, chunks)
        name = "disk image (Apple_HFS : %d)" % pi if a.parts > 1 else "whole disk (synthetic : 0)"
        blkx.append((name, pi - 1 if a.parts > 1 else -1, mish))

    xml = ['<?xml version="1.0" encoding="UTF-8"?>',
           '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">',
           '<plist version="1.0">', '<dict>', '\t<key>resource-fork</key>', '\t<dict>', '\t\t<key>blkx</key>', '\t\t<array>']
    for name, ident, mish in blkx:
        b64 = base64.encodebytes(mish).decode("ascii")
        xml += ['\t\t\t<dict>',
                '\t\t\t\t<key>Attributes</key>', '\t\t\t\t<string>0x0050</string>',
                '\t\t\t\t<key>CFName</key>', '\t\t\t\t<string>%s</string>' % escape(name),
                '\t\t\t\t<key>Data</key>', '\t\t\t\t<data>', b64.rstrip("\n"), '\t\t\t\t</data>',
                '\t\t\t\t<key>ID</key>', '\t\t\t\t<string>%d</string>' % ident,
                '\t\t\t\t<key>Name</key>', '\t\t\t\t<string>%s</string>' % escape(name),
                '\t\t\t</dict>']
    xml += ['\t\t</array>', '\t</dict>', '</dict>', '</plist>', '']
    xml_bytes = "\n".join(xml).encode("utf-8")

    koly = struct.pack(">4sIII", b"koly", 4, 512, 1)
    koly += struct.pack(">QQQQQ", 0, 0, len(fork), 0, 0)               # running/data/rsrc offsets+lengths
    koly += struct.pack(">II", 1, 1) + b"\0" * 16                     # segment 1/1, id
    koly += struct.pack(">II", 0, 0) + b"\0" * 128                    # data checksum (none)
    koly += struct.pack(">QQ", len(fork), len(xml_bytes))             # XML offset/length
    koly += b"\0" * 120
    koly += struct.pack(">II", 0, 0) + b"\0" * 128                    # master checksum (none)
    koly += struct.pack(">IQ", 1, total_sectors)
    koly += b"\0" * 12
    assert len(koly) == 512

    with open(a.dst, "wb") as f:
        f.write(fork)
        f.write(xml_bytes)
        f.write(koly)
    kinds = {}
    for _, _, _, t, _ in plan:
        kinds[t] = kinds.get(t, 0) + 1
    print("wrote %s: %d sectors, %d chunks, %d partition(s), types %s, %d bytes" %
          (a.dst, total_sectors, len(plan), len(part_bounds), {hex(k): v for k, v in kinds.items()}, os.path.getsize(a.dst)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
