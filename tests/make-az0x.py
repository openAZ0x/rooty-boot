#!/usr/bin/env python3
"""Assemble a synthetic AZ0x signed-firmware fixture for the test suite.

Usage: make-az0x.py <out.img> --kernel <ext2-image> --rootfs <ext2-image>
                    [--version STR] [--device NAME]...

Mirrors the AZ0x container layout: 0x28-byte header
(offsets to the string/device/partition tables), string table at 0x38,
8-byte device entries, 64-byte partition descriptors with per-partition
SHA-256 over the raw (XZ) payload. Payloads given on the command line are
XZ-compressed into the container; small dummy BOOT/splash partitions are
added for realism.
"""
import argparse
import hashlib
import lzma
import struct


def build_strtab(version, imagename, devices, partnames):
    blob = bytearray(b"\0")  # offset 0 is the empty string
    offs = {}

    def add(s):
        offs[s] = len(blob)
        blob.extend(s.encode() + b"\0")

    add(version)
    add(imagename)
    for d in devices:
        add(d)
    for p in partnames:
        add(p)
    return bytes(blob), offs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--kernel", required=True)
    ap.add_argument("--rootfs", required=True)
    ap.add_argument("--version", default="SNAPSHOT-TEST")
    ap.add_argument("--device", action="append", default=["JC11S"])
    args = ap.parse_args()

    devices = args.device
    # one splash pair per device group (like the real images), then kernel+rootfs
    partnames = ["splash", "updatesplash", "kernel", "rootfs"]

    strtab, offs = build_strtab(args.version, "EngineOS test image", devices, partnames)

    strtab_off = 0x38
    devtab_off = strtab_off + len(strtab)
    parttab_off = devtab_off + 8 * len(devices)
    partend_off = parttab_off + 0x40 * (len(devices) + len(partnames))

    payloads = []
    for name, data in [
        ("BOOT", b"idbloader-test" * 64),
        ("splash", b"splash-test" * 16),
        ("updatesplash", b"updatesplash-test" * 16),
        ("kernel", open(args.kernel, "rb").read()),
        ("rootfs", open(args.rootfs, "rb").read()),
    ]:
        if name == "BOOT":
            payloads.append((name, None, data))  # BOOT stored raw
        else:
            payloads.append((name, offs[name], lzma.compress(data)))

    header = bytearray(0x38)
    header[0:4] = b"AZ0x"
    struct.pack_into("<I", header, 0x04, 1)            # format version
    struct.pack_into("<I", header, 0x0C, strtab_off)   # string table offset
    struct.pack_into("<I", header, 0x10, strtab_off)   # (duplicate)
    struct.pack_into("<I", header, 0x14, devtab_off)
    struct.pack_into("<I", header, 0x18, parttab_off)
    struct.pack_into("<I", header, 0x1C, partend_off)
    struct.pack_into("<I", header, 0x20, len(strtab))
    header[0x24] = len(devices)
    header[0x26] = len(payloads)

    out = bytearray(header)
    out += strtab
    for i, d in enumerate(devices):
        out += struct.pack("<II", 0x15E4D000 + i, offs[d])
    assert len(out) == parttab_off

    pids = {"BOOT": (b"BOOT", 0, 0x800000), "splash": (b"PART", 0, 0x800000),
            "updatesplash": (b"PART", 0, 0x800000),
            "kernel": (b"PART", 1, 0x0), "rootfs": (b"PART", 1, 0x0)}

    data_off = (partend_off + 0x0F) & ~0x0F
    desc_off = parttab_off
    for name, nameoff, blob in payloads:
        typ, tint, flags = pids[name]
        while len(out) < data_off:
            out += b"\0"
        d = bytearray(0x40)
        d[0:4] = typ
        d[4] = tint
        d[5:8] = flags.to_bytes(3, "little")
        struct.pack_into("<QQ", d, 0x08, data_off, len(blob))
        struct.pack_into("<II", d, 0x18, nameoff if nameoff is not None else 0, 0x0)
        d[0x20:0x40] = hashlib.sha256(blob).digest()
        out[desc_off:desc_off + 0x40] = d
        desc_off += 0x40
        out += blob
        data_off = (data_off + len(blob) + 0x0F) & ~0x0F

    assert desc_off == partend_off, (desc_off, partend_off)
    with open(args.out, "wb") as f:
        f.write(out)
    print(f"wrote {args.out}: {len(out)} bytes, {len(payloads)} partitions")


if __name__ == "__main__":
    main()
