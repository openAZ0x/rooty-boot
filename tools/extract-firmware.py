#!/usr/bin/env python3
"""Extract the kernel and rootfs partition images from an inMusic AZ0x
signed firmware update file.

Usage: extract-firmware.py <update.img> <output_dir>

Writes into <output_dir>:
    kernel.img   - the stock `kernel` partition (ext2 with /kernel.fit inside)
    rootfs.img   - the stock `rootfs` partition (ext2/ext4 rootfs image)

Format: AZ0x header, 8-byte device entries, 64-byte partition descriptors,
string table; every partition slice carries a SHA-256 which is verified here.
The partition payloads are XZ streams and are decompressed on the fly.
"""
import hashlib
import io
import lzma
import os
import struct
import sys

HEADER_FMT = None  # header parsed field-by-field below (see firmware-format.md)
CHUNK = 1 << 20


def die(msg):
    print(f"extract-firmware: FATAL: {msg}", file=sys.stderr)
    sys.exit(1)


class SliceReader(io.RawIOBase):
    """Bounded, read-only view of a region of another file."""

    def __init__(self, fh, start, size):
        self.fh = fh
        self.remaining = size
        fh.seek(start)

    def readable(self):
        return True

    def read(self, n=-1):
        if n is None or n < 0:
            n = self.remaining
        n = min(n, self.remaining)
        if n == 0:
            return b""
        data = self.fh.read(n)
        self.remaining -= len(data)
        return data


def cstr(strtab, off):
    if off >= len(strtab):
        return "?"
    return strtab[off:strtab.find(b"\0", off)].decode("ascii", "replace")


def sha256_slice(fh, start, size):
    h = hashlib.sha256()
    rd = SliceReader(fh, start, size)
    while True:
        b = rd.read(CHUNK)
        if not b:
            break
        h.update(b)
    return h.digest()


def xz_to_file(fh, start, size, dest):
    h = hashlib.sha256()
    written = 0
    with open(dest + ".part", "wb") as out, lzma.LZMAFile(SliceReader(fh, start, size)) as xz:
        while True:
            b = xz.read(CHUNK)
            if not b:
                break
            h.update(b)
            written += len(b)
            out.write(b)
    os.replace(dest + ".part", dest)
    return written, h.digest()


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <update.img> <output_dir>", file=sys.stderr)
        sys.exit(1)
    img, outdir = sys.argv[1], sys.argv[2]
    if not os.path.isfile(img):
        die(f"file not found: {img}")
    os.makedirs(outdir, exist_ok=True)

    filesize = os.path.getsize(img)
    with open(img, "rb") as f:
        hdr = f.read(0x28)
        if len(hdr) < 0x28 or hdr[:4] != b"AZ0x":
            die(f"{img} is not an AZ0x signed image")
        magic = hdr[:4]
        ver = struct.unpack("<I", hdr[4:8])[0]
        strtab, strtab2, devtab, parttab, partend, strsz = struct.unpack("<6I", hdr[0x0C:0x24])
        ndev, npart = hdr[0x24], hdr[0x26]
        if ver != 1:
            print(f"  NOTE: untested AZ0x format version {ver}")
        if strtab != strtab2:
            die("string table offsets disagree")
        # layout: header, string table, device table, partition descriptors, data
        if not (0x28 <= strtab <= devtab <= parttab <= partend <= filesize):
            die(f"implausible table offsets: str={strtab:#x} dev={devtab:#x} part={parttab:#x}-{partend:#x}")
        if strtab + strsz > devtab:
            die("string table overlaps the device table")
        if npart == 0 or npart > 64 or ndev == 0 or ndev > 32:
            die(f"implausible counts: devices={ndev} partitions={npart}")

        f.seek(strtab)
        strtab_data = f.read(strsz)
        if len(strtab_data) != strsz:
            die("string table truncated")

        print(f"Parsing {img}: format v{ver}, {ndev} device(s), {npart} partition(s)")
        print(f"  Version string: {cstr(strtab_data, 1)!r}")

        f.seek(devtab)
        devices = []
        for _ in range(ndev):
            pid, nameoff = struct.unpack("<II", f.read(8))
            devices.append((pid, cstr(strtab_data, nameoff)))
        print(f"  Devices: {', '.join(n for _, n in devices)}")

        parts = []
        for i in range(npart):
            f.seek(parttab + i * 0x40)
            d = f.read(0x40)
            typ = d[:4].decode("ascii", "replace")
            start, size = struct.unpack("<QQ", d[8:0x18])
            nameoff, _mask = struct.unpack("<II", d[0x18:0x20])
            sha = d[0x20:0x40]
            name = cstr(strtab_data, nameoff)
            if start + size > filesize:
                die(f"partition {i} ({name!r}) extends past end of file")
            print(f"  p{i}: {typ:<4} {name:<14} off={start:#010x} size={size:>12,}")
            parts.append({"i": i, "type": typ, "name": name, "start": start, "size": size, "sha": sha})

        wanted = {}
        for p in parts:
            if p["type"] != "PART":
                continue
            if p["name"] in ("kernel", "rootfs"):
                if p["name"] in wanted:
                    die(f"multiple partitions named {p['name']!r}")
                wanted[p["name"]] = p
        missing = [n for n in ("kernel", "rootfs") if n not in wanted]
        if missing:
            die(f"no partition(s) named {', '.join(missing)} in this image")

        for name in ("kernel", "rootfs"):
            p = wanted[name]
            print(f"Verifying {name} ({p['size']:,} bytes)... ", end="", flush=True)
            if sha256_slice(f, p["start"], p["size"]) != p["sha"]:
                die(f"SHA-256 mismatch on {name} partition - file corrupt or modified")
            print("ok")
            if p["size"] < 6 or p["size"] > (1 << 34):
                die(f"{name} payload has implausible size {p['size']}")
            f.seek(p["start"])
            if f.read(6) != b"\xfd7zXZ\x00":
                die(f"{name} payload is not XZ-compressed")
            dest = os.path.join(outdir, f"{name}.img")
            print(f"  decompressing {name} -> {dest}")
            total, digest = xz_to_file(f, p["start"], p["size"], dest)
            print(f"  wrote {dest}: {total:,} bytes (sha256 {digest.hex()[:16]}...)")

    print("Done.")


if __name__ == "__main__":
    main()
