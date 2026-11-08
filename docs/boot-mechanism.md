# Boot mechanism

[← README](../README.md) · [Yocto](meta-az0x.md) · [Recovery](flashing.md)

## One boot path, two sources

```text
vendor BootROM → vendor U-Boot
                  └─ eMMC kernel partition (ext2)
                       └─ /kernel.fit
                            ├─ Linux kernel
                            ├─ board device tree
                            └─ bootargs overlay: root=PARTLABEL=<IMAGE_LABEL>
                                 └─ USB GPT partition → ext4 rootfs → init
```

On JC11S, U-Boot selects `conf-rk3288-az01-jc11s` and `cmdline` with
`bootm …#conf-${board}#cmdline`. Files under `/boot` on the stick do not change
the kernel that U-Boot loads. There is no initramfs in this workflow: the kernel
must discover USB and mount ext4 itself.

## FIT clone bypass

CVE-2026-46728 affects the configuration-signature verification path in
vulnerable U-Boot. The signature's node list can be redirected to pristine
image metadata cloned under `/images/images/…`, while the actual image nodes
reference replacement payloads with updated SHA-256 hashes. Existing RSA
signature bytes are retained. No private signing key is generated or used.

This is a **verification bypass**, not ordinary signing. A clean unsigned
Yocto FIT is still rejected by stock U-Boot. Patched U-Boot also rejects the
repacked FIT. Do not assume every release before some version number is
vulnerable: vendor fixes can be backported.

## Repack mode

`make repack` runs the existing `vendor/tamper/tamper_cmdline.py` path:

- keep the vendor kernel and board DTB;
- replace `fdt-cmdline` with the compiled `BOOTARGS` overlay;
- redirect only the cmdline signature's node list;
- check that its signed byte stream remains identical.

## Yocto mode

`make yocto` runs `tools/repack-fit.py` against the original signed FIT and
the deployed unsigned `meta-az0x` FIT:

- extract its ARM zImage and matching board DTB;
- retain vendor boot addresses/metadata, adapting the zImage to the vendor's
  `none`/`gzip` outer compression;
- append the replacement kernel, DTB and locally compiled bootargs overlay;
- retain **all** original external payloads, including other board overlays;
- redirect image references in each configuration signature's node list;
- require every signature byte stream and RSA value to remain unchanged.

Unsupported formats fail rather than being guessed: absolute vendor
`data-position`, non-SHA-256 payload hashes, non-ARM kernels, compressed custom
FIT payloads, missing board configs and unsupported outer compression.

The helper does not change load addresses or support an initramfs. Signature
stream equality alone does not prove that larger kernels/decompressed payloads
fit the board's memory layout. The default custom-kernel partition image is
16 MiB; `flash-kernel` checks the actual device's slot size before writing.

## What has been validated

| Evidence | What it establishes |
|---|---|
| Existing vendor-kernel USB-rootfs bring-up | The command-line-only boot path has hardware precedent |
| Existing replacement-payload verifier tests on 5.0.2/5.0.4-era FITs | A replacement kernel payload can pass a vulnerable verifier; a fixed verifier rejects it |
| Repository synthetic tests | Payload/hash preservation and identical signature streams for the new combined repacker |
| Complete Yocto kernel + DTB + rootfs on physical Prime 4+ | **Not validated by this change** |

Stay on the known-compatible installed firmware (do not upgrade beyond 5.0.4
expecting this bypass to survive). Other boards and releases need their own
verification. This is not a general-purpose secure-boot unlocking tool.

## Restore is explicit

Repacking saves the original `kernel.img` as `<label>-restore.img`. Restoring
that partition returns to the vendor kernel and its original bootargs. There
is **no automatic stock fallback** if the stick is absent or the custom kernel
fails. Know how to reach fastboot before testing. See [flashing](flashing.md).
