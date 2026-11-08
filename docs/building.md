# Building

[← README](../README.md) · [Yocto](meta-az0x.md) · [Flashing](flashing.md)

## Host tools

Use Linux with GNU Make, Bash and Python 3:

```sh
sudo apt install device-tree-compiler e2fsprogs gdisk curl fastboot
# Optional: lint and Debian rootfs support
sudo apt install shellcheck debootstrap qemu-user-static
```

All tasks run from the checkout. Use absolute paths for external inputs,
especially when moving between the checkout and a Yocto build directory.

## Common settings

Edit `config.env`, export variables, or pass `NAME=value` to Make:

| Setting | Default / purpose |
|---|---|
| `FIRMWARE_IMG` | Required vendor update path or URL, matching the installed release |
| `IMAGE_LABEL` | `debian`; 1–16 ASCII letters/digits/`_`/`-`; GPT name and ext4 label |
| `BOOTARGS` | `root=PARTLABEL=$IMAGE_LABEL rootwait rw console=ttyS3,115200n8 loglevel=4` |
| `STICK_SIZE_MB` | `4096`; size of the generated whole-disk USB image |
| `IMAGES_OUT` | `images/`; generated artifacts, never tracked |
| `ROOTFS_IMAGE` | Optional **raw ext4**, not a WIC/GPT disk or compressed archive |
| `ROOTFS_DIR` | `rootfs/`; alternative directory tree |
| `CUSTOM_FIT` | Optional unsigned Yocto FIT, consumed by the low-level `kernel` task |
| `BOARD` | `rk3288-az01-jc11s`; FIT board configuration suffix |
| `KERNEL_PARTITION_MIB` | `16` for a custom kernel; stock repacks use the original artifact size |

`BOOTARGS` must contain exactly one matching `root=PARTLABEL=…`. A filesystem
label and GPT partition name are different things; this workflow sets both to
the same value. The kernel selects the **GPT partition name**.

## Existing-firmware repack

```sh
make repack FIRMWARE_IMG=/absolute/path/update.img IMAGE_LABEL=myroot
make image ROOTFS_IMAGE=/absolute/path/rootfs.ext4 IMAGE_LABEL=myroot
```

Extraction verifies the partition SHA-256 values, decompresses the vendor
`kernel`/`rootfs` payloads and dumps `/kernel.fit`. This is **not RSA
authentication of the downloaded update**; obtain firmware from a trusted source.
Results are cached under `cache/firmware/<update-name>/`.

Advanced alternative: supply `KERNEL_ITB` (vendor FIT) and `RESTORE_IMG_SRC`
(stock kernel partition image) instead of `FIRMWARE_IMG`. Do not mix both input
forms. Keep the restore image from the same installed release.

For a source-built kernel and matching rootfs, use the [Yocto workflow](meta-az0x.md).

## USB image assembly

`make image` creates one GPT partition starting at 1 MiB and a backup GPT at the
end of the disk image. It never writes a physical disk.

**Directory input:** applies optional `overlay/`, installs eMMC-lockdown and
bootcount-reset units, checks the resulting tree, then runs `mkfs.ext4 -d`.
Preserve root ownership when preparing a real tree; run the directory assembly
as root when needed (the Debian builder creates root-owned files).

**Raw ext4 input:** copies the filesystem, checks it with `e2fsck`, adjusts its
root fstab entry, relabels and grows it to the USB partition. Ownership/modes
stay in the filesystem; the input file is not modified. Active fstab references
to the known internal eMMC are refused. `overlay/` is not applied. This is not
a complete audit of mounts/services; include eMMC protection and bootcount
reset in that distro. The [Yocto guide](meta-az0x.md#runtime-safety) covers this.

## Optional Debian rootfs

This is a convenience alternative to Yocto, using the **vendor kernel**, not
a second build system you must maintain:

```sh
export FIRMWARE_IMG=/absolute/path/PRIME4PLUS-5.0.4-Update.img
export IMAGE_LABEL=myroot
export ROOT_PASSWORD='choose-your-own-password'
export QEMU=/usr/bin/qemu-arm-static
make rootfs
make repack
sudo -E make image
```

`make rootfs` uses sudo/debootstrap (armhf Debian trixie), installs systemd,
SSH and Ethernet DHCP, imports vendor modules/firmware, and installs the eMMC
safety policy. `ROOT_PASSWORD` has no default: set it before building or
`build-rootfs.sh` refuses to run. `ARCH`, `DISTRO`, `MIRROR`, `MODULES_SRC`,
`KVERSION` and the vendor udev allowlist are also configurable in `config.env`.

Do **not** pair those vendor modules with a custom Yocto kernel. Use the Yocto
rootfs containing modules from that same kernel build instead.

## Checks and cleanup

```sh
make lint
make test
make verify      # static pre-flight of built artifacts; reads files only
make clean       # default images/ and tests/work/
make distclean   # also default rootfs/ and cache/
```

Tests use synthetic containers/FITs and command mocks. Optional real-firmware
and golden tests are gated by `TEST_FIRMWARE_IMG`/`TEST_POC_DIR`; the normal
test suite does not download firmware or access hardware. Some legacy import
tests use noninteractive sudo and skip if unavailable.

Cleanup targets remove the default generated directories, not custom external
paths. No firmware blobs, keys, generated images or local build trees belong
in commits.
