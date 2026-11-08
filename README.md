<div align="center">

# 🔓 rooty-boot

### Boot your own OS on a signed-boot controller

Repack vendor firmware or bring a Yocto build to signed Denon DJ controllers.
Small scripts, explicit Make targets, and a stock-kernel restore image.

**[Quick start](#quick-start)** · **[Write & boot](#write--boot)** · **[Make targets](#make-targets)** · **[Docs](#documentation)**

</div>

---

> [!IMPORTANT]
> **The kernel lives on the controller's eMMC; the root filesystem lives on USB.**
> Stock U-Boot loads `kernel.fit` from the internal `kernel` partition, not the
> stick. This project rewrites that FIT so Linux mounts your USB partition.
> It does **not** replace the bootloader or produce a signed Engine OS update.

## Supported devices

| Device | Kernel boot | Status |
|---|---|---|
| **Denon Prime 4+** (JC11S) | Signed FIT | ✅ Tested |
| SC LIVE 4 · SC LIVE 2 | Signed FIT | ⚠️ Same path, untested |
| Prime GO+ | Signed FIT | ⚠️ Same path, untested |
| Mixstream Pro+ · Mixstream Pro Go | Signed FIT | ⚠️ Same path, untested |
| Prime 4 G2 | Signed FIT | ❌ Patched U-Boot |
| Rane SYSTEM ONE | Signed FIT | ❌ Unverified |
| SC5000 / SC6000 · Prime 4 / 2 / Go · Mixstream Pro | Unsigned zImage | ➖ Not needed |

Untested models still need their own `BOARD`, device tree, console and firmware
version. The bypass only works on firmware that still carries the vulnerable
verifier.

## Two workflows

| | **Repack existing firmware** | **Bring your own Yocto build** |
|---|---|---|
| Kernel + board DTB | Keep the vendor's | Replace with your `meta-az0x` build |
| Boot target | `IMAGE_LABEL` → `root=PARTLABEL=…` | Same label, paired with the Yocto rootfs |
| USB userspace | Your ext4 image, or optional Debian build | The matching Yocto `.rootfs.ext4` |
| Entry point | `make repack` | `make yocto-build`, then `make yocto` |
| Status | Existing vendor-kernel USB boot path | **Experimental; not hardware-validated here** |

Both start from a **signed vendor firmware image matching the installed release**.
The Yocto route repacks that vendor FIT; it does not flash Yocto's unsigned FIT
directly. [How the boot path works →](docs/boot-mechanism.md)

> [!WARNING]
> This relies on the FIT `hashed-nodes` bypass, **CVE-2026-46728**. A patched
> bootloader rejects the result. Existing evidence covers 5.0.2/5.0.4-era
> firmware; **stay on your known-working release and do not upgrade past 5.0.4**
> expecting this path to survive. Other firmware and boards are not certified.
> Keep the restore image and a working way into fastboot before writing anything.

## Prerequisites

Linux, Bash, Python 3 and GNU Make:

```sh
sudo apt install device-tree-compiler e2fsprogs gdisk curl fastboot
```

For Yocto, use an **already configured** build containing
[`openAZ0x/meta-az0x`](https://github.com/openAZ0x/meta-az0x) and its normal
dependencies. This repository does not clone layers or set up a distro.

> [!NOTE]
> Under **WSL**, `/mnt/c/...` is fine for firmware and build inputs, but USB
> devices must be attached to the distro (`usbipd bind`/`attach`) before
> `fastboot` or `flash-usb` can see them. A device that only exists on the
> Windows side will not appear in `lsblk` or `fastboot devices`.

## Quick start

### A · Repack existing firmware

Keep the vendor kernel/DTB and redirect boot to a USB partition called `myroot`:

```sh
make repack FIRMWARE_IMG=/absolute/path/PRIME4PLUS-5.0.4-Update.img IMAGE_LABEL=myroot

# Put an existing, vendor-kernel-compatible rootfs on a GPT USB disk image.
make image ROOTFS_IMAGE=/absolute/path/rootfs.ext4 IMAGE_LABEL=myroot
```

`FIRMWARE_IMG` also accepts an HTTPS URL. The firmware is only an **input**:
the repack produces a kernel-partition image and its stock restore counterpart.
It does not copy Engine OS's internal rootfs into a portable installation.

Need a userspace instead? The optional Debian builder imports matching vendor
modules/firmware: [build guide](docs/building.md#optional-debian-rootfs).

### B · Build and package Yocto

Build a kernel, DTB and rootfs using `meta-az0x`. Point to your existing build
and `oe-init-build-env`; keep the same image recipe throughout:

```sh
make yocto-build \
  YOCTO_BUILD_DIR=/absolute/path/build \
  YOCTO_INIT=/absolute/path/poky/oe-init-build-env \
  YOCTO_IMAGE=core-image-minimal

make yocto \
  FIRMWARE_IMG=/absolute/path/PRIME4PLUS-5.0.4-Update.img \
  YOCTO_BUILD_DIR=/absolute/path/build \
  YOCTO_IMAGE=core-image-minimal \
  IMAGE_LABEL=myroot
```

Already built? Skip `yocto-build` and give `YOCTO_DEPLOY_DIR` to `make yocto`.
The build task selects `az0x-signed`, `yocto-rt` (or `YOCTO_PROVIDER=yocto`)
and systemd via a temporary BitBake configuration; it leaves `local.conf` alone.

The packaging task takes `kernel.fit` and the recipe's `.rootfs.ext4` from that
deploy directory, substitutes the kernel + board DTB + bootargs into the vendor
FIT, and assembles the USB image. **Keep kernel and rootfs from the same build.**

[Yocto integration, limits and validation →](docs/meta-az0x.md)

### Outputs

```text
images/
├── myroot-kernel-partition.img   → controller's internal kernel partition
├── myroot-root.img               → whole USB stick (GPT + ext4)
└── myroot-restore.img            → original vendor kernel partition
```

## Write & boot

**Build targets never write to devices.** Inspect both targets first:

```sh
lsblk -o NAME,SIZE,TRAN,MOUNTPOINTS,MODEL
fastboot devices
```

Then check the artifacts without touching anything:

```sh
make verify FIRMWARE_IMG=/absolute/path/PRIME4PLUS-5.0.4-Update.img IMAGE_LABEL=myroot
```

Unmount the chosen stick's partitions yourself, then explicitly opt in:

```sh
# ERASES the whole USB disk. Replace /dev/sdX; do not use a partition path.
sudo make flash-usb USB_DEVICE=/dev/sdX IMAGE_LABEL=myroot CONFIRM=YES

# Controller must already be in fastboot. Use its actual serial.
make flash-kernel SERIAL=YOUR_DEVICE_SERIAL IMAGE_LABEL=myroot CONFIRM=YES
```

The scripts refuse a mounted/non-USB disk, an unspecified fastboot device, or an
oversized kernel image. **Neither task reboots.** Insert the stick, then reboot
or power-cycle the controller yourself. First-test a custom kernel with serial
console attached; `rootwait` can wait forever if the stick cannot be found.

**Back to stock:**

```sh
make restore SERIAL=YOUR_DEVICE_SERIAL IMAGE_LABEL=myroot CONFIRM=YES
```

Then reboot manually. Removing the stick alone does **not** restore stock boot.
[Flashing, safety and recovery →](docs/flashing.md)

## Make targets

| Target | What it does |
|---|---|
| `make` | Show help; no build or device access |
| `make repack` | Vendor FIT + boot label → kernel image + restore image |
| `make yocto-build` | Run BitBake in your configured build; may fetch/build dependencies |
| `make yocto` | Package existing Yocto FIT + rootfs; no implicit BitBake or flashing |
| `make image` | `ROOTFS_DIR` or `ROOTFS_IMAGE` → GPT USB image |
| `make verify` | Static pre-flight of built artifacts; reads files only |
| `make rootfs` | Optional Debian rootfs; needs sudo and network |
| `make flash-usb` / `flash-kernel` / `restore` | Explicit, opt-in device writes |
| `make lint` / `test` | Static checks and synthetic tests; no real device writes |
| `make clean` / `distclean` | Remove generated files; `distclean` also removes rootfs/cache |

All settings have defaults in [`config.env`](config.env); override with Make
arguments or environment variables. Use the **same `IMAGE_LABEL`** for packaging,
writing and restoring. `make kernel` is the low-level packer that `repack`
wraps; it respects `CUSTOM_FIT`, so prefer `repack` for the vendor-only route.

## Scope & safety

- Only the controller's **`kernel` partition** is written by the flash tasks;
  SPL, U-Boot, internal `rootfs` and `data` are not flashed.
- Directory/Debian images include eMMC read-only and bootcount-reset units.
  Imported ext4 images receive fstab checks, **not a full safety-policy audit**;
  their own distro must provide eMMC lockdown and bootcount reset.
- Signature-stream checks catch repacking mistakes. They are **not** a test of
  a real bootloader, DRAM layout, drivers or the complete Yocto system.
- No firmware, signing keys or device images are distributed here.

## Documentation

| Guide | Covers |
|---|---|
| [Building](docs/building.md) | Configuration, dependencies and optional Debian path |
| [Yocto + meta-az0x](docs/meta-az0x.md) | Build/package contract and custom-kernel bring-up |
| [Flashing](docs/flashing.md) | Target checks, USB writes, fastboot and restore |
| [Boot mechanism](docs/boot-mechanism.md) | FIT layout, both repack modes and evidence limits |
