# Yocto + meta-az0x

[← README](../README.md) · [Build settings](building.md) · [Flashing](flashing.md)

## Keep the ownership simple

| Project | Owns |
|---|---|
| [`meta-az0x`](https://github.com/openAZ0x/meta-az0x) | Board support, source-built kernel/DTB, vendor firmware packaging |
| Your distro/image layer | Applications, image recipe, runtime services and policy |
| `rooty-boot` | Vendor FIT repack, USB image packaging and explicit flash/restore tasks |

No embedded Yocto checkout, duplicated kernel recipe or new build framework is
needed here. The interface is just **two deployed files** from the same build:

```text
<deploy-dir>/kernel.fit                              # unsigned, vendor-shaped FIT
<deploy-dir>/<image>-az0x-signed.rootfs.ext4           # raw filesystem
```

## 1. Build

Prepare an existing Yocto build following the BSP's README. Stage the vendor
firmware blobs it requires, add your normal image layer if using a custom image,
then run:

```sh
make yocto-build \
  YOCTO_BUILD_DIR=/absolute/path/build \
  YOCTO_INIT=/absolute/path/poky/oe-init-build-env \
  YOCTO_IMAGE=core-image-minimal \
  YOCTO_PROVIDER=yocto-rt
```

If `bitbake` is already in the initialized shell environment, omit `YOCTO_INIT`.
`YOCTO_BUILD_DIR` must still point to that configured build. The wrapper runs
`bitbake -r <temporary-config> virtual/kernel <image>` and sets:

```bitbake
MACHINE:forcevariable = "az0x-signed"
AZ0X_KERNEL_PROVIDER:forcevariable = "yocto-rt"
AZ0X_KERNEL_ALLOW_UNSIGNED:forcevariable = "1"
INIT_MANAGER:forcevariable = "systemd"
```

The early config matters: machine/init selection must happen before their
includes are parsed. `forcevariable` uses OpenEmbedded's default override.
`YOCTO_PROVIDER=yocto` selects the non-RT provider. No permanent configuration
is written by this wrapper; BitBake performs its normal build/fetch/deploy work.
`az0x-image` is **not** supplied by the BSP itself: use your image layer or the
standard `core-image-minimal` recipe. No deploy artifact should be assumed from
an unrelated earlier build.

## 2. Package

```sh
make yocto \
  FIRMWARE_IMG=/absolute/path/PRIME4PLUS-5.0.4-Update.img \
  YOCTO_BUILD_DIR=/absolute/path/build \
  YOCTO_IMAGE=core-image-minimal \
  IMAGE_LABEL=myroot
```

`YOCTO_DEPLOY_DIR` defaults to
`$YOCTO_BUILD_DIR/tmp/deploy/images/az0x-signed`. For a different build layout,
set it explicitly. For a different rootfs filename, override `ROOTFS_IMAGE`.

This task does **not** invoke BitBake or flash anything. It:

1. Extracts the signed vendor FIT and original kernel partition for recovery.
2. Replaces kernel + JC11S board DTB from the unsigned deployed FIT, plus a
   fresh bootargs overlay pointing to `IMAGE_LABEL`.
3. Preserves original external payloads and checks all configuration signature
   streams/RSA values before writing the repacked FIT.
4. Wraps that FIT as `/kernel.fit` in an ext2 kernel-partition image.
5. Assembles the matching raw ext4 rootfs into a labelled GPT USB image.

`AZ0X_FIT_BOOTARGS` in the BSP's unsigned FIT is not the final boot target:
rooty-boot generates the activation overlay from its own `IMAGE_LABEL` and
`BOOTARGS`. There is no requirement to use the BSP's default `denonlinux` label.

## What must match

- **Vendor base/restore:** use the firmware release installed on the target.
  Stay on a known-vulnerable bootloader; a newer patched one rejects activation.
- **Kernel + DTB + modules:** take all from the same Yocto build. The rootfs
  must carry matching `/lib/modules/<kernel-release>` when drivers are modular.
- **Architecture/board:** ARMv7 JC11S, with the expected FIT configuration and
  image names. This is not the aarch64 AZ04 path.
- **USB boot support:** USB host/storage and ext4 support needed before root
  mount must be built into the kernel. No initramfs is supplied by this workflow.
- **Boot label:** use one `IMAGE_LABEL` for both kernel and stick packaging.

The custom kernel's version need **not** equal the vendor kernel version. The
vendor-kernel-only workflow is different: if retaining that kernel, the imported
module tree must match its release (`AZ0X_BOARD_KVER` on a prebuilt BSP build).

## Runtime safety

Raw ext4 imports retain their own distro policy. Packaging checks active fstab
references to internal eMMC, but does not install/audit all services or prevent
automounters from writing internal storage at runtime.

Put the eMMC lockdown units/helpers/rule from `vendor/rootfs-overlay/` into
your image recipe if you want the same read-only policy as the Debian path.
The BSP already provides `az01-bootcount`; include and enable it rather than
installing two competing bootcount-reset services. Check your final image's
enabled units. The Make build wrapper selects systemd, but does not install
those policies on your behalf.

## Validation boundary

**Experimental:** synthetic and real-FIT tests verify combined
kernel/DTB/cmdline repacking, preserved payloads and unchanged signature
streams (`make test`, plus `make verify` over the built artifacts). This is not
a captured physical boot of the complete source-built stack.

First bring-up needs serial console, a known-good restore image and tested
fastboot access. Validate the repacked FIT against your actual bootloader,
check its load/decompression memory ranges, boot, then verify kernel version,
USB root mount, modules, eMMC read-only state and bootcount reset. Do not call
the route hardware-proven until that evidence exists.
