# Flashing & recovery

[← README](../README.md) · [Build settings](building.md) · [Boot mechanism](boot-mechanism.md)

## Before writing

- Build from a vendor release matching the installed firmware. Keep its stock
  `<label>-restore.img` somewhere safe, not only on the USB stick being erased.
- Run the static pre-flight and read its output before any write:
  `make verify FIRMWARE_IMG=… IMAGE_LABEL=myroot`. It checks the ext2/FIT
  structure, bootargs, restore provenance and the USB filesystem.
- Confirm the device's fastboot entry procedure from its manual or your already
  verified method. This guide does not guess a hardware button combination.
- Use the correct USB device-mode connection for your controller and a data
  cable. `fastboot devices` must show the target before flashing.
- Under WSL, attach the USB device to the distro first (`usbipd`), otherwise
  neither `fastboot` nor `lsblk` can see it.
- For a custom kernel, attach serial console before the first test. A signature
  rejection or early kernel failure may leave the screen unchanged.

## 1. Write the stick

Inspect disks and unmount the chosen USB disk's filesystems yourself:

```sh
lsblk -o NAME,SIZE,TRAN,MOUNTPOINTS,MODEL
sudo make flash-usb USB_DEVICE=/dev/sdX IMAGE_LABEL=myroot CONFIRM=YES
```

**This erases the whole selected disk.** The script requires a whole USB disk,
refuses mounted/swap/held devices and undersized disks, and does not unmount
anything automatically. It writes `images/myroot-root.img`, then moves the
backup GPT to the end of the physical stick. The partition remains the generated
size; unused space on a larger stick is not automatically allocated.

## 2. Write the controller's kernel partition

With the controller already in fastboot:

```sh
fastboot devices
make flash-kernel SERIAL=YOUR_DEVICE_SERIAL IMAGE_LABEL=myroot CONFIRM=YES
```

An explicit serial is mandatory, even with one connected device. The script
queries `partition-size:kernel`, rejects an oversized image, then writes only
the `kernel` partition. It does not unlock/format the device or write bootloaders,
the internal rootfs, or the data partition.

**No automatic reboot.** Insert the stick before manually rebooting or
power-cycling. A wrong label/missing stick can leave `rootwait` waiting forever.

## 3. First boot

On serial (`ttyS3`, 115200 for the default JC11S settings), check:

```sh
uname -r
cat /proc/cmdline
findmnt /
ls /lib/modules
```

The kernel version must match the module tree; `/` must be the USB filesystem.
Debian's optional builder enables Ethernet DHCP and SSH. Yocto login/networking
depend on your image recipe. `ROOT_PASSWORD` only configures the Debian builder;
Yocto account policy belongs in your distro.

For a rootfs that includes the eMMC-lockdown/bootcount policy, also verify without
any write probe:

```sh
for d in /dev/mmcblk0 /dev/mmcblk0p*; do
  [ -b "$d" ] || continue
  findmnt -rn -S "$d"       # expected: no mounts
  blockdev --getro "$d"     # expected: 1
done
cat /sys/bus/platform/devices/ff730000.power-management/ff730000.power-management:bootcount/bootcount
# expected: 0, if the bootcount driver and reset service are active
```

## Restore stock boot

Re-enter fastboot using the verified device procedure:

```sh
make restore SERIAL=YOUR_DEVICE_SERIAL IMAGE_LABEL=myroot CONFIRM=YES
```

Then manually reboot. Only `kernel` is restored; it contains the original vendor
FIT and bootargs. Merely removing the stick is **not** a rollback, and keeping
the vendor board configuration valid does **not** create an automatic fallback.

Recovery depends on fastboot remaining reachable and having the correct restore
image; this project does not promise unconditional recovery from hardware or
bootloader failure. Do not use bootloader update/format/reset commands.
