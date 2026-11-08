#!/usr/bin/env bash
# Explicit opt-in writes only. Builds never invoke this script.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source config.env
die() { echo "flash: $*" >&2; exit 1; }
[[ "$CONFIRM" == YES ]] || die "device writes require CONFIRM=YES; inspect your target first"

case "${1:-}" in
  kernel|restore)
    [[ -n "$SERIAL" ]] || die "set SERIAL from fastboot devices (never select a device implicitly)"
    command -v fastboot >/dev/null || die "fastboot not installed"
    for b in stat awk; do command -v "$b" >/dev/null || die "missing $b"; done
    file="$IMAGES_OUT/$IMAGE_LABEL-kernel-partition.img"
    [[ "$1" == restore ]] && file="$IMAGES_OUT/$IMAGE_LABEL-restore.img"
    [[ -s "$file" ]] || die "image missing: $file"
    fastboot devices | awk -v s="$SERIAL" '$1 == s && $2 == "fastboot" {found=1} END {exit !found}' \
      || die "SERIAL is not listed by fastboot devices"
    reply=$(fastboot -s "$SERIAL" getvar partition-size:kernel 2>&1) \
      || die "cannot read kernel partition size"
    size=$(sed -nE 's/.*partition-size:kernel:[[:space:]]*(0x[[:xdigit:]]+|[0-9]+).*/\1/p' <<<"$reply" | head -1)
    [[ "$size" =~ ^(0x[[:xdigit:]]+|[0-9]+)$ ]] || die "invalid kernel partition size: $reply"
    (( $(stat -c%s "$file") <= size )) || die "image exceeds device kernel partition"
    echo "Writing $file to kernel on $SERIAL (no automatic reboot)."
    fastboot -s "$SERIAL" flash kernel "$file"
    ;;
  usb)
    [[ "$EUID" == 0 ]] || die "USB writes need root: sudo -E make flash-usb ..."
    for b in lsblk findmnt blockdev sgdisk dd stat; do
      command -v "$b" >/dev/null || die "missing $b"
    done
    [[ -n "$USB_DEVICE" && -b "$USB_DEVICE" ]] || die "set USB_DEVICE to the whole USB disk, e.g. /dev/sdX"
    disk=$(readlink -f "$USB_DEVICE")
    [[ $(lsblk -dnro TYPE "$disk") == disk ]] || die "USB_DEVICE must be a whole disk, not a partition"
    [[ $(lsblk -dnro TRAN "$disk") == usb ]] || die "refusing a non-USB disk"
    [[ $(blockdev --getro "$disk") == 0 ]] || die "disk is read-only"
    # Include holders/child partitions so mounted, swap and device-mapper
    # targets cannot be overwritten. Do not auto-unmount anything.
    nodes=$(lsblk -nrpo NAME "$disk") || die "cannot inspect disk children"
    swaps=$(swapon --show=NAME --noheadings) || die "cannot inspect active swap"
    while read -r node; do
      if findmnt -rn -S "$node" >/dev/null; then die "mounted filesystem on $node; unmount it yourself"; fi
      if grep -Fxq "$node" <<<"$swaps"; then die "active swap on $node"; fi
      holders=$(ls /sys/class/block/"$(basename "$node")"/holders) || die "cannot inspect holders on $node"
      [[ -z "$holders" ]] || die "active holders on $node"
    done <<<"$nodes"
    file="$IMAGES_OUT/$ROOTFS_IMG"
    [[ -s "$file" ]] || die "image missing: $file"
    # The input image itself must not live on the disk being erased.
    source_disk=$(findmnt -nro SOURCE -T "$file")
    source_disk=${source_disk%%\[*}
    if [[ -b "$source_disk" ]] && lsblk -s -nrpo NAME "$source_disk" | grep -Fxq "$disk"; then
      die "image is stored on the destination disk"
    fi
    (( $(stat -c%s "$file") <= $(blockdev --getsize64 "$disk") )) || die "USB disk is smaller than image"
    echo "ERASING $disk with $file"
    lsblk -dno NAME,SIZE,MODEL,SERIAL "$disk"
    dd if="$file" of="$disk" bs=4M conv=fsync status=progress
    # The stick may exceed the image size. Move the backup GPT to the actual
    # end of disk; do not resize partitions or touch other disks.
    sgdisk -e "$disk"
    blockdev --rereadpt "$disk"
    ;;
  *) die "usage: bash tools/flash.sh kernel|usb|restore" ;;
esac
