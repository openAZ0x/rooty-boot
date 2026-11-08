#!/usr/bin/env bash
# Reject an image that could automount/write eMMC or lacks the safety policy.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source config.env

die() { echo "rootfs-safety: FATAL: $*" >&2; exit 1; }
need_exec() { [[ -x "$ROOTFS_DIR$1" ]] || die "missing executable $1"; }

[[ -d "$ROOTFS_DIR" ]] || die "rootfs missing: $ROOTFS_DIR"
need_exec /usr/local/sbin/emmc-lock-one
need_exec /usr/local/sbin/emmc-lockdown
need_exec /usr/local/sbin/reset-denon-bootcount

[[ -L "$ROOTFS_DIR/etc/systemd/system/local-fs-pre.target.wants/emmc-lockdown.service" ]] \
  || die "emmc-lockdown.service is not enabled"
[[ -L "$ROOTFS_DIR/etc/systemd/system/sysinit.target.wants/bootcount-reset.service" ]] \
  || die "bootcount-reset.service is not enabled"

if [[ -f "$ROOTFS_DIR/etc/fstab" ]] \
   && awk '!/^[[:space:]]*(#|$)/ && /mmcblk0|ff0f0000\.dwmmc|931ad49d-ad59-0849-833a-9bf00af5b60e/ { bad=1 } END { exit !bad }' \
      "$ROOTFS_DIR/etc/fstab"; then
  die "fstab contains an active internal-eMMC mount"
fi

search_roots=()
for p in "$ROOTFS_DIR/etc" "$ROOTFS_DIR/usr/local" "$ROOTFS_DIR/usr/lib/systemd"; do
  [[ -e "$p" ]] && search_roots+=("$p")
done
if (( ${#search_roots[@]} )); then
  grep -RIlE 'mount[[:space:]].*(/dev/)?mmcblk0|blockdev[[:space:]]+--setrw|az01config[[:space:]]+(set|clear)-flag|What=.*mmcblk0' \
    "${search_roots[@]}" > /tmp/rootfs-safety-matches.$$ 2>/dev/null || true
  if [[ -s /tmp/rootfs-safety-matches.$$ ]]; then
    matches=$(tr '\n' ' ' < /tmp/rootfs-safety-matches.$$)
    rm -f /tmp/rootfs-safety-matches.$$
    die "unsafe eMMC write/mount reference: $matches"
  fi
  rm -f /tmp/rootfs-safety-matches.$$
fi

# Generic desktop automounters are deliberately absent. The vendor edisksd
# daemon is never imported by the driver-support copy.
if [[ -f "$ROOTFS_DIR/var/lib/dpkg/status" ]]; then
  for pkg in udisks2 udiskie gvfs-daemons usbmount autofs; do
    if awk -v p="$pkg" 'BEGIN { RS="" } $0 ~ "(^|\\n)Package: " p "(\\n|$)" && $0 ~ "(^|\\n)Status: install ok installed(\\n|$)" { found=1 } END { exit !found }' \
       "$ROOTFS_DIR/var/lib/dpkg/status"; then
      die "automounter package installed: $pkg"
    fi
  done
fi

echo "rootfs-safety: OK - no default eMMC mounts; lockdown + bootcount reset enabled"
