#!/usr/bin/env bash
# Install/reinstall the invariant Debian-side eMMC and bootcount policy.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source config.env

[[ -d "$ROOTFS_DIR" ]] || { echo "rootfs missing: $ROOTFS_DIR" >&2; exit 1; }
[[ -d "$SAFETY_OVERLAY_DIR" ]] || { echo "safety overlay missing: $SAFETY_OVERLAY_DIR" >&2; exit 1; }

cp -a "$SAFETY_OVERLAY_DIR"/. "$ROOTFS_DIR"/
chmod 0755 \
  "$ROOTFS_DIR/usr/local/sbin/emmc-lock-one" \
  "$ROOTFS_DIR/usr/local/sbin/emmc-lockdown" \
  "$ROOTFS_DIR/usr/local/sbin/reset-denon-bootcount"

mkdir -p \
  "$ROOTFS_DIR/etc/systemd/system/local-fs-pre.target.wants" \
  "$ROOTFS_DIR/etc/systemd/system/sysinit.target.wants"
ln -sfn ../emmc-lockdown.service \
  "$ROOTFS_DIR/etc/systemd/system/local-fs-pre.target.wants/emmc-lockdown.service"
ln -sfn ../bootcount-reset.service \
  "$ROOTFS_DIR/etc/systemd/system/sysinit.target.wants/bootcount-reset.service"
