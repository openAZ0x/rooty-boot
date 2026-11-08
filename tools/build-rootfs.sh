#!/usr/bin/env bash
# Build a Debian rootfs for booting from USB on a signed-boot controller.
#
# Stage 1/2 debootstrap + base configuration (hostname, fstab, networkd, ssh).
# Device-specific extras belong in the optional `overlay/` directory (copied in
# by make-image.sh) rather than here, so this script stays device-agnostic.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source config.env

log() { echo -e "\n\033[1;32m>>\033[0m $*"; }

[[ -n "$ROOT_PASSWORD" ]] || { echo "ROOT_PASSWORD is empty - set it before building (see config.env)" >&2; exit 1; }

# ---------------------------------------------------------------- deps
for b in debootstrap mkfs.ext4 debugfs; do
  command -v "$b" >/dev/null || { echo "missing $b"; exit 1; }
done
QEMU="${QEMU:-/usr/bin/qemu-arm}"
[[ -x "$QEMU" ]] || { echo "missing qemu-arm"; exit 1; }

# ---------------------------------------------------------------- stage 1
if [[ -f "$ROOTFS_DIR/debootstrap/debootstrap" ]]; then
  log "debootstrap stage-1 already present, skipping"
else
  log "debootstrap --foreign $DISTRO $ARCH"
  rm -rf "$ROOTFS_DIR"
  debootstrap --arch="$ARCH" --foreign --variant=minbase \
    "$DISTRO" "$ROOTFS_DIR" "$MIRROR"
fi

if [[ ! -e "$ROOTFS_DIR/usr/bin/qemu-arm-static" ]]; then
  cp "$QEMU" "$ROOTFS_DIR/usr/bin/qemu-arm-static"
fi

# ---------------------------------------------------------------- stage 2
if [[ -f "$ROOTFS_DIR/debootstrap/debootstrap" ]]; then
  log "debootstrap --second-stage"
  chroot "$ROOTFS_DIR" /debootstrap/debootstrap --second-stage
else
  log "second-stage already done"
fi

# ---------------------------------------------------------------- sources
cat > "$ROOTFS_DIR/etc/apt/sources.list" <<EOF
deb $MIRROR $DISTRO main contrib non-free non-free-firmware
deb $MIRROR $DISTRO-updates main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security $DISTRO-security main contrib non-free non-free-firmware
EOF

# ---------------------------------------------------------------- configure
log "writing base configuration"
cat > "$ROOTFS_DIR/etc/hostname" <<< "$APPLIANCE_HOSTNAME"
cat > "$ROOTFS_DIR/etc/hosts" <<EOF
127.0.0.1 localhost
127.0.1.1 $APPLIANCE_HOSTNAME
EOF

# The kernel is told to mount by PARTLABEL; fstab mirrors that.
cat > "$ROOTFS_DIR/etc/fstab" <<EOF
PARTLABEL=$IMAGE_LABEL / ext4 errors=remount-ro 0 1
EOF

# DHCP on the built-in ethernet via systemd-networkd.
mkdir -p "$ROOTFS_DIR/etc/systemd/network"
cat > "$ROOTFS_DIR/etc/systemd/network/20-ethernet.network" <<'EOF'
[Match]
Name=eth0 en* end0

[Network]
DHCP=yes
EOF

# ssh: root login with password (development convenience for a USB image -
# set a strong ROOT_PASSWORD, or disable this drop-in for production).
mkdir -p "$ROOTFS_DIR/etc/ssh/sshd_config.d"
cat > "$ROOTFS_DIR/etc/ssh/sshd_config.d/10-usbboot.conf" <<'EOF'
PermitRootLogin yes
PasswordAuthentication yes
EOF

cat > "$ROOTFS_DIR/etc/default/locale" <<'EOF'
LANG=C.UTF-8
EOF

# ---------------------------------------------------------------- packages
# Minimal but useful-over-SSH: udev (without it /dev and predictable device
# names break), systemd, ssh, networkd and a couple of admin basics.
log "installing runtime packages (this is the slow network step)"
chroot "$ROOTFS_DIR" bash -c '
  set -e
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends \
    udev \
    systemd-sysv \
    systemd \
    openssh-server \
    iproute2 net-tools \
    python3 \
    sudo \
    ca-certificates locales \
    e2fsprogs dosfstools
  echo "root:$1" | chpasswd
  systemctl enable ssh systemd-networkd systemd-resolved 2>/dev/null || true
' _ "$ROOT_PASSWORD"

# ---------------------------------------------------------------- vendor kernel support (optional)
# Everything the vendor kernel needs beyond what is built in - the module
# tree, /lib/firmware blobs, modprobe.d dropins and vendored udev rules -
# imported from the Engine OS rootfs (MODULES_SRC + KVERSION). Kept in a
# separate script so an existing tree can be refreshed without re-running
# debootstrap. No-ops (with a log line) when MODULES_SRC is empty.
bash tools/import-vendor-support.sh

# Reproducible safety policy: do not mount the internal eMMC in Debian, mark
# its parent disk and every partition block-layer read-only, and reset the PMU
# boot counter at startup/shutdown so Engine OS does not inherit a high count.
bash tools/install-safety-policy.sh
bash tools/check-rootfs-safety.sh

log "rootfs ready at $ROOTFS_DIR"
du -sh "$ROOTFS_DIR"
