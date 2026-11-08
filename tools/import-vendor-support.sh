#!/usr/bin/env bash
# Import vendor kernel support from the Engine OS rootfs into the Debian tree.
#
# The vendor kernel builds in the root-disk, console and display drivers, so
# the image boots without any of this - but WiFi/BT (brcmfmac), the ilitek
# touchscreen, the eta5805 audio DSPs and the jms578 USB-SATA bridge are
# loadable modules and/or need request_firmware() blobs. From MODULES_SRC (an
# ext2/3/4 rootfs image or an extracted tree) this copies:
#
#   /lib/modules/$KVERSION   -> $ROOTFS_DIR/lib/modules/
#   /lib/firmware            -> $ROOTFS_DIR/lib/firmware/
#   modprobe.d dropins       -> $ROOTFS_DIR/etc/modprobe.d/
#   udev rules (allowlist)   -> $ROOTFS_DIR/etc/udev/rules.d/
#
# Vendor trees may be merged-usr (/lib -> usr/lib symlink) or classic; both
# /lib/... and /usr/lib/... source paths are probed. Run via build-rootfs.sh,
# or standalone (with sudo, and MODULES_SRC/KVERSION in the environment) to
# refresh an already-built rootfs without re-running debootstrap.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source config.env

log() { echo -e "\n\033[1;32m>>\033[0m $*"; }
die() { echo "import-vendor-support: FATAL: $*" >&2; exit 1; }

# Self-contained vendor udev rules worth importing. Rules that spawn vendor
# services (79-audio-dsp.rules -> dsp-config@.service,
# 71-az01-power-button.rules -> az01-power-button.service) are not portable;
# add those via overlay/ if you port the units.
VENDOR_UDEV_RULES="${VENDOR_UDEV_RULES:-01-pl330-autosuspend.rules}"

# Source of the vendor rootfs: either MODULES_SRC directly, or FIRMWARE_IMG
# (a firmware update file/URL, downloaded and extracted on demand).
source tools/firmware-source.sh
if [[ -n "${FIRMWARE_IMG:-}" && -n "$MODULES_SRC" ]]; then
  die "MODULES_SRC and FIRMWARE_IMG are both set; FIRMWARE_IMG extracts its own rootfs - unset one"
fi
if [[ -z "$MODULES_SRC" && -n "${FIRMWARE_IMG:-}" ]]; then
  resolve_firmware
  MODULES_SRC="$FW_DIR/rootfs.img"
  log "vendor rootfs from FIRMWARE_IMG cache: $MODULES_SRC"
fi
[[ -n "$MODULES_SRC" ]] || { log "no MODULES_SRC/FIRMWARE_IMG; assuming kernel has everything built-in"; exit 0; }

[[ -d "$ROOTFS_DIR" ]] || die "rootfs missing at $ROOTFS_DIR - run build-rootfs.sh first"
[[ -e "$MODULES_SRC" ]] || die "MODULES_SRC not found: $MODULES_SRC"

IS_IMG=0
[[ -f "$MODULES_SRC" ]] && IS_IMG=1
if [[ $IS_IMG -eq 1 ]] && ! command -v debugfs >/dev/null; then
  die "MODULES_SRC is an image but debugfs (e2fsprogs) is not installed"
fi

# KVERSION: if unset, auto-detect from the single module tree in the source.
if [[ -z "$KVERSION" ]]; then
  det=""
  for p in /lib/modules /usr/lib/modules; do
    if [[ $IS_IMG -eq 1 ]]; then
      det+=$'\n'$(sudo debugfs -R "ls -p $p" "$MODULES_SRC" 2>/dev/null \
        | awk -F/ 'NF>=6 && $6!="." && $6!=".." {print $6}')
    elif [[ -d "$MODULES_SRC$p" ]]; then
      det+=$'\n'$(ls -1 "$MODULES_SRC$p")
    fi
  done
  mapfile -t kvs < <(printf '%s' "$det" | sed '/^$/d' | sort -u)
  if [[ ${#kvs[@]} -eq 1 ]]; then
    KVERSION=${kvs[0]}
    log "auto-detected KVERSION=$KVERSION"
  elif [[ ${#kvs[@]} -eq 0 ]]; then
    die "KVERSION unset and no /lib/modules/* found in MODULES_SRC"
  else
    die "KVERSION unset and multiple module trees found: ${kvs[*]}"
  fi
fi

# rdump into a fresh staging directory, then merge into $dest. debugfs exit
# status is unreliable, and checking an existing destination used to let stale
# output masquerade as a successful refresh.
img_rdump() {
  local vp="$1" dest="$2" base scratch
  base=$(basename "$vp")
  scratch=$(mktemp -d)
  sudo debugfs -R "rdump $vp $scratch" "$MODULES_SRC" >/dev/null 2>&1 || true
  if [[ -d "$scratch/$base" ]]; then
    sudo mkdir -p "$dest/$base"
    sudo cp -a "$scratch/$base/." "$dest/$base/"
    sudo rm -rf "$scratch"
    return 0
  fi
  sudo rm -rf "$scratch"
  return 1
}

# ---------------------------------------------------------------- modules
mods_done=0
sudo rm -rf "$ROOTFS_DIR/lib/modules/$KVERSION"
for cand in "/lib/modules/$KVERSION" "/usr/lib/modules/$KVERSION"; do
  if [[ $IS_IMG -eq 1 ]]; then
    sudo mkdir -p "$ROOTFS_DIR/lib/modules"
    if img_rdump "$cand" "$ROOTFS_DIR/lib/modules"; then mods_done=1; break; fi
  elif [[ -d "$MODULES_SRC$cand" ]]; then
    sudo mkdir -p "$ROOTFS_DIR/lib/modules"
    sudo cp -a "$MODULES_SRC$cand" "$ROOTFS_DIR/lib/modules/"
    mods_done=1; break
  fi
done
[[ $mods_done -eq 1 ]] || die "no /lib/modules/$KVERSION in MODULES_SRC (wrong KVERSION or wrong source?) - refusing to build a driver-incomplete image"

moddir="$ROOTFS_DIR/lib/modules/$KVERSION"
kos=$(sudo find "$moddir" \( -name '*.ko' -o -name '*.ko.*' \) | wc -l)
log "modules: $kos .ko files for $KVERSION"
[[ $kos -gt 0 ]] || echo "WARNING: module tree for $KVERSION contains no .ko files"
if [[ ! -f "$moddir/modules.dep" ]]; then
  if command -v depmod >/dev/null; then
    log "module metadata missing; running depmod"
    sudo depmod -b "$ROOTFS_DIR" "$KVERSION"
  else
    die "copied module tree lacks modules.dep and depmod is unavailable"
  fi
fi

# ---------------------------------------------------------------- firmware
fw_done=0
for cand in /lib/firmware /usr/lib/firmware; do
  if [[ $IS_IMG -eq 1 ]]; then
    sudo mkdir -p "$ROOTFS_DIR/lib"
    if img_rdump "$cand" "$ROOTFS_DIR/lib"; then fw_done=1; break; fi
  elif [[ -d "$MODULES_SRC$cand" ]]; then
    sudo mkdir -p "$ROOTFS_DIR/lib/firmware"
    sudo cp -a "$MODULES_SRC$cand/." "$ROOTFS_DIR/lib/firmware/"
    fw_done=1; break
  fi
done
if [[ $fw_done -eq 1 ]]; then
  log "firmware: $(sudo du -sh "$ROOTFS_DIR/lib/firmware" | cut -f1)"
else
  echo "WARNING: no /lib/firmware in MODULES_SRC - drivers using request_firmware() will fail"
fi

# ---------------------------------------------------------------- modprobe.d / udev
tmp=$(mktemp -d)
trap 'sudo rm -rf "$tmp"' EXIT

stage_dir() { # stage_dir <subpath e.g. modprobe.d> ; echoes staged dir or fails
  local sub="$1" cand
  for cand in "/lib/$sub" "/usr/lib/$sub"; do
    if [[ $IS_IMG -eq 1 ]]; then
      if img_rdump "$cand" "$tmp"; then echo "$tmp/${cand##*/}"; return 0; fi
    elif [[ -d "$MODULES_SRC$cand" ]]; then
      cp -a "$MODULES_SRC$cand" "$tmp/"
      echo "$tmp/${cand##*/}"
      return 0
    fi
  done
  return 1
}

if mp=$(stage_dir modprobe.d); then
  sudo mkdir -p "$ROOTFS_DIR/etc/modprobe.d"
  n=0
  for f in "$mp"/*.conf; do
    [[ -e "$f" ]] || continue
    b=$(basename "$f")
    # systemd.conf: Debian ships its own; the vendor one would shadow it.
    [[ "$b" == "systemd.conf" ]] && continue
    sudo cp "$f" "$ROOTFS_DIR/etc/modprobe.d/$b"
    n=$((n + 1))
  done
  log "modprobe.d: $n dropin(s)"
fi

if [[ "${VENDOR_UDEV_RULES,,}" != "none" ]] && ud=$(stage_dir udev/rules.d); then
  sudo mkdir -p "$ROOTFS_DIR/etc/udev/rules.d"
  n=0
  for b in $VENDOR_UDEV_RULES; do
    if [[ -e "$ud/$b" ]]; then
      sudo cp "$ud/$b" "$ROOTFS_DIR/etc/udev/rules.d/$b"
      n=$((n + 1))
    else
      echo "WARNING: udev rule $b not found in vendor rootfs"
    fi
  done
  log "udev rules: $n imported"
fi

log "vendor kernel support import complete"
