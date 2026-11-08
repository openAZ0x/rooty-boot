#!/usr/bin/env bash
# Tamper the signed vendor kernel.fit so it boots OUR command line, then wrap
# the result into a fastboot-flashable ext2 `kernel` partition image.
#
# By default only fdt-cmdline changes. With CUSTOM_FIT set, replace the
# kernel and board DTB from that Yocto FIT too (experimental).
# See docs/boot-mechanism.md. No private key is involved and no bootloader is
# replaced - the tool exploits the FIT hashed-nodes signature bypass
# (CVE-2026-46728, fixed upstream in U-Boot 2026.07).
#
# Requires, all supplied by you (see config.env):
#   KERNEL_ITB       the signed vendor kernel.fit
#   RESTORE_IMG_SRC  a pristine copy of the stock kernel partition
#   TAMPER_PY        the cmdline-tamper tool (ships with the CVE PoC)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source config.env

log() { echo -e "\n\033[1;32m>>\033[0m $*"; }

for b in dtc python3 mke2fs stat; do
  command -v "$b" >/dev/null || { echo "missing $b"; exit 1; }
done

# Optionally derive KERNEL_ITB + RESTORE_IMG_SRC from a firmware update file
# (path or URL). Mutually exclusive with setting them explicitly.
source tools/firmware-source.sh
if [[ -n "${FIRMWARE_IMG:-}" ]]; then
  if [[ -n "$KERNEL_ITB" || -n "$RESTORE_IMG_SRC" ]]; then
    echo "FATAL: FIRMWARE_IMG and KERNEL_ITB/RESTORE_IMG_SRC are both set; unset one set" >&2
    exit 1
  fi
  resolve_firmware
  KERNEL_ITB="$FW_DIR/kernel.fit"
  RESTORE_IMG_SRC="$FW_DIR/kernel.img"
  log "KERNEL_ITB/RESTORE_IMG_SRC <- FIRMWARE_IMG cache: $FW_DIR"
fi

[[ -n "$KERNEL_ITB" && -f "$KERNEL_ITB" ]] || { echo "KERNEL_ITB not set or missing"; exit 1; }
[[ -n "$TAMPER_PY" && -f "$TAMPER_PY" ]] || { echo "TAMPER_PY not set or missing"; exit 1; }
[[ -n "$RESTORE_IMG_SRC" && -f "$RESTORE_IMG_SRC" ]] || { echo "RESTORE_IMG_SRC not set or missing"; exit 1; }
python3 - "$BOOTARGS" "$IMAGE_LABEL" <<'PY'
import sys
roots = [word for word in sys.argv[1].split() if word.startswith('root=')]
if roots != ['root=PARTLABEL=' + sys.argv[2]]:
    sys.exit('BOOTARGS must select exactly one root=PARTLABEL=' + sys.argv[2])
PY

mkdir -p "$IMAGES_OUT"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ---------------------------------------------------------------- cmdline overlay
log "building fdt-cmdline overlay (bootargs: $BOOTARGS)"
python3 - "$BOOTARGS" "$WORK/cmdline.dts" <<'PY'
import sys
bootargs = sys.argv[1]
out = sys.argv[2]
tpl = open("vendor/cmdline.dts.in").read()
assert "@@BOOTARGS@@" in tpl
import json
open(out, "w").write(tpl.replace('"@@BOOTARGS@@"', json.dumps(bootargs)))
PY

dtc -@ -I dts -O dtb "$WORK/cmdline.dts" -o "$WORK/cmdline.dtbo"

# ---------------------------------------------------------------- tamper
log "tampering $KERNEL_ITB"
if [[ -n "$CUSTOM_FIT" ]]; then
  [[ -f "$CUSTOM_FIT" ]] || { echo "CUSTOM_FIT not found: $CUSTOM_FIT" >&2; exit 1; }
  echo "EXPERIMENTAL: replacing kernel + DTB; a matching USB rootfs is required."
  python3 tools/repack-fit.py "$KERNEL_ITB" "$WORK/tampered.fit" \
    "$CUSTOM_FIT" "$WORK/cmdline.dtbo" --board "$BOARD"
else
  python3 "$TAMPER_PY" "$KERNEL_ITB" "$WORK/tampered.fit" "$WORK/cmdline.dtbo"
fi

# ---------------------------------------------------------------- ext2 partition
# U-Boot loads /kernel.fit from the root of the ext2 `kernel` partition. Build a
# compact ext2 (no 64-bit / no metadata_csum - the bootloader's loader wants a
# plain fs) containing the tampered fit. The stock artifact may be smaller
# than the physical GPT slot; custom kernels can use the configured slot size.
log "building kernel partition ext2 image"
mkdir -p "$WORK/kdir"
cp "$WORK/tampered.fit" "$WORK/kdir/kernel.fit"
part_bytes=$(stat -c%s "$RESTORE_IMG_SRC")
if [[ -n "$CUSTOM_FIT" ]]; then
  [[ "$KERNEL_PARTITION_MIB" =~ ^[1-9][0-9]*$ ]] || { echo "invalid KERNEL_PARTITION_MIB" >&2; exit 1; }
  part_bytes=$(( KERNEL_PARTITION_MIB * 1024 * 1024 ))
fi
fit_bytes=$(stat -c%s "$WORK/tampered.fit")
if (( fit_bytes > part_bytes )); then
  echo "FATAL: tampered fit (${fit_bytes} bytes) is larger than the output kernel image (${part_bytes} bytes)" >&2
  exit 1
fi
if (( fit_bytes + 131072 > part_bytes )); then
  echo "WARNING: tampered fit leaves only $((part_bytes - fit_bytes)) bytes of ext2 slack; mke2fs may not fit it"
fi
mke2fs -q -F -t ext2 -O '^64bit,^metadata_csum' -L kernel \
  -d "$WORK/kdir" "$WORK/kernel.img" "$(( part_bytes / 1024 ))K"
mv "$WORK/kernel.img" "$IMAGES_OUT/$IMAGE_LABEL-kernel-partition.img"

# ---------------------------------------------------------------- restore
log "collecting restore image"
cp -f "$RESTORE_IMG_SRC" "$IMAGES_OUT/$IMAGE_LABEL-restore.img"

log "done:"
ls -la "$IMAGES_OUT/"
