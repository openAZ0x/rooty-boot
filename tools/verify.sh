#!/usr/bin/env bash
# Static pre-flight for generated artifacts. Reads files only: no device,
# no writes to images, no network. Verifies that what would be flashed is
# internally consistent and that the restore artifact is the stock one.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source config.env

log() { printf '\n\033[1;32m>>\033[0m %s\n' "$*"; }
ok()  { printf '  ok   %s\n' "$*"; }
warn(){ printf '  warn %s\n' "$*"; }
die() { printf '  FAIL %s\n' "$*" >&2; exit 1; }

KIMG="$IMAGES_OUT/$IMAGE_LABEL-kernel-partition.img"
RIMG="$IMAGES_OUT/$IMAGE_LABEL-restore.img"
DIMG="$IMAGES_OUT/$ROOTFS_IMG"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

for b in debugfs od dtc sgdisk e2fsck; do
  command -v "$b" >/dev/null || die "missing $b"
done

# ---------------------------------------------------------------- kernel image
log "kernel partition image"
[[ -f "$KIMG" ]] || die "missing $KIMG"
size=$(stat -c%s "$KIMG")
(( size % 1024 == 0 )) || die "size $size is not a whole number of KiB"
if [[ -n "$CUSTOM_FIT" ]]; then
  limit=$(( KERNEL_PARTITION_MIB * 1024 * 1024 ))
else
  limit=$size
fi
(( size <= limit )) || die "image ($size) exceeds limit ($limit)"
ok "size $size bytes, label/ext2 container"

debugfs -R 'stat /kernel.fit' "$KIMG" 2>/dev/null | grep -q 'Type: regular' \
  || die "/kernel.fit missing from the ext2 container"
debugfs -R "dump /kernel.fit $WORK/kernel.fit" "$KIMG" >/dev/null 2>&1
[[ $(od -An -tx1 -N4 "$WORK/kernel.fit" | tr -d ' \n') == d00dfeed ]] || die "FIT magic missing"
dtc -I dtb -O dts -o /dev/null "$WORK/kernel.fit" 2>/dev/null || die "FIT does not parse as a device tree"
ok "ext2 contains /kernel.fit, valid FIT structure"

python3 - "$WORK/kernel.fit" "$IMAGE_LABEL" "$BOARD" "$BOOTARGS" "$WORK/bootargs" "$WORK/cmdline.dtbo" <<'PY' || die "FIT policy check failed"
import importlib.util, re, subprocess, sys
fit_path, label, board, expected, out, dtbo = sys.argv[1:7]
spec = importlib.util.spec_from_file_location('rf', 'tools/repack-fit.py')
rf = importlib.util.module_from_spec(spec); spec.loader.exec_module(rf)
fit = rf.Fit(open(fit_path, 'rb').read())
configs = {p.rsplit('/', 2)[-2] for p in fit.signatures()}
for required in ('conf-' + board, 'cmdline'):
    if required not in configs:
        sys.exit('missing configuration ' + required)
if fit.text('/configurations', 'default') != 'conf-' + board:
    sys.exit('default configuration is not conf-' + board)
sigs = fit.signatures()
if not sigs:
    sys.exit('no configuration signatures')
for sig in sigs:
    algo = fit.text(sig, 'algo').lower()
    if algo.split(',')[0] not in ('sha256', 'sha1', 'sha512'):
        sys.exit('unexpected signature algorithm in ' + sig + ': ' + algo)
    if not fit.properties(sig).get('key-name-hint'):
        sys.exit('signature without key-name-hint: ' + sig)
open(dtbo, 'wb').write(fit.payload('fdt-cmdline'))
dts = subprocess.run(['dtc', '-I', 'dtb', '-O', 'dts', dtbo],
                     check=True, text=True, capture_output=True).stdout
m = re.search(r'bootargs\s*=\s*"([^"]*)"', dts)
if not m:
    sys.exit('no bootargs in the command-line overlay')
if m.group(1) != expected:
    sys.exit('bootargs differ from BOOTARGS:\n  FIT:  %s\n  conf: %s' % (m.group(1), expected))
roots = [w for w in m.group(1).split() if w.startswith('root=')]
if roots != ['root=PARTLABEL=' + label]:
    sys.exit('FIT does not select PARTLABEL=' + label)
open(out, 'w').write(m.group(1))
print('  ok   %d signatures; default conf-%s; cmdline selects PARTLABEL=%s'
      % (len(sigs), board, label))
PY
ok "bootargs: $(cat "$WORK/bootargs")"

# ---------------------------------------------------------------- restore image
log "restore image"
[[ -f "$RIMG" ]] || die "missing $RIMG (cannot guarantee recovery)"
cmp -s "$RIMG" "$KIMG" && die "restore image is identical to the tampered kernel image"
if [[ -n "${RESTORE_IMG_SRC:-}" ]]; then
  cmp -s "$RIMG" "$RESTORE_IMG_SRC" || die "restore differs from RESTORE_IMG_SRC"
  ok "byte-identical to RESTORE_IMG_SRC"
elif [[ -n "${FIRMWARE_IMG:-}" ]]; then
  source tools/firmware-source.sh
  resolve_firmware >/dev/null
  cmp -s "$RIMG" "$FW_DIR/kernel.img" || die "restore differs from the firmware's stock kernel partition"
  ok "byte-identical to the stock kernel partition in $(basename "$FIRMWARE_IMG")"
else
  warn "no FIRMWARE_IMG/RESTORE_IMG_SRC set; restore provenance not verified"
fi

# ---------------------------------------------------------------- USB image
log "USB root disk image"
if [[ ! -f "$DIMG" ]]; then
  warn "missing $DIMG; kernel-only check"
else
  sgdisk -v "$DIMG" 2>/dev/null | grep -q 'No problems found' || die "GPT validation failed"
  name=$(sgdisk -i 1 "$DIMG" | awk -F"'" '/Partition name/ {print $2}')
  [[ "$name" == "$IMAGE_LABEL" ]] || die "partition name '$name' != IMAGE_LABEL '$IMAGE_LABEL'"
  secs=$(sgdisk -p "$DIMG" | awk '$1 == 1 {print $3 - $2 + 1}')
  dd if="$DIMG" of="$WORK/part.ext4" bs=512 skip=2048 count="$secs" status=none
  e2fsck -fn "$WORK/part.ext4" >/dev/null 2>&1 || die "ext4 filesystem is not clean"
  label=$(debugfs -R 'stats' "$WORK/part.ext4" 2>/dev/null | sed -n 's/^Filesystem volume name: *//p')
  [[ "$label" == "$IMAGE_LABEL" ]] || die "ext4 label '$label' != IMAGE_LABEL '$IMAGE_LABEL'"
  fstab=$(debugfs -R 'cat /etc/fstab' "$WORK/part.ext4" 2>/dev/null || true)
  grep -qE "^PARTLABEL=${IMAGE_LABEL}[[:space:]]+/[[:space:]]" <<<"$fstab" \
    || die "/etc/fstab does not mount PARTLABEL=$IMAGE_LABEL as /"
  if awk '!/^[[:space:]]*(#|$)/ && /mmcblk0|ff0f0000\.dwmmc|931ad49d-ad59-0849-833a-9bf00af5b60e/ {bad=1} END {exit !bad}' <<<"$fstab"; then
    die "/etc/fstab mounts internal eMMC"
  fi
  ok "GPT valid, partition/ext4 label '$IMAGE_LABEL', fstab root correct, fs clean"
  ok "stick is $(stat -c%s "$DIMG") bytes; partition $(stat -c%s "$WORK/part.ext4") bytes"
fi

log "static checks passed"
echo "  This proves the artifacts are self-consistent and targeted at the"
echo "  configured label. It does NOT prove a particular bootloader accepts"
echo "  the repack, that the kernel runs on your board, or that fastboot is"
echo "  reachable. Keep the restore image and a known fastboot route."
