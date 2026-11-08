#!/usr/bin/env bash
# Assemble the bootable USB stick image from a root filesystem, plus any
# optional `overlay/` files.
#
# The root filesystem comes from one of two sources:
#
#   ROOTFS_DIR    a directory tree, normally built by build-rootfs.sh. This is
#                 the default: overlay/ is applied and the eMMC safety policy
#                 is installed and checked here.
#   ROOTFS_IMAGE  a ready-made raw ext4 image, e.g. the .rootfs.ext4 a Yocto
#                 build emits (see docs/meta-az0x.md). A copy is updated,
#                 relabelled and grown to fill the partition. overlay/ is NOT
#                 applied: the image must already carry its own eMMC lockdown.
#
# Produces images/$IMAGE_LABEL-root.img (dd to a USB stick) as a GPT disk with
# a single ext4 partition named $IMAGE_LABEL - the PARTLABEL the tampered
# cmdline points at. The kernel/restore artifacts are produced separately by
# make-kernel.sh in the same output directory.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source config.env

log() { echo -e "\n\033[1;32m>>\033[0m $*"; }
die() { echo "make-image: $*" >&2; exit 1; }

command -v sgdisk >/dev/null || die "missing sgdisk (apt install gdisk)"
[[ "$STICK_SIZE_MB" =~ ^[1-9][0-9]*$ ]] || die "STICK_SIZE_MB must be a positive integer"

if [[ -n "${ROOTFS_IMAGE:-}" ]]; then
  [[ -f "$ROOTFS_IMAGE" ]] || die "ROOTFS_IMAGE not found: $ROOTFS_IMAGE"
  for b in e2label e2fsck resize2fs debugfs; do
    command -v "$b" >/dev/null || die "missing $b (apt install e2fsprogs)"
  done
  if [[ -d "$ROOTFS_DIR" && -n "$(ls -A "$ROOTFS_DIR" 2>/dev/null)" ]]; then
    log "note: ROOTFS_IMAGE set - using it instead of $ROOTFS_DIR"
  fi
else
  [[ -d "$ROOTFS_DIR" ]] || die "rootfs missing - run build-rootfs.sh first"
  command -v mkfs.ext4 >/dev/null || die "missing mkfs.ext4"
fi

# ---------------------------------------------------------------- overlay
if [[ -z "${ROOTFS_IMAGE:-}" ]]; then
  log "applying overlay files"
  if [[ -d "$OVERLAY_DIR" ]]; then
    cp -a "$OVERLAY_DIR"/. "$ROOTFS_DIR"/
  fi

  # User overlays are applied first; reinstall the invariant policy afterward
  # so it cannot be accidentally replaced, then reject any new eMMC
  # mount/write path.
  log "enforcing rootfs eMMC safety policy"
  bash tools/install-safety-policy.sh
  bash tools/check-rootfs-safety.sh
fi

# ---------------------------------------------------------------- rootfs image
mkdir -p "$IMAGES_OUT"
OUT="$IMAGES_OUT/$ROOTFS_IMG"
if [[ -n "$ROOTFS_IMAGE" ]]; then
  [[ $(realpath "$ROOTFS_IMAGE") != $(realpath -m "$OUT") ]] || die "input rootfs must not be the output disk image"
fi
log "building GPT image $OUT (partition label=$IMAGE_LABEL, ext4 label=$IMAGE_LABEL)"
img_bytes=$(( STICK_SIZE_MB * 1024 * 1024 ))

# 1. Create the GPT first: one partition named $IMAGE_LABEL starting at 1 MiB
#    (sector 2048 at 512B sectors - the standard modern alignment). sgdisk
#    reserves the secondary GPT at the end of the disk automatically.
rm -f "$OUT"
truncate -s "$img_bytes" "$OUT"
sgdisk -o "$OUT" >/dev/null
sgdisk -n "1:2048s:0" -t 1:8300 -c "1:$IMAGE_LABEL" "$OUT" >/dev/null

# 2. Build the ext4 into a raw file sized to the EXACT partition length
#    (larger would overrun the partition and clobber the secondary GPT).
part_sectors=$(sgdisk -p "$OUT" | awk '$1 == 1 {print $3 - $2 + 1}')
[[ "$part_sectors" =~ ^[0-9]+$ ]] || die "could not determine partition length"
part_bytes=$(( part_sectors * 512 ))

tmp_ext4=$(mktemp "$IMAGES_OUT/.rootfs.ext4.XXXXXX")
trap 'rm -f "$tmp_ext4" "$tmp_ext4.fstab"' EXIT

if [[ -n "${ROOTFS_IMAGE:-}" ]]; then
  src_bytes=$(stat -c%s "$ROOTFS_IMAGE")
  if (( src_bytes > part_bytes )); then
    die "ROOTFS_IMAGE ($src_bytes bytes) is larger than the USB partition ($part_bytes bytes); raise STICK_SIZE_MB"
  fi
  log "importing rootfs image ($src_bytes bytes)"
  cp --sparse=always "$ROOTFS_IMAGE" "$tmp_ext4"
  # Always validate, including an image that needs no resizing. Do not edit
  # the input or accept a corrupt/non-ext filesystem because debugfs exited 0.
  rc=0
  e2fsck -f -p "$tmp_ext4" || rc=$?
  (( rc <= 1 )) || die "e2fsck failed on ROOTFS_IMAGE (exit $rc)"

  # We cannot run the directory-based policy checks over an opaque filesystem,
  # so enforce the one invariant that can be read without mounting: the image
  # must not mount the internal eMMC by device path.
  fstab=$(debugfs -R "cat /etc/fstab" "$tmp_ext4" 2>/dev/null || true)
  if awk '!/^[[:space:]]*(#|$)/ && /mmcblk0|ff0f0000\.dwmmc|931ad49d-ad59-0849-833a-9bf00af5b60e/ {bad=1} END {exit !bad}' <<<"$fstab"; then
    die "refusing ROOTFS_IMAGE: /etc/fstab mounts internal eMMC"
  fi

  # Replace all active root entries with one canonical entry; preserve
  # comments and unrelated mounts, even if one old root entry already matched.
  expected_fstab=$(
    printf 'PARTLABEL=%s / ext4 rw,errors=remount-ro 0 1\n' "$IMAGE_LABEL"
    awk '/^[[:space:]]*#/ || (NF && $2 != "/") {print}' <<<"$fstab"
  )
  if [[ "$fstab" != "$expected_fstab" ]]; then
    log "rewriting /etc/fstab root entry to PARTLABEL=$IMAGE_LABEL"
    fstab_new="$tmp_ext4.fstab"
    printf '%s\n' "$expected_fstab" > "$fstab_new"
    debugfs -w -R "rm /etc/fstab" "$tmp_ext4" >/dev/null 2>&1 || true
    debugfs -w -R "write \"$fstab_new\" /etc/fstab" "$tmp_ext4" >/dev/null
    debugfs -w -R "set_inode_field /etc/fstab mode 0100644" "$tmp_ext4" >/dev/null
    actual=$(debugfs -R 'cat /etc/fstab' "$tmp_ext4" 2>/dev/null)
    [[ "$actual" == "$(cat "$fstab_new")" ]] || die "fstab write/readback failed"
    rm -f "$fstab_new"
  fi

  e2label "$tmp_ext4" "$IMAGE_LABEL"
  if (( src_bytes < part_bytes )); then
    truncate -s "$part_bytes" "$tmp_ext4"
    set +e
    e2fsck -f -y "$tmp_ext4" >/dev/null 2>&1; rc=$?
    set -e
    (( rc <= 2 )) || die "e2fsck failed on ROOTFS_IMAGE (exit $rc)"
    resize2fs "$tmp_ext4" >/dev/null
  fi
else
  du_bytes=$(du -sb "$ROOTFS_DIR" | awk '{print $1}')
  if (( du_bytes + 200*1024*1024 > part_bytes )); then
    echo "WARNING: rootfs ($du_bytes bytes) nearly fills the partition ($part_bytes bytes)"
  fi
  mkfs.ext4 -q -F -L "$IMAGE_LABEL" -d "$ROOTFS_DIR" "$tmp_ext4" "$(( part_bytes / 1024 ))K" >/dev/null
fi

# 3. Write the ext4 into the partition (1 MiB offset)
dd if="$tmp_ext4" of="$OUT" bs=1M seek=1 conv=notrunc status=none
rm -f "$tmp_ext4"

log "verifying partition table:"
sgdisk -p "$OUT"

# ---------------------------------------------------------------- flash images
log "collecting flash images"
for f in "$IMAGES_OUT/$IMAGE_LABEL-kernel-partition.img" \
         "$IMAGES_OUT/$IMAGE_LABEL-restore.img"; do
  [[ -f "$f" ]] || { echo "WARNING: $f missing - run make-kernel.sh"; continue; }
done

log "done:"
ls -la "$IMAGES_OUT/"
