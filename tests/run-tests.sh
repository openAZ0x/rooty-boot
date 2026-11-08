#!/usr/bin/env bash
# tests/run-tests.sh - test suite for the rooty-boot toolchain.
#
#   ./tests/run-tests.sh [filter]     run all tests, or those whose name
#                                     contains the filter substring
#
# Tiers:
#   lint      - syntax/static checks (always run)
#   synthetic - a fake AZ0x firmware exercises the extractor, the
#               download/cache resolver, the vendor-support import and the
#               USB image assembly. No vendor files or network needed
#               (the URL test uses a loopback http server). Needs sudo -n
#               for the import tests.
#   real      - gated on a real firmware update being available: reused
#               from cache/firmware/*/update.img or TEST_FIRMWARE_IMG.
#               The make-kernel test uses the vendored tamper tool
#               (vendor/tamper/) or TEST_TAMPER_PY if set.
#   golden    - gated on TEST_POC_DIR pointing at the CVE-2026-46728 PoC
#               checkout with kernel504-ubuntu-partition.img AND a cached
#               5.0.4 firmware; reproduces the device-tested tampered
#               kernel.fit byte for byte.
set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit
source tests/lib.sh

WORK="${TEST_WORK:-$PWD/tests/work}"
FILTER="${1:-}"
KVER_SYN=6.99.1-synthetic

matches() { [[ -z "$FILTER" || "$1" == *"$FILTER"* ]]; }

clean_path() {
  rm -rf "$@" 2>/dev/null && return 0
  sudo -n rm -rf "$@" 2>/dev/null
}

for b in python3 mke2fs dd stat; do
  command -v "$b" >/dev/null || { echo "missing dependency: $b" >&2; exit 2; }
done

# ---------------------------------------------------------------- fixture
build_fixture() {
  clean_path "$WORK" || { echo "cannot clean $WORK" >&2; exit 2; }
  mkdir -p "$WORK/ktree" \
    "$WORK/rtree/lib/modules/$KVER_SYN" "$WORK/rtree/lib/firmware/brcm" \
    "$WORK/rtree/usr/lib/modprobe.d" "$WORK/rtree/usr/lib/udev/rules.d" \
    "$WORK/stubroot/etc" "$WORK/out"
  head -c 4096 /dev/urandom > "$WORK/kernel.fit.orig"
  cp "$WORK/kernel.fit.orig" "$WORK/ktree/kernel.fit"
  echo "not-a-real-module" > "$WORK/rtree/lib/modules/$KVER_SYN/fake.ko"
  echo 'kernel/fake.ko:' > "$WORK/rtree/lib/modules/$KVER_SYN/modules.dep"
  echo fw-bytes > "$WORK/rtree/lib/firmware/brcm/fw.bin"
  echo "options brcmfmac feature_disable=0x80000" > "$WORK/rtree/usr/lib/modprobe.d/brcmfmac.conf"
  echo "# debian ships its own" > "$WORK/rtree/usr/lib/modprobe.d/systemd.conf"
  echo documentation > "$WORK/rtree/usr/lib/modprobe.d/README"
  echo 'ACTION=="add", TEST=="power/control"' > "$WORK/rtree/usr/lib/udev/rules.d/01-pl330-autosuspend.rules"
  echo 'ENV{SYSTEMD_WANTS}+="dsp-config@x.service"' > "$WORK/rtree/usr/lib/udev/rules.d/79-audio-dsp.rules"
  echo marker-content > "$WORK/stubroot/etc/marker.txt"
  mke2fs -q -F -t ext2 -d "$WORK/ktree" "$WORK/kernel.ext2" 4M
  mke2fs -q -F -t ext2 -d "$WORK/rtree" "$WORK/rootfs.ext2" 8M
  python3 tests/make-az0x.py "$WORK/synthetic.img" \
    --kernel "$WORK/kernel.ext2" --rootfs "$WORK/rootfs.ext2" >/dev/null
  cp "$WORK/synthetic.img" "$WORK/synthetic-url.img"
}

# ---------------------------------------------------------------- lint
t_lint() {
  matches lint || return 0
  local bad=0 s
  for s in tools/*.sh tests/run-tests.sh vendor/rootfs-overlay/usr/local/sbin/*; do
    bash -n "$s" || { bad=1; echo "syntax error: $s"; }
  done
  (( bad )) && fail lint/syntax || ok lint/syntax
  if command -v shellcheck >/dev/null; then
    if shellcheck -S warning tools/*.sh tests/run-tests.sh tests/lib.sh \
       vendor/rootfs-overlay/usr/local/sbin/*; then
      ok lint/shellcheck
    else
      fail lint/shellcheck
    fi
  else
    skip lint/shellcheck "shellcheck not installed"
  fi
  if python3 -m py_compile tools/*.py tests/*.py \
     vendor/tamper/tamper_cmdline.py vendor/tamper/build_attack_fit.py; then
    ok lint/python
  else
    fail lint/python
  fi
}

# ---------------------------------------------------------------- extractor
t_extract() {
  matches extract || return 0
  local d="$WORK/out"
  if python3 tools/extract-firmware.py "$WORK/synthetic.img" "$d" > "$WORK/extract.log" 2>&1; then
    ok extract/ok
  else
    fail extract/ok "$(tail -1 "$WORK/extract.log")"
    return 0
  fi
  cmp -s "$d/kernel.img" "$WORK/kernel.ext2" && ok extract/kernel-identical || fail extract/kernel-identical
  cmp -s "$d/rootfs.img" "$WORK/rootfs.ext2" && ok extract/rootfs-identical || fail extract/rootfs-identical
  want_contains extract/reports-version "SNAPSHOT-TEST" "$WORK/extract.log"

  # bad magic
  cp "$WORK/synthetic.img" "$WORK/badmagic.img"
  printf 'XXXX' | dd of="$WORK/badmagic.img" bs=1 seek=0 conv=notrunc status=none
  if python3 tools/extract-firmware.py "$WORK/badmagic.img" "$WORK/o1" >/dev/null 2>&1; then
    fail extract/bad-magic "accepted"
  else
    ok extract/bad-magic
  fi

  # corrupted payload -> SHA-256 mismatch
  cp "$WORK/synthetic.img" "$WORK/badsha.img"
  local sz
  sz=$(stat -c%s "$WORK/badsha.img")
  printf '\xff' | dd of="$WORK/badsha.img" bs=1 seek=$((sz - 32)) conv=notrunc status=none
  python3 tools/extract-firmware.py "$WORK/badsha.img" "$WORK/o2" > "$WORK/badsha.log" 2>&1
  local rc=$?
  if (( rc )) && grep -q "SHA-256 mismatch" "$WORK/badsha.log"; then
    ok extract/sha-mismatch
  else
    fail extract/sha-mismatch "rc=$rc"
  fi

  # truncated container
  head -c $((sz / 2)) "$WORK/synthetic.img" > "$WORK/trunc.img"
  python3 tools/extract-firmware.py "$WORK/trunc.img" "$WORK/o3" > "$WORK/trunc.log" 2>&1
  rc=$?
  if (( rc )) && grep -qE "past end of file|implausible" "$WORK/trunc.log"; then
    ok extract/truncated
  else
    fail extract/truncated "rc=$rc"
  fi
}

# ---------------------------------------------------------------- resolver
t_fwsource() {
  matches fwsource || return 0
  local cache="$WORK/fwcache" d="$WORK/fwcache/synthetic"
  clean_path "$cache" || { fail fwsource/local-extract "cannot clean $cache"; return 0; }
  clean_path "$d" || { fail fwsource/local-extract "cannot clean $d"; return 0; }
  if FIRMWARE_CACHE_DIR="$cache" FIRMWARE_IMG="$WORK/synthetic.img" \
     bash -c 'source tools/firmware-source.sh; log(){ :; }; resolve_firmware' > "$WORK/fws.log" 2>&1; then
    ok fwsource/local-extract
  else
    fail fwsource/local-extract "$(tail -1 "$WORK/fws.log")"
    return 0
  fi
  want_file fwsource/kernel-img "$d/kernel.img"
  want_file fwsource/rootfs-img "$d/rootfs.img"
  cmp -s "$d/kernel.fit" "$WORK/kernel.fit.orig" && ok fwsource/fit-dumped || fail fwsource/fit-dumped
  FIRMWARE_CACHE_DIR="$cache" FIRMWARE_IMG="$WORK/synthetic.img" \
    bash -c 'source tools/firmware-source.sh; log(){ echo "$*"; }; resolve_firmware' > "$WORK/reuse.log" 2>&1
  want_contains fwsource/reuse "reusing cached" "$WORK/reuse.log"

  # URL path against a loopback http server
  if command -v curl >/dev/null; then
    local port srv rc
    port=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
    python3 -m http.server "$port" --bind 127.0.0.1 --directory "$WORK" > "$WORK/httpd.log" 2>&1 &
    srv=$!
    clean_path "$cache/synthetic-url" \
      || { kill "$srv" 2>/dev/null || true; fail fwsource/url-download "cannot clean cache"; return 0; }
    FIRMWARE_CACHE_DIR="$cache" FIRMWARE_IMG="http://127.0.0.1:$port/synthetic-url.img" \
      bash -c 'source tools/firmware-source.sh; log(){ :; }; resolve_firmware' > "$WORK/url.log" 2>&1
    rc=$?
    kill "$srv" 2>/dev/null || true
    if (( rc == 0 )); then
      ok fwsource/url-download
      want_file fwsource/url-extracted "$cache/synthetic-url/kernel.img"
    else
      fail fwsource/url-download "rc=$rc $(tail -1 "$WORK/url.log")"
    fi
  else
    skip fwsource/url "curl not installed"
  fi
}

# ---------------------------------------------------------------- import
t_import() {
  matches import || return 0
  if ! sudo -n true 2>/dev/null; then
    skip import/image-mode "sudo -n unavailable"
    skip import/tree-mode "sudo -n unavailable"
    skip import/wrong-kversion "sudo -n unavailable"
    return 0
  fi
  local tgt="$WORK/imported"
  clean_path "$tgt" && mkdir -p "$tgt"
  # Redirect is intentionally performed by the unprivileged test runner.
  # shellcheck disable=SC2024
  if sudo env MODULES_SRC="$WORK/rootfs.ext2" ROOTFS_DIR="$tgt" \
       bash tools/import-vendor-support.sh > "$WORK/import.log" 2>&1; then
    ok import/image-mode
  else
    fail import/image-mode "$(tail -1 "$WORK/import.log")"
  fi
  want_contains import/autodetect-kversion "auto-detected KVERSION=$KVER_SYN" "$WORK/import.log"
  want_file import/module "$tgt/lib/modules/$KVER_SYN/fake.ko"
  want_file import/modules-dep "$tgt/lib/modules/$KVER_SYN/modules.dep"
  want_file import/firmware "$tgt/lib/firmware/brcm/fw.bin"
  want_file import/modprobe "$tgt/etc/modprobe.d/brcmfmac.conf"
  want_no_file import/modprobe-systemd-conf "$tgt/etc/modprobe.d/systemd.conf"
  want_file import/udev-rule "$tgt/etc/udev/rules.d/01-pl330-autosuspend.rules"
  want_no_file import/udev-service-rule "$tgt/etc/udev/rules.d/79-audio-dsp.rules"

  tgt="$WORK/imported-tree"
  clean_path "$tgt" && mkdir -p "$tgt"
  # shellcheck disable=SC2024
  if sudo env MODULES_SRC="$WORK/rtree" ROOTFS_DIR="$tgt" \
       bash tools/import-vendor-support.sh > "$WORK/import-tree.log" 2>&1; then
    ok import/tree-mode
  else
    fail import/tree-mode "$(tail -1 "$WORK/import-tree.log")"
  fi
  want_file import/tree-module "$tgt/lib/modules/$KVER_SYN/fake.ko"
  want_file import/tree-firmware "$tgt/lib/firmware/brcm/fw.bin"
  want_file import/tree-modprobe "$tgt/etc/modprobe.d/brcmfmac.conf"

  # shellcheck disable=SC2024
  if sudo env MODULES_SRC="$WORK/rootfs.ext2" ROOTFS_DIR="$WORK/imported" KVERSION=6.0.0-wrong \
       bash tools/import-vendor-support.sh > "$WORK/import-bad.log" 2>&1; then
    fail import/wrong-kversion "exited 0"
  else
    ok import/wrong-kversion
  fi
}

# ---------------------------------------------------------------- eMMC + bootcount safety policy
t_safety() {
  matches safety || return 0
  local root="$WORK/safetyroot" bad="$WORK/safetybad"
  rm -rf "$root" "$bad"
  mkdir -p "$root/etc"
  printf 'PARTLABEL=testroot / ext4 errors=remount-ro 0 1\n' > "$root/etc/fstab"

  if ROOTFS_DIR="$root" bash tools/install-safety-policy.sh > "$WORK/safety-install.log" 2>&1; then
    ok safety/install
  else
    fail safety/install "$(tail -1 "$WORK/safety-install.log")"
    return 0
  fi
  want_file safety/locker "$root/usr/local/sbin/emmc-lockdown"
  want_file safety/bootcount-helper "$root/usr/local/sbin/reset-denon-bootcount"
  [[ -L "$root/etc/systemd/system/local-fs-pre.target.wants/emmc-lockdown.service" ]] \
    && ok safety/lockdown-enabled || fail safety/lockdown-enabled
  [[ -L "$root/etc/systemd/system/sysinit.target.wants/bootcount-reset.service" ]] \
    && ok safety/bootcount-enabled || fail safety/bootcount-enabled
  want_contains safety/udev-parent 'KERNEL=="mmcblk0"' "$root/etc/udev/rules.d/60-emmc-readonly.rules"
  want_contains safety/udev-partitions 'KERNEL=="mmcblk0p[0-9]*"' "$root/etc/udev/rules.d/60-emmc-readonly.rules"
  want_contains safety/udev-ignore 'ENV{UDISKS_IGNORE}="1"' "$root/etc/udev/rules.d/60-emmc-readonly.rules"

  if ROOTFS_DIR="$root" bash tools/check-rootfs-safety.sh > "$WORK/safety-check.log" 2>&1; then
    ok safety/check-clean-rootfs
  else
    fail safety/check-clean-rootfs "$(tail -1 "$WORK/safety-check.log")"
  fi

  # The PMU helper must write zero and verify it.
  echo 9 > "$WORK/bootcount"
  if BOOTCOUNT_PATH="$WORK/bootcount" "$root/usr/local/sbin/reset-denon-bootcount" \
       && [[ $(cat "$WORK/bootcount") == 0 ]]; then
    ok safety/bootcount-reset
  else
    fail safety/bootcount-reset
  fi

  # Unsafe fstab mounts and explicit setrw paths must be rejected.
  cp -a "$root" "$bad"
  echo '/dev/mmcblk0p10 /engine ext4 defaults 0 0' >> "$bad/etc/fstab"
  if ROOTFS_DIR="$bad" bash tools/check-rootfs-safety.sh >/dev/null 2>&1; then
    fail safety/reject-emmc-fstab "accepted"
  else
    ok safety/reject-emmc-fstab
  fi
  rm -rf "$bad"
  cp -a "$root" "$bad"
  mkdir -p "$bad/usr/local/sbin"
  printf '#!/bin/sh\nblockdev --setrw /dev/mmcblk0\n' > "$bad/usr/local/sbin/unsafe"
  chmod +x "$bad/usr/local/sbin/unsafe"
  if ROOTFS_DIR="$bad" bash tools/check-rootfs-safety.sh >/dev/null 2>&1; then
    fail safety/reject-setrw "accepted"
  else
    ok safety/reject-setrw
  fi

  # Unit-test the locker without touching real storage: a temporary block node
  # plus a fake blockdev proves both --setro and --getro are required.
  if sudo -n true 2>/dev/null; then
    rm -rf "${WORK:?}/dev" && mkdir -p "$WORK/dev"
    sudo mknod "$WORK/dev/mmcblk0" b 7 250
    cat > "$WORK/fake-blockdev" <<'EOF'
#!/bin/sh
echo "$*" >> "$BLOCKDEV_LOG"
if [ "$1" = --getro ]; then echo 1; fi
exit 0
EOF
    chmod +x "$WORK/fake-blockdev"
    : > "$WORK/blockdev.log"
    if BLOCKDEV="$WORK/fake-blockdev" BLOCKDEV_LOG="$WORK/blockdev.log" \
       EMMC_DEV_ROOT="$WORK/dev" "$root/usr/local/sbin/emmc-lock-one" "$WORK/dev/mmcblk0"; then
      ok safety/block-layer-lock
    else
      fail safety/block-layer-lock
    fi
    want_contains safety/blockdev-setro "--setro $WORK/dev/mmcblk0" "$WORK/blockdev.log"
    want_contains safety/blockdev-getro "--getro $WORK/dev/mmcblk0" "$WORK/blockdev.log"
    sudo rm -f "$WORK/dev/mmcblk0"
  else
    skip safety/block-layer-lock "sudo -n unavailable for temporary block node"
  fi
}

# ---------------------------------------------------------------- USB image
t_make_image() {
  matches image || return 0
  command -v sgdisk >/dev/null || { skip image/gpt "sgdisk not installed"; return 0; }
  local out="$WORK/imgout" img secs blocks bsz fs_bytes part_bytes
  rm -rf "$out" && mkdir -p "$out"
  if IMAGES_OUT="$out" IMAGE_LABEL=testroot ROOTFS_DIR="$WORK/stubroot" STICK_SIZE_MB=64 \
       bash tools/make-image.sh > "$WORK/mkimg.log" 2>&1; then
    ok image/build
  else
    fail image/build "$(tail -1 "$WORK/mkimg.log")"
    return 0
  fi
  img="$out/testroot-root.img"
  want_file image/output "$img"
  if sgdisk -v "$img" 2>/dev/null | grep -q "No problems found"; then
    ok image/gpt-valid
  else
    fail image/gpt-valid
  fi
  secs=$(sgdisk -p "$img" | awk '$1 == 1 {print $3 - $2 + 1}')
  part_bytes=$(( secs * 512 ))
  dd if="$img" of="$WORK/part.ext4" bs=512 skip=2048 count="$secs" status=none
  debugfs -R "stats" "$WORK/part.ext4" 2>/dev/null > "$WORK/fsstats"
  want_contains image/ext4-label "Filesystem volume name:   testroot" "$WORK/fsstats"
  blocks=$(sed -n 's/^Block count: *\([0-9]*\)$/\1/p' "$WORK/fsstats")
  bsz=$(sed -n 's/^Block size: *\([0-9]*\)$/\1/p' "$WORK/fsstats")
  if [[ "$blocks" && "$bsz" ]]; then
    fs_bytes=$(( blocks * bsz ))
    if (( fs_bytes <= part_bytes )); then
      ok image/fs-fits-partition
    else
      fail image/fs-fits-partition "fs $fs_bytes > partition $part_bytes (clobbers secondary GPT)"
    fi
  else
    fail image/fs-fits-partition "could not parse debugfs stats"
  fi
  debugfs -R "cat /etc/marker.txt" "$WORK/part.ext4" 2>/dev/null > "$WORK/marker.out"
  want_contains image/content "marker-content" "$WORK/marker.out"
  debugfs -R "dump /usr/local/sbin/emmc-lockdown $WORK/image-emmc-lockdown" \
    "$WORK/part.ext4" >/dev/null 2>&1
  want_file image/emmc-lockdown "$WORK/image-emmc-lockdown"
  debugfs -R "dump /usr/local/sbin/reset-denon-bootcount $WORK/image-bootcount-reset" \
    "$WORK/part.ext4" >/dev/null 2>&1
  want_file image/bootcount-reset "$WORK/image-bootcount-reset"
  debugfs -R "stat /etc/systemd/system/local-fs-pre.target.wants/emmc-lockdown.service" \
    "$WORK/part.ext4" 2>/dev/null > "$WORK/image-lockdown-unit"
  want_contains image/lockdown-enabled "Type: symlink" "$WORK/image-lockdown-unit"
}

# ---------------------------------------------------------------- real firmware (gated)
cached_real() {  # prints the first cache dir with a full real extraction
  local d
  for d in cache/firmware/*; do
    if [[ -f "$d/kernel.fit" && -f "$d/kernel.img" && -f "$d/rootfs.img" ]]; then
      echo "$d"
      return 0
    fi
  done
  return 1
}

t_real() {
  matches real || return 0
  local src="" d="$WORK/real"
  if [[ -n "${TEST_FIRMWARE_IMG:-}" ]]; then
    src=$TEST_FIRMWARE_IMG
  else
    local f
    for f in cache/firmware/*/update.img; do
      [[ -f "$f" ]] && { src=$f; break; }
    done
  fi
  if [[ -z "$src" ]]; then
    skip real/extract "no cached firmware; set TEST_FIRMWARE_IMG (or run a build once)"
    skip real/make-kernel "depends on real/extract"
    return 0
  fi
  rm -rf "$d" && mkdir -p "$d"
  if python3 tools/extract-firmware.py "$src" "$d" > "$WORK/real.log" 2>&1; then
    ok real/extract
  else
    fail real/extract "$(tail -1 "$WORK/real.log")"
    return 0
  fi
  local ks
  ks=$(stat -c%s "$d/kernel.img")
  if (( ks > 5 * 1024 * 1024 && ks < 10 * 1024 * 1024 )); then
    ok real/kernel-partition-size
  else
    fail real/kernel-partition-size "$ks"
  fi
  if debugfs -R "dump /kernel.fit $d/real.fit" "$d/kernel.img" >/dev/null 2>&1 \
     && [[ "$(od -An -tx1 -N4 "$d/real.fit" | tr -d ' \n')" == "d00dfeed" ]]; then
    ok real/fit-magic
  else
    fail real/fit-magic
  fi
  if debugfs -R "ls /lib/modules" "$d/rootfs.img" 2>/dev/null | grep -q "az01"; then
    ok real/module-tree
  else
    fail real/module-tree
  fi

  # make-kernel round-trip on real inputs
  local c tp out part
  c=$(cached_real) || c=""
  tp=${TEST_TAMPER_PY:-$PWD/vendor/tamper/tamper_cmdline.py}
  if [[ -z "$c" || -z "$tp" ]]; then
    skip real/make-kernel "needs a firmware cache entry and TEST_TAMPER_PY"
    return 0
  fi
  out="$WORK/mk1"
  rm -rf "$out" && mkdir -p "$out"
  if KERNEL_ITB="$c/kernel.fit" RESTORE_IMG_SRC="$c/kernel.img" TAMPER_PY="$tp" \
     IMAGES_OUT="$out" IMAGE_LABEL=tt \
     BOOTARGS="root=PARTLABEL=tt rootwait rw console=ttyS3,115200n8 loglevel=4" \
     bash tools/make-kernel.sh > "$WORK/mkk1.log" 2>&1; then
    ok real/make-kernel
  else
    fail real/make-kernel "$(tail -1 "$WORK/mkk1.log")"
    return 0
  fi
  part="$out/tt-kernel-partition.img"
  if [[ "$(stat -c%s "$part")" == "$(stat -c%s "$c/kernel.img")" ]]; then
    ok real/kernel-stock-size
  else
    fail real/kernel-stock-size
  fi
  debugfs -R "dump /kernel.fit $WORK/mine1.fit" "$part" >/dev/null 2>&1
  if grep -aqF "root=PARTLABEL=tt" "$WORK/mine1.fit"; then
    ok real/bootargs-embedded
  else
    fail real/bootargs-embedded
  fi
  if cmp -s "$out/tt-restore.img" "$c/kernel.img"; then
    ok real/restore-identical
  else
    fail real/restore-identical
  fi
  out="$WORK/mk2"
  rm -rf "$out" && mkdir -p "$out"
  KERNEL_ITB="$c/kernel.fit" RESTORE_IMG_SRC="$c/kernel.img" TAMPER_PY="$tp" \
    IMAGES_OUT="$out" IMAGE_LABEL=tt \
    BOOTARGS="root=PARTLABEL=tt rootwait rw console=ttyS3,115200n8 loglevel=4" \
    bash tools/make-kernel.sh > "$WORK/mkk2.log" 2>&1
  debugfs -R "dump /kernel.fit $WORK/mine2.fit" "$out/tt-kernel-partition.img" >/dev/null 2>&1
  if cmp -s "$WORK/mine1.fit" "$WORK/mine2.fit"; then
    ok real/tamper-deterministic
  else
    fail real/tamper-deterministic
  fi
}

# ---------------------------------------------------------------- golden (gated)
t_golden() {
  matches golden || return 0
  local poc=${TEST_POC_DIR:-}
  if [[ -z "$poc" || ! -f "$poc/kernel504-ubuntu-partition.img" ]]; then
    skip golden/byte-identical "TEST_POC_DIR unset or missing kernel504-ubuntu-partition.img"
    return 0
  fi
  local tp=${TEST_TAMPER_PY:-$PWD/vendor/tamper/tamper_cmdline.py} c="" d
  for d in cache/firmware/*5.0.4*; do
    [[ -f "$d/kernel.fit" ]] && { c=$d; break; }
  done
  if [[ -z "$c" || -z "$tp" ]]; then
    skip golden/byte-identical "needs a cached 5.0.4 firmware and TEST_TAMPER_PY"
    return 0
  fi
  debugfs -R "dump /kernel.fit $WORK/poc.fit" "$poc/kernel504-ubuntu-partition.img" >/dev/null 2>&1
  local out="$WORK/golden"
  rm -rf "$out" && mkdir -p "$out"
  # Historical artifact uses root=LABEL, unlike today's PARTLABEL workflow.
  # Exercise the unchanged low-level helper directly with that exact overlay.
  sed 's|@@BOOTARGS@@|root=LABEL=ubuntu-root rootwait rw console=ttyS3,115200n8 loglevel=7 fsck.repair=yes systemd.getty_auto=n|' \
    vendor/cmdline.dts.in > "$out/golden.dts"
  dtc -@ -I dts -O dtb "$out/golden.dts" -o "$out/golden.dtbo"
  python3 "$tp" "$c/kernel.fit" "$WORK/gold.fit" "$out/golden.dtbo" > "$WORK/golden.log" 2>&1 \
    || { fail golden/byte-identical "$(tail -1 "$WORK/golden.log")"; return 0; }
  if cmp -s "$WORK/gold.fit" "$WORK/poc.fit"; then
    ok golden/byte-identical
  else
    fail golden/byte-identical "tampered fit differs from the device-tested PoC artifact"
  fi
}

# ------------------------------------------------- prebuilt rootfs image import
t_make_image_import() {
  matches image || return 0
  command -v sgdisk >/dev/null || { skip image-import/gpt "sgdisk not installed"; return 0; }
  command -v mkfs.ext4 >/dev/null || { skip image-import/mkfs "mkfs.ext4 not installed"; return 0; }
  local out="$WORK/imgimport" src="$WORK/src-rootfs.ext4" secs part_bytes img
  rm -rf "$out" && mkdir -p "$out" "$WORK/srcroot/etc"
  printf 'PARTLABEL=elsewhere / ext4 defaults 0 1\n# keep me\n' > "$WORK/srcroot/etc/fstab"
  echo "hello" > "$WORK/srcroot/marker"
  mkfs.ext4 -q -F -L oldlabel -d "$WORK/srcroot" "$src" 16M

  if ROOTFS_IMAGE="$src" IMAGES_OUT="$out" IMAGE_LABEL=denonlinux STICK_SIZE_MB=64 \
       bash tools/make-image.sh > "$WORK/imgimport.log" 2>&1; then
    ok image-import/build
  else
    fail image-import/build "$(tail -1 "$WORK/imgimport.log")"
    return 0
  fi

  img="$out/denonlinux-root.img"
  want_file image-import/output "$img"
  if sgdisk -i 1 "$img" 2>/dev/null | grep -q "Partition name: 'denonlinux'"; then
    ok image-import/partition-label
  else
    fail image-import/partition-label
  fi

  secs=$(sgdisk -p "$img" | awk '$1 == 1 {print $3 - $2 + 1}')
  part_bytes=$(( secs * 512 ))
  dd if="$img" of="$WORK/import-part.ext4" bs=512 skip=2048 count="$secs" status=none
  debugfs -R "stats" "$WORK/import-part.ext4" 2>/dev/null > "$WORK/import-fsstats"
  want_contains image-import/ext4-label "Filesystem volume name:   denonlinux" "$WORK/import-fsstats"

  # The source filesystem is 16 MiB; the partition is 63 MiB, so it must grow.
  local blocks bsz fs_bytes
  blocks=$(sed -n 's/^Block count: *\([0-9]*\)$/\1/p' "$WORK/import-fsstats")
  bsz=$(sed -n 's/^Block size: *\([0-9]*\)$/\1/p' "$WORK/import-fsstats")
  fs_bytes=$(( blocks * bsz ))
  # resize2fs fills the partition but rounds down to a block boundary (and may
  # leave a block group of slack), so require "most of the partition" rather
  # than an exact byte match.
  if (( fs_bytes <= part_bytes )) && (( fs_bytes > part_bytes - 1024*1024 )); then
    ok image-import/grown-to-partition
  else
    fail image-import/grown-to-partition "$fs_bytes != ~$part_bytes (block size $bsz)"
  fi

  debugfs -R "cat /etc/fstab" "$WORK/import-part.ext4" 2>/dev/null > "$WORK/import-fstab"
  want_contains image-import/fstab-rewritten \
    "PARTLABEL=denonlinux / ext4 rw,errors=remount-ro 0 1" "$WORK/import-fstab"
  want_contains image-import/fstab-preserved "# keep me" "$WORK/import-fstab"
  if debugfs -R "cat /marker" "$WORK/import-part.ext4" 2>/dev/null | grep -qx hello; then
    ok image-import/content-verbatim
  else
    fail image-import/content-verbatim
  fi

  # An image that mounts the internal eMMC must be refused.
  rm -rf "$WORK/badroot" && mkdir -p "$WORK/badroot/etc"
  printf '/dev/mmcblk0p3 /mnt/data ext4 defaults 0 0\n' > "$WORK/badroot/etc/fstab"
  mkfs.ext4 -q -F -L bad -d "$WORK/badroot" "$WORK/bad-rootfs.ext4" 16M
  if ROOTFS_IMAGE="$WORK/bad-rootfs.ext4" IMAGES_OUT="$WORK/badout" IMAGE_LABEL=bad \
       STICK_SIZE_MB=64 bash tools/make-image.sh > "$WORK/imgbad.log" 2>&1; then
    fail image-import/emmc-refused "accepted an fstab that mounts /dev/mmcblk"
  else
    ok image-import/emmc-refused
  fi
}

build_fixture
t_lint
t_extract
t_fwsource
t_import
t_safety
t_make_image
t_make_image_import
t_real
t_golden

# Import tests run as root; return work files to the caller so make clean and
# the next test run never depend on root-owned leftovers.
if sudo -n true 2>/dev/null; then
  sudo chown -R "$(id -u):$(id -g)" "$WORK" 2>/dev/null || true
fi
finish
