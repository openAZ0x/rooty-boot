# shellcheck shell=bash
# firmware-source.sh - sourced (NOT executed) by import-vendor-support.sh and
# make-kernel.sh. Requires config.env sourced and log() defined by the caller.
# (ROOT gets a fallback so the lib also works when sourced standalone.)
#
# Provides resolve_firmware: turns FIRMWARE_IMG (a path or URL to an official
# AZ0x firmware update .img) into a cached extraction:
#
#   cache/firmware/<name>/update.img   the downloaded update (URL case)
#   cache/firmware/<name>/kernel.fit   the signed vendor FIT (KERNEL_ITB)
#   cache/firmware/<name>/kernel.img   the stock `kernel` partition (RESTORE_IMG_SRC)
# cache/firmware/<name>/rootfs.img   the stock rootfs (module/firmware source)
#
# If the extracted outputs already exist and the source file is unchanged, the
# cache is reused (rm -r cache/firmware/<name> to force re-extraction).

ROOT="${ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

resolve_firmware() {
  [[ -n "${FIRMWARE_IMG:-}" ]] || return 1

  local src name sum marker cache_dir
  cache_dir=${FIRMWARE_CACHE_DIR:-$ROOT/cache/firmware}
  if [[ "$FIRMWARE_IMG" =~ ^[a-zA-Z][a-zA-Z0-9+.-]*:// ]]; then
    name=$(basename "${FIRMWARE_IMG%%\?*}")
    name=${name%.img}
    FW_DIR="$cache_dir/$name"
    mkdir -p "$FW_DIR"
    src="$FW_DIR/update.img"
    if [[ -f "$src" ]]; then
      log "using previously downloaded $src"
    else
      command -v curl >/dev/null || { echo "firmware-source: FATAL: FIRMWARE_IMG is a URL but curl is missing" >&2; exit 1; }
      log "downloading $FIRMWARE_IMG"
      curl -fL --retry 3 --retry-delay 2 --retry-connrefused \
        -o "$src.part" "$FIRMWARE_IMG" \
        || { rm -f "$src.part"; echo "firmware-source: FATAL: download failed" >&2; exit 1; }
      mv "$src.part" "$src"
    fi
  else
    src=$FIRMWARE_IMG
    [[ -f "$src" ]] || { echo "firmware-source: FATAL: FIRMWARE_IMG not found: $src" >&2; exit 1; }
    name=$(basename "$src")
    name=${name%.img}
    FW_DIR="$cache_dir/$name"
    mkdir -p "$FW_DIR"
  fi

  marker="$FW_DIR/.source-sha256"
  sum=$(sha256sum "$src" | awk '{print $1}')
  if [[ -f "$FW_DIR/rootfs.img" && -f "$FW_DIR/kernel.img" && -f "$FW_DIR/kernel.fit" && -f "$marker" ]] \
     && [[ $(cat "$marker") == "$sum" ]]; then
    log "reusing cached extraction in $FW_DIR"
    return 0
  fi

  log "extracting kernel/rootfs partitions from $(basename "$src")"
  python3 "$ROOT/tools/extract-firmware.py" "$src" "$FW_DIR" || exit 1

  command -v debugfs >/dev/null \
    || { echo "firmware-source: FATAL: debugfs (e2fsprogs) required to unpack kernel.fit" >&2; exit 1; }
  rm -f "$FW_DIR/kernel.fit"
  debugfs -R "dump /kernel.fit $FW_DIR/kernel.fit" "$FW_DIR/kernel.img" >/dev/null 2>&1
  [[ -s "$FW_DIR/kernel.fit" ]] \
    || { echo "firmware-source: FATAL: could not dump /kernel.fit from kernel.img" >&2; exit 1; }

  echo "$sum" > "$marker"

  log "cached in $FW_DIR: kernel.fit, kernel.img (stock partition), rootfs.img"
  log "IMPORTANT: flash a kernel partition built from the SAME firmware version as currently installed on the device - see the version-matching note in docs/flashing.md"
  return 0
}
