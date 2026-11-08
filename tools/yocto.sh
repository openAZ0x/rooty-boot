#!/usr/bin/env bash
# Build in an existing Yocto environment, or package its deployed FIT + rootfs.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
source config.env
die() { echo "yocto: $*" >&2; exit 1; }

case "${1:-}" in
  build)
    [[ -d "$YOCTO_BUILD_DIR/conf" ]] || die "set YOCTO_BUILD_DIR to an existing configured build"
    [[ "$YOCTO_PROVIDER" == yocto || "$YOCTO_PROVIDER" == yocto-rt ]] || die "YOCTO_PROVIDER must be yocto or yocto-rt"
    [[ "$YOCTO_MACHINE" == az0x-signed ]] || die "only YOCTO_MACHINE=az0x-signed is supported"
    [[ "$YOCTO_IMAGE" =~ ^[a-zA-Z0-9.+_-]+$ ]] || die "invalid YOCTO_IMAGE recipe name"
    build=$(realpath "$YOCTO_BUILD_DIR")
    if [[ -n "$YOCTO_INIT" ]]; then
      init=$(realpath "$YOCTO_INIT")
      [[ -f "$init" ]] || die "YOCTO_INIT not found"
      # oe-init-build-env is not nounset-safe. It may change the directory.
      set +u
      # shellcheck disable=SC1090
      source "$init" "$build"
      set -u
    fi
    command -v bitbake >/dev/null || die "source oe-init-build-env first, or set YOCTO_INIT"
    cd "$build"
    config=$(mktemp)
    trap 'rm -f "$config"' EXIT
    # Read early: MACHINE and INIT_MANAGER affect which config files get
    # included. A post-read (-R) assignment would be too late for that.
    # forcevariable is in OE's default OVERRIDES, so local.conf defaults and
    # the signed machine's prebuilt default cannot silently defeat this mode.
    cat > "$config" <<EOF
MACHINE:forcevariable = "$YOCTO_MACHINE"
AZ0X_KERNEL_PROVIDER:forcevariable = "$YOCTO_PROVIDER"
AZ0X_KERNEL_ALLOW_UNSIGNED:forcevariable = "1"
INIT_MANAGER:forcevariable = "systemd"
EOF
    bitbake -r "$config" virtual/kernel "$YOCTO_IMAGE"
    ;;
  pack)
    [[ -n "$YOCTO_DEPLOY_DIR" ]] || die "set YOCTO_DEPLOY_DIR (or YOCTO_BUILD_DIR)"
    deploy=$(realpath "$YOCTO_DEPLOY_DIR")
    export CUSTOM_FIT="${CUSTOM_FIT:-$deploy/kernel.fit}"
    export ROOTFS_IMAGE="${ROOTFS_IMAGE:-$deploy/$YOCTO_IMAGE-$YOCTO_MACHINE.rootfs.ext4}"
    [[ -s "$CUSTOM_FIT" ]] || die "missing $CUSTOM_FIT; run make yocto-build first"
    [[ -s "$ROOTFS_IMAGE" ]] || die "missing $ROOTFS_IMAGE; set ROOTFS_IMAGE to the deployed ext4"
    bash tools/make-kernel.sh
    bash tools/make-image.sh
    ;;
  *) die "usage: bash tools/yocto.sh build|pack" ;;
esac
