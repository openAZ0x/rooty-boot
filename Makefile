.DEFAULT_GOAL := help
.PHONY: help lint test repack yocto yocto-build verify flash-kernel flash-usb restore rootfs kernel image clean distclean

help: ## show this help
	@echo "rooty-boot - vendor firmware or Yocto, booting a USB rootfs"
	@echo
	@echo "  make repack       repack existing firmware with IMAGE_LABEL boot target"
	@echo "  make yocto-build  build kernel + rootfs in YOCTO_BUILD_DIR (existing setup)"
	@echo "  make yocto        package YOCTO_DEPLOY_DIR kernel.fit + rootfs for USB boot"
	@echo "  make image        wrap ROOTFS_IMAGE (ext4) or ROOTFS_DIR in a GPT USB image"
	@echo "  make verify       static pre-flight of built artifacts (no device access)"
	@echo "  make rootfs       optional Debian rootfs + vendor support (sudo/network)"
	@echo
	@echo "  make flash-usb    write USB_DEVICE (sudo; CONFIRM=YES; erases disk)"
	@echo "  make flash-kernel write only the controller kernel partition (SERIAL, CONFIRM=YES)"
	@echo "  make restore      restore stock kernel partition (SERIAL, CONFIRM=YES)"
	@echo "                    flash tasks never reboot automatically"
	@echo
	@echo "  make test       run the test suite (see tests/run-tests.sh header for env knobs)"
	@echo "  make lint       shellcheck / bash -n / py_compile only"
	@echo "  make clean      remove images/ and tests/work/"
	@echo "  make distclean  also remove rootfs/ and the firmware cache (re-downloads!)"
	@echo
	@echo "Set FIRMWARE_IMG and IMAGE_LABEL; see README.md for both workflows."

repack: ## vendor-kernel repack only; keep the stock kernel and DTB
	CUSTOM_FIT= bash tools/make-kernel.sh

yocto-build: ## run BitBake in an existing configured build
	bash tools/yocto.sh build

yocto: ## package already deployed Yocto outputs; never build/flash implicitly
	bash tools/yocto.sh pack

verify: ## static checks on generated artifacts; reads files only
	bash tools/verify.sh

flash-kernel:
	bash tools/flash.sh kernel

flash-usb:
	bash tools/flash.sh usb

restore:
	bash tools/flash.sh restore

rootfs: ## build the Debian rootfs (debootstrap; needs sudo + network)
	sudo -E bash tools/build-rootfs.sh

kernel: ## tamper the signed fit and build the flashable kernel partition image
	bash tools/make-kernel.sh

image: ## assemble the USB stick image from rootfs/
	bash tools/make-image.sh

test: ## run the test suite
	bash tests/run-tests.sh
	python3 -m unittest discover -s tests -p 'test_*.py'

lint: ## static checks only
	@for script in tools/*.sh tests/*.sh vendor/rootfs-overlay/usr/local/sbin/*; do bash -n "$$script" || exit; done \
	   && echo "bash -n ok"
	@shellcheck -S warning tools/*.sh tests/run-tests.sh tests/lib.sh \
	   vendor/rootfs-overlay/usr/local/sbin/* && echo "shellcheck ok"
	@python3 -m py_compile tools/*.py tests/*.py \
	   vendor/tamper/tamper_cmdline.py vendor/tamper/build_attack_fit.py \
	   && echo "py_compile ok"

clean: ## remove build outputs (keeps rootfs/ and the firmware cache)
	rm -rf images tests/work

distclean: ## remove everything regenerable, including the firmware cache
	rm -rf images tests/work rootfs cache
