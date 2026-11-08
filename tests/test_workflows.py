"""Make/CLI integration and write guards, using synthetic images and mocks."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_fit import BOARD, DTB, ROOT, fixture, mod


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='rooty-test-')
        self.work = Path(self.tmp.name)
        self.env = os.environ.copy()
        # Do not inherit real device/firmware/build inputs into hermetic tests.
        for name in ('FIRMWARE_IMG', 'KERNEL_ITB', 'RESTORE_IMG_SRC', 'CUSTOM_FIT',
                     'ROOTFS_IMAGE', 'BOOTARGS', 'SERIAL', 'USB_DEVICE', 'YOCTO_INIT',
                     'YOCTO_BUILD_DIR', 'YOCTO_DEPLOY_DIR', 'CONFIRM', 'MAKEFLAGS', 'MFLAGS',
                     'ROOT', 'KERNEL_PARTITION_MIB'):
            self.env.pop(name, None)
        self.env.update(IMAGES_OUT=str(self.work / 'outputs'), IMAGE_LABEL='testroot',
                        ROOTFS_DIR=str(self.work / 'no-directory-root'), OVERLAY_DIR=str(self.work / 'no-overlay'))
        self.stock = self.work / 'stock.fit'
        self.stock.write_bytes(fixture())
        self.restore = self.work / 'stock-kernel.img'
        self.env.update(KERNEL_ITB=str(self.stock), RESTORE_IMG_SRC=str(self.restore))

    def tearDown(self):
        self.tmp.cleanup()

    def run_cmd(self, *args, ok=True, **env):
        result = subprocess.run(args, cwd=ROOT, env={**self.env, **env}, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if ok:
            self.assertEqual(result.returncode, 0, result.stdout)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout)
        return result

    def image_tools(self):
        if not all(shutil.which(t) for t in ('dtc', 'mke2fs', 'debugfs', 'sgdisk', 'e2fsck', 'resize2fs')):
            self.skipTest('image tools not installed')
        tree = self.work / 'stock-kernel'
        tree.mkdir()
        shutil.copyfile(self.stock, tree / 'kernel.fit')
        self.run_cmd('mke2fs', '-q', '-F', '-t', 'ext2', '-d', str(tree), str(self.restore), '4M')

    def read_kernel(self):
        output = self.work / 'extracted.fit'
        self.run_cmd('debugfs', '-R', f'dump /kernel.fit {output}',
                     str(self.work / 'outputs/testroot-kernel-partition.img'))
        return mod.Fit(output.read_bytes())

    def test_make_help_is_non_destructive(self):
        result = self.run_cmd('make')
        for target in ('repack', 'yocto-build', 'yocto', 'flash-usb', 'flash-kernel', 'restore'):
            self.assertIn(target, result.stdout)
        self.assertFalse((self.work / 'outputs').exists())

    def test_stock_repack_and_restore(self):
        self.image_tools()
        self.run_cmd('make', 'repack')
        fit = self.read_kernel()
        for name in ('kernel', DTB, 'extra'):
            self.assertEqual(fit.payload(name), mod.Fit(fixture()).payload(name))
        self.assertIn(b'root=PARTLABEL=testroot', fit.payload('fdt-cmdline'))
        self.assertEqual(self.restore.read_bytes(), (self.work / 'outputs/testroot-restore.img').read_bytes())

    def test_bootargs_label_mismatch_refused(self):
        self.image_tools()
        result = self.run_cmd('make', 'repack', ok=False, BOOTARGS='root=PARTLABEL=wrong rw')
        self.assertIn('exactly one root=PARTLABEL=testroot', result.stdout)

    def test_unsafe_label_refused(self):
        result = self.run_cmd('make', 'repack', 'IMAGE_LABEL=../../escape', ok=False)
        self.assertIn('IMAGE_LABEL must', result.stdout)

    def test_yocto_pack_kernel_dtb_and_usb_rootfs(self):
        self.image_tools()
        deploy = self.work / 'deploy'
        deploy.mkdir()
        (deploy / 'kernel.fit').write_bytes(fixture(custom=True, inline=True))
        rootfs = deploy / 'core-image-minimal-az0x-signed.rootfs.ext4'
        tree = self.work / 'rootfs'
        (tree / 'etc').mkdir(parents=True)
        (tree / 'etc/fstab').write_text('/dev/root / ext4 defaults 0 1\n')
        (tree / 'marker').write_text('original-content')
        self.run_cmd('mke2fs', '-q', '-F', '-t', 'ext4', '-d', str(tree), str(rootfs), '16M')
        before = hashlib.sha256(rootfs.read_bytes()).digest()
        self.run_cmd('make', 'yocto', YOCTO_DEPLOY_DIR=str(deploy), STICK_SIZE_MB='64')
        fit = self.read_kernel()
        custom = mod.Fit((deploy / 'kernel.fit').read_bytes())
        for name in ('kernel', DTB):
            self.assertEqual(fit.payload(name), custom.payload(name))
        self.assertIn(b'root=PARTLABEL=testroot', fit.payload('fdt-cmdline'))
        self.assertEqual(before, hashlib.sha256(rootfs.read_bytes()).digest())
        self.assertTrue((self.work / 'outputs/testroot-root.img').is_file())
        self.assertEqual((self.work / 'outputs/testroot-kernel-partition.img').stat().st_size, 16 * 1024 * 1024)

    def test_yocto_build_uses_early_config_and_keeps_local_conf(self):
        build = self.work / 'build'
        (build / 'conf').mkdir(parents=True)
        local = build / 'conf/local.conf'
        local.write_text('# original local.conf\n')
        bin_dir = self.work / 'bin'
        bin_dir.mkdir()
        bitbake = bin_dir / 'bitbake'
        record = self.work / 'bitbake-config'
        args = self.work / 'bitbake-args'
        bitbake.write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" > "{args}"\ncat "$2" > "{record}"\n')
        bitbake.chmod(0o755)
        init = self.work / 'oe-init-build-env'
        init.write_text(f'export PATH="{bin_dir}:$PATH"\ncd "$1"\n')
        self.run_cmd('make', 'yocto-build', YOCTO_BUILD_DIR=str(build), YOCTO_INIT=str(init))
        self.assertIn('MACHINE:forcevariable = "az0x-signed"', record.read_text())
        self.assertIn('AZ0X_KERNEL_PROVIDER:forcevariable = "yocto-rt"', record.read_text())
        self.assertIn('INIT_MANAGER:forcevariable = "systemd"', record.read_text())
        self.assertEqual(args.read_text().splitlines()[::2][0], '-r')
        self.assertIn('virtual/kernel\ncore-image-minimal', args.read_text())
        self.assertEqual(local.read_text(), '# original local.conf\n')
        self.assertFalse(Path(args.read_text().splitlines()[1]).exists())

    def mock_fastboot(self, partition_size='0x01000000'):
        bin_dir = self.work / 'bin'
        bin_dir.mkdir()
        log = self.work / 'fastboot.log'
        binary = bin_dir / 'fastboot'
        binary.write_text(f'''#!/bin/sh
printf '%s\n' "$*" >> "{log}"
case "$*" in
  devices) printf 'fixture-device\\tfastboot\\n' ;;
  '-s fixture-device getvar partition-size:kernel') echo 'partition-size:kernel: {partition_size}' >&2 ;;
  '-s fixture-device flash kernel '*) exit 0 ;;
  *) exit 23 ;;
esac
''')
        binary.chmod(0o755)
        self.env['PATH'] = str(bin_dir) + ':' + self.env['PATH']
        out = self.work / 'outputs'
        out.mkdir()
        (out / 'testroot-kernel-partition.img').write_bytes(b'K' * 8192)
        (out / 'testroot-restore.img').write_bytes(b'S' * 4096)
        return log

    def test_write_targets_require_confirmation_before_device_access(self):
        log = self.mock_fastboot()
        for target in ('flash-kernel', 'flash-usb', 'restore'):
            result = self.run_cmd('make', target, ok=False)
            self.assertIn('CONFIRM=YES', result.stdout)
        self.assertFalse(log.exists())

    def test_fastboot_requires_serial_and_checks_size(self):
        log = self.mock_fastboot(partition_size='0x1000')
        self.run_cmd('make', 'flash-kernel', ok=False, CONFIRM='YES')
        self.assertFalse(log.exists())
        result = self.run_cmd('make', 'flash-kernel', ok=False, CONFIRM='YES', SERIAL='fixture-device')
        self.assertIn('exceeds', result.stdout)
        self.assertNotIn('flash kernel', log.read_text())

    def test_explicit_flash_and_restore_never_reboot(self):
        log = self.mock_fastboot()
        self.run_cmd('make', 'flash-kernel', CONFIRM='YES', SERIAL='fixture-device')
        self.run_cmd('make', 'restore', CONFIRM='YES', SERIAL='fixture-device')
        self.assertNotIn('reboot', log.read_text())
        self.assertIn('testroot-kernel-partition.img', log.read_text())
        self.assertIn('testroot-restore.img', log.read_text())

    def test_verify_accepts_built_artifacts(self):
        self.image_tools()
        self.run_cmd('make', 'repack')
        result = self.run_cmd('make', 'verify')
        self.assertIn('static checks passed', result.stdout)

    def test_verify_rejects_missing_kernel_fit(self):
        self.image_tools()
        self.run_cmd('make', 'repack')
        image = self.work / 'outputs/testroot-kernel-partition.img'
        self.run_cmd('debugfs', '-w', '-R', 'rm /kernel.fit', str(image))
        result = self.run_cmd('make', 'verify', ok=False)
        self.assertIn('/kernel.fit missing', result.stdout)

    def test_verify_rejects_wrong_label(self):
        self.image_tools()
        self.run_cmd('make', 'repack')
        result = self.run_cmd('make', 'verify', ok=False, BOOTARGS='root=PARTLABEL=other rw')
        self.assertIn('bootargs differ', result.stdout)

    def test_usb_regular_file_refused(self):
        file = self.work / 'not-a-disk'
        file.write_bytes(b'keep-me')
        self.run_cmd('make', 'flash-usb', ok=False, CONFIRM='YES', USB_DEVICE=str(file))
        self.assertEqual(file.read_bytes(), b'keep-me')

    def test_document_links(self):
        documents = [ROOT / 'README.md', *sorted((ROOT / 'docs').glob('*.md'))]
        for file in documents:
            text = file.read_text()
            for target in re.findall(r'\]\(([^)#]+)(?:#[^)]*)?\)', text):
                if '://' not in target:
                    self.assertTrue((file.parent / target).exists(), (file, target))


if __name__ == '__main__':
    unittest.main()
