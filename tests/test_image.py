"""Raw ext4 import checks; no sudo, vendor firmware or physical disks."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ImageTests(unittest.TestCase):
    def setUp(self):
        if not all(shutil.which(t) for t in ('mke2fs', 'debugfs', 'sgdisk', 'e2fsck', 'resize2fs')):
            self.skipTest('filesystem tools unavailable')
        self.tmp = tempfile.TemporaryDirectory(prefix='rooty-image-')
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)

    def source(self, fstab=None):
        tree = self.work / 'tree'
        (tree / 'etc').mkdir(parents=True)
        if fstab is not None:
            (tree / 'etc/fstab').write_text(fstab)
        src = self.work / 'source.ext4'
        subprocess.run(['mke2fs', '-q', '-F', '-t', 'ext4', '-d', str(tree), str(src), '16M'],
                       check=True, capture_output=True)
        return src

    def pack(self, src, ok=True):
        out = self.work / 'out'
        env = {**os.environ, 'ROOTFS_IMAGE': str(src), 'IMAGES_OUT': str(out),
               'IMAGE_LABEL': 'testroot', 'STICK_SIZE_MB': '64',
               'ROOTFS_DIR': str(self.work / 'unused-root')}
        result = subprocess.run(['bash', 'tools/make-image.sh'], cwd=ROOT, env=env,
                                text=True, capture_output=True)
        if ok:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)
        return result

    def read_fstab(self):
        partition = self.work / 'partition.ext4'
        with (self.work / 'out/testroot-root.img').open('rb') as src, partition.open('wb') as dst:
            src.seek(1024 * 1024)
            shutil.copyfileobj(src, dst)
        result = subprocess.run(['debugfs', '-R', 'cat /etc/fstab', str(partition)],
                                text=True, capture_output=True, check=True)
        return result.stdout

    def test_missing_fstab_gets_usb_root(self):
        src = self.source()
        before = hashlib.sha256(src.read_bytes()).digest()
        self.pack(src)
        self.assertEqual(self.read_fstab(), 'PARTLABEL=testroot / ext4 rw,errors=remount-ro 0 1\n')
        self.assertEqual(before, hashlib.sha256(src.read_bytes()).digest())

    def test_duplicate_roots_removed_and_comments_kept(self):
        src = self.source('# /dev/mmcblk0p10 is not mounted\n'
                          'PARTLABEL=testroot / ext4 defaults 0 1\n/dev/root / ext4 defaults 0 1\n')
        self.pack(src)
        content = self.read_fstab()
        self.assertEqual(sum(line.split()[1] == '/' for line in content.splitlines()
                             if line and not line.startswith('#')), 1)
        self.assertIn('# /dev/mmcblk0p10 is not mounted', content)

    def test_known_internal_partuuid_refused(self):
        src = self.source('PARTUUID=931ad49d-ad59-0849-833a-9bf00af5b60e /data ext4 defaults 0 0\n')
        self.assertIn('internal eMMC', self.pack(src, ok=False).stderr)

    def test_invalid_filesystem_refused(self):
        src = self.work / 'invalid.ext4'
        src.write_bytes(b'not an ext4 filesystem')
        self.pack(src, ok=False)
        self.assertEqual(src.read_bytes(), b'not an ext4 filesystem')

    def test_input_cannot_be_output(self):
        src = self.source()
        out = self.work / 'out'
        out.mkdir()
        destination = out / 'testroot-root.img'
        shutil.copyfile(src, destination)
        before = hashlib.sha256(destination.read_bytes()).digest()
        self.assertIn('input rootfs must not be', self.pack(destination, ok=False).stderr)
        self.assertEqual(before, hashlib.sha256(destination.read_bytes()).digest())


if __name__ == '__main__':
    unittest.main()
