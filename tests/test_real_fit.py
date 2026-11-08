"""Structural checks against a real vendor FIT (gated; no secrets or blobs shipped).

Skips unless a cached kernel.fit exists or TEST_FIRMWARE_IMG is set. Verifies the
combined repacker against the vendor's own kernel/DTB: every other board payload
must survive, the command line must change, and all signatures must still verify
to their original RSA values.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'vendor/tamper'))
from build_attack_fit import serialize

spec = importlib.util.spec_from_file_location('repack_fit', ROOT / 'tools/repack-fit.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

BOARD = 'rk3288-az01-jc11s'


def cached_fit():
    for path in sorted((ROOT / 'cache/firmware').glob('*/kernel.fit')):
        return path
    return None


def extract_fit(tmp):
    source = os.environ.get('TEST_FIRMWARE_IMG')
    if not source:
        return None
    subprocess.run([sys.executable, str(ROOT / 'tools/extract-firmware.py'), source, str(tmp)],
                   check=True, capture_output=True)
    out = tmp / 'kernel.fit'
    subprocess.run(['debugfs', '-R', f'dump /kernel.fit {out}', str(tmp / 'kernel.img')],
                   check=True, capture_output=True)
    return out


def unsigned_fit(kernel, dtb, board):
    strings, names, tokens = b'', {}, []

    def begin(name):
        tokens.append(('BEGIN', (name.encode(), b'\0' * (-(len(name) + 1) % 4))))

    def end():
        tokens.append(('END', None))

    def prop(name, data):
        names.setdefault(name, len(strings))
        if isinstance(data, str):
            data = data.encode() + b'\0'
        tokens.append(('PROP', (names[name], len(data), data, b'\0' * (-len(data) % 4))))
        return data

    for name in ('arch', 'compression', 'data', 'algo', 'value', 'kernel', 'fdt'):
        prop_name = name.encode() + b'\0'
        names[name] = len(strings)
        strings += prop_name
    begin('')
    begin('images')
    for name, payload in (('kernel', kernel), ('fdt-' + board, dtb)):
        begin(name)
        prop('arch', 'arm')
        prop('compression', 'none')
        prop('data', payload)
        begin('hash-1')
        prop('algo', 'sha256')
        prop('value', hashlib.sha256(payload).digest())
        end()
        end()
    end()
    begin('configurations')
    begin('conf-' + board)
    prop('kernel', 'kernel')
    prop('fdt', 'fdt-' + board)
    end()
    end()
    end()
    tokens.append(('FDT_END', None))
    block = serialize(tokens)
    strings_pos = 56 + len(block)
    total = (strings_pos + len(strings) + 3) & ~3
    header = struct.pack('>10I', 0xd00dfeed, total, 56, strings_pos, 40, 17, 16, 0,
                         len(strings), len(block))
    return header + b'\0' * 16 + block + strings + b'\0' * (total - strings_pos - len(strings))


class RealFitTests(unittest.TestCase):
    def setUp(self):
        if not all(shutil.which(t) for t in ('debugfs',)):
            self.skipTest('debugfs unavailable')
        self.tmp = tempfile.TemporaryDirectory(prefix='rooty-real-')
        self.addCleanup(self.tmp.cleanup)
        path = cached_fit()
        if path is None:
            try:
                path = extract_fit(Path(self.tmp.name))
            except (subprocess.CalledProcessError, KeyError):
                path = None
        if path is None:
            self.skipTest('no cached vendor kernel.fit and no TEST_FIRMWARE_IMG')
        self.vendor = mod.Fit(Path(path).read_bytes())

    def test_vendor_fit_has_the_assumed_shape(self):
        self.assertIn('/configurations/conf-' + BOARD + '/signature-0', self.vendor.signatures())
        self.assertEqual('arm', self.vendor.text('/images/kernel', 'arch'))
        self.assertGreater(len(self.vendor.signatures()), 1)

    def test_self_repack_preserves_everything_but_bootargs(self):
        kernel = self.vendor.payload('kernel')
        dtb = self.vendor.payload('fdt-' + BOARD)
        custom = mod.Fit(unsigned_fit(kernel, dtb, BOARD))
        out = mod.Fit(mod.repack(self.vendor, custom, b'test-overlay', BOARD))

        self.assertEqual(kernel, out.payload('kernel'))
        self.assertEqual(dtb, out.payload('fdt-' + BOARD))
        self.assertEqual(b'test-overlay', out.payload('fdt-cmdline'))
        for name in ('fdt-rk3288-az05-jp11s', 'fdt-rk3288-az05-jp20',
                     'fdt-rk3288-az05-jp21', 'fdt-az01b'):
            self.assertEqual(self.vendor.payload(name), out.payload(name), name)
        self.assertEqual(self.vendor.signatures(), out.signatures())
        for signature in out.signatures():
            self.assertEqual(self.vendor.get(signature, 'value'),
                             out.get(signature, 'value'), signature)


if __name__ == '__main__':
    unittest.main()
