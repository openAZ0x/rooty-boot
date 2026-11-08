"""Synthetic FIT tests: no vendor payloads, keys or connected devices."""
import gzip
import hashlib
import importlib.util
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'vendor/tamper'))
from build_attack_fit import serialize, u32

spec = importlib.util.spec_from_file_location('repack_fit', ROOT / 'tools/repack-fit.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

BOARD = 'rk3288-az01-jc11s'
DTB = 'fdt-' + BOARD


def fixture(custom=False, compression='none', absolute=False, inline=False):
    strings = b''
    names = {}
    for name in ('description', 'arch', 'compression', 'data', 'data-offset', 'data-size',
                 'data-position', 'algo', 'value', 'kernel', 'fdt', 'default',
                 'key-name-hint', 'hashed-nodes', 'hashed-strings'):
        names[name] = len(strings)
        strings += name.encode() + b'\0'
    tokens, external = [], bytearray()

    def begin(name):
        tokens.append(('BEGIN', (name.encode(), b'\0' * (-(len(name) + 1) % 4))))

    def end():
        tokens.append(('END', None))

    def prop(name, data):
        if isinstance(data, str):
            data = data.encode() + b'\0'
        tokens.append(('PROP', (names[name], len(data), data, b'\0' * (-len(data) % 4))))

    kernel = bytearray(b'K' * (512 if custom else 256))
    struct.pack_into('<I', kernel, 0x24, 0x016f2818)
    # A minimal real DTB (empty root node) with a distinguishable extra NOP.
    block = serialize([('BEGIN', (b'', b'\0' * 3)), ('END', None), ('FDT_END', None)])
    dtb = struct.pack('>10I', 0xd00dfeed, 56 + len(block), 56, 56 + len(block),
                      40, 17, 16, 0, 0, len(block)) + b'\0' * 16 + block
    if custom:
        dtb += b'custom-dtb'
    payloads = {'kernel': bytes(kernel), DTB: dtb, 'fdt-cmdline': b'old-overlay', 'extra': b'keep-me'}
    if compression == 'gzip' and not custom:
        payloads['kernel'] = gzip.compress(payloads['kernel'], mtime=0)

    begin('')
    prop('description', 'synthetic fixture')
    begin('images')
    for name, payload in payloads.items():
        begin(name)
        prop('arch', 'arm')
        prop('compression', compression if name == 'kernel' else 'none')
        if inline:
            prop('data', payload)
        else:
            external += b'\0' * (-len(external) % 4)
            prop('data-position' if absolute else 'data-offset', u32(len(external)))
            prop('data-size', u32(len(payload)))
            external += payload
        begin('hash-1')
        prop('algo', 'sha256')
        prop('value', hashlib.sha256(payload).digest())
        end()
        end()
    end()
    begin('configurations')
    prop('default', 'conf-' + BOARD)
    for conf, images in [('conf-' + BOARD, ['kernel', DTB]), ('cmdline', ['fdt-cmdline']),
                         ('extra-config', ['extra'])]:
        begin(conf)
        if 'kernel' in images:
            prop('kernel', 'kernel')
        prop('fdt', images[-1])
        if not custom:
            begin('signature-0')
            prop('algo', 'sha256,rsa2048')
            prop('key-name-hint', 'test-key')
            prop('value', b'S' * 256)
            nodes = ['/', '/configurations/' + conf]
            for image in images:
                nodes += ['/images/' + image, '/images/' + image + '/hash-1']
            prop('hashed-nodes', ''.join(n + '\0' for n in nodes).encode())
            prop('hashed-strings', u32(0) + u32(len(strings)))
            end()
        end()
    end()
    end()
    tokens.append(('FDT_END', None))
    block = serialize(tokens)
    strings_pos = 56 + len(block)
    total = (strings_pos + len(strings) + 3) & ~3
    header = struct.pack('>10I', 0xd00dfeed, total, 56, strings_pos, 40, 17, 16, 0,
                         len(strings), len(block))
    return header + b'\0' * 16 + block + strings + b'\0' * (total - strings_pos - len(strings)) + external


class RepackTests(unittest.TestCase):
    def test_replacement_and_all_signature_streams(self):
        original = mod.Fit(fixture())
        custom = mod.Fit(fixture(custom=True))
        streams = {p: original.stream(p) for p in original.signatures()}
        output = mod.Fit(mod.repack(original, custom, b'new-overlay', BOARD))
        for path, stream in streams.items():
            self.assertEqual(stream, output.stream(path))
            self.assertEqual(b'S' * 256, output.get(path, 'value'))
        for name in ('kernel', DTB):
            self.assertEqual(custom.payload(name), output.payload(name))
        self.assertEqual(b'new-overlay', output.payload('fdt-cmdline'))
        self.assertEqual(b'keep-me', output.payload('extra'))
        for name in ('kernel', DTB, 'fdt-cmdline'):
            self.assertEqual(hashlib.sha256(output.payload(name)).digest(),
                             output.get('/images/' + name + '/hash-1', 'value'))

    def test_gzip_vendor_kernel(self):
        output = mod.Fit(mod.repack(mod.Fit(fixture(compression='gzip')),
                                   mod.Fit(fixture(custom=True)), b'overlay', BOARD))
        self.assertEqual(mod.Fit(fixture(custom=True)).payload('kernel'),
                         gzip.decompress(output.payload('kernel')))

    def test_inline_custom_fit(self):
        custom = mod.Fit(fixture(custom=True, inline=True))
        output = mod.Fit(mod.repack(mod.Fit(fixture()), custom, b'overlay', BOARD))
        self.assertEqual(custom.payload('kernel'), output.payload('kernel'))
        self.assertEqual(custom.payload(DTB), output.payload(DTB))

    def test_wrong_board_refused(self):
        with self.assertRaises(KeyError):
            mod.repack(mod.Fit(fixture()), mod.Fit(fixture(custom=True)), b'overlay', 'wrong-board')

    def test_absolute_external_offsets_refused(self):
        with self.assertRaisesRegex(ValueError, 'absolute'):
            mod.repack(mod.Fit(fixture(absolute=True)), mod.Fit(fixture(custom=True)), b'overlay', BOARD)

    def test_invalid_zimage_refused(self):
        custom = mod.Fit(fixture(custom=True))
        custom.set('/images/kernel', 'data-size', u32(16))
        custom.set('/images/kernel/hash-1', 'value', hashlib.sha256(b'K' * 16).digest())
        with self.assertRaisesRegex(ValueError, 'zImage'):
            mod.repack(mod.Fit(fixture()), custom, b'overlay', BOARD)

    def test_corrupt_custom_payload_refused(self):
        custom = bytearray(fixture(custom=True))
        custom[-1] ^= 1  # the unrelated payload need not be read by repacking
        parsed = mod.Fit(bytes(custom))
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            parsed.payload('extra')

    def test_repacking_an_already_repacked_fit_refused(self):
        output = mod.Fit(mod.repack(mod.Fit(fixture()), mod.Fit(fixture(custom=True)), b'overlay', BOARD))
        with self.assertRaisesRegex(ValueError, 'already'):
            mod.repack(output, mod.Fit(fixture(custom=True)), b'overlay', BOARD)


if __name__ == '__main__':
    unittest.main()
