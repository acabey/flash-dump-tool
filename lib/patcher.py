#!/usr/bin/env python3

import struct
import sys

from lib.common import *


# Apply KXAM patches to a target

def patch(originaldata, patchset):
    # Patch format
    # 4 byte offet
    # 4 byte count
    # 4 byte * count patch payload

    # Get the patch offset
    # Get the patch size

    patched_data = originaldata

    currentoffset = 0
    patchoffsetbytes = bytes(patchset[currentoffset:currentoffset + 4])

    while (patchoffsetbytes != b'\xFF\xFF\xFF\xFF'):
        patchoffsetbytes = bytes(patchset[currentoffset:currentoffset + 4])
        patchoffset = struct.unpack('>I', patchoffsetbytes)[0]
        dbgprint('patch offset: ' + str(hex(patchoffset)))

        currentoffset += 4

        patchcountbytes = bytes(patchset[currentoffset:currentoffset + 4])
        patchcount = struct.unpack('>I', patchcountbytes)[0]
        dbgprint('patch count : ' + str(hex(patchcount)))
        dbgprint('payload size: ' + str(hex(patchcount * 4)))

        currentoffset += 4

        patchpayloadbytes = bytes(patchset[currentoffset:currentoffset + 4 * patchcount])
        dbgprint('payload     : ' + str(patchpayloadbytes))

        patched_data[patchoffset:patchoffset + patchcount] = [patchpayloadbytes]

        currentoffset += 4 * patchcount

    return bytes(patched_data)


"""
There are two implementations of the actual patching algorithm here because writing directly to files is much lighter on MemoryStream

There is no reason to completely load the files into RAM before modifying when they can be modified InitializeComponent
"""


def main(argv):
    target = argv[1] if len(argv) > 0 else None
    patch = argv[2] if len(argv) > 1 else None

    if not (target and patch):
        print('Usage: applypatch.py target.bin patches.kxam')

    # Patch format
    # 4 byte offet
    # 4 byte count
    # 4 byte * count patch payload

    with open(patch, 'rb') as patchfile:
        with open(target, 'r+b') as targetfile:

            while (patchfile.readable()):

                patchoffsetbytes = patchfile.read(4)
                if patchoffsetbytes == b'\xFF\xFF\xFF\xFF':
                    break

                patchoffset = struct.unpack('>I', patchoffsetbytes)[0]
                print('patchoffset: ' + str(hex(patchoffset)))

                patchcountbytes = patchfile.read(4)
                patchcount = struct.unpack('>I', patchcountbytes)[0]
                print('patchcount: ' + str(hex(patchcount)))
                print('expected payload size: ' + str(hex(patchcount * 4)))

                patchpayloadbytes = patchfile.read(4 * patchcount)
                print('payload length: ' + str(hex(len(patchpayloadbytes))))
                print('payload: ' + str(patchpayloadbytes))

                print('Writing patch of length ' + str(hex(patchcount)) + ' to offset ' + str(hex(patchoffset)))

                targetfile.seek(patchoffset, 0)
                targetfile.write(patchpayloadbytes)

    print('Successfully wrote patches')


if __name__ == '__main__':
    main(sys.argv)
