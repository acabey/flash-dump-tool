#!/usr/bin/env python3

# Apply KXAM patches to a target

import sys

def main(argv):
    target = argv[1] if len(argv) >  0 else None
    patch = argv[2] if len(argv) >  1 else None

    if not (target and patch):
        print('Usage: applypatch.py target.bin patches.kxam')

    # Patch format
    # 4 byte offet
    # 4 byte count
    # 4 byte * count patch payload

    with open(patch, 'rb') as patchfile:
        with open(target, 'wb+') as targetfile:
            patchcountbytes = None

#            while(True)
#
#                patchoffsetbytes = patchfile.read(4)
#                if patchoffsetbytes == b'\xFF\xFF\xFF\xFF':
#                    break
            while ((patchoffsetbytes = patchfile.read(4)) != b'\xFF\xFF\xFF\xFF'):

                patchoffset = struct.unpack('>I', patchoffsetbytes)[0]

                patchcountbytes = patchfile.read(4)
                patchcount = struct.unpack('>I', patchcountbytes)[0]

                patchpayloadbytes = patchfile.read(4*patchcount)

                print('Writing patch of length ' + str(hex(patchcount)) + ' to offset ' + str(hex(patchoffset)))

                targetfile.seek(patchoffset,0)
                #targetfile.write(patchpayloadbytes)

    print('Successfully wrote patches')


if __name__ == '__main__':
    main(sys.argv)
