#!/usr/bin/env python3

# Split decompressed SE into kernel + HV parts

import sys

HV_SIZE = 0x40000

def main(argv):
    hv = argv[1] if len(argv) >  0 else None
    kernel = argv[2] if len(argv) >  1 else None

    out = argv[3] if len(argv) > 2 else 'SE_dec_recombined.bin'

    if not (hv and kernel):
        print('Usage: combinekernel.py hv.bin xboxkrnl.exe [se_dec.bin]')


    with open(out, 'w+b') as outfile:
        with open(hv, 'rb') as hvfile:
            outfile.write(hvfile.read())
        with open(kernel, 'rb') as kernelfile:
            outfile.write(kernelfile.read())

    print('Successfully combined SE')


if __name__ == '__main__':
    main(sys.argv)
