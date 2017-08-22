#!/usr/bin/env python3

# Split decompressed SE into kernel + HV parts

import sys

HV_SIZE = 0x40000

def main(argv):
    target = argv[1] if len(argv) >  0 else None

    if not (target):
        print('Usage: splitkernel.py xboxkrnl.bin')

    hv = target + '_HV.bin'
    kernel = taget + '_xboxkrnl.exe'

    with open(target, 'rb') as targetfile:
        with open(hv, 'w+b') as hvfile:
            hvfile.write(targetfile.read(HV_SIZE))
        with open(kernel, 'w+b') as kernelfile:
            kernelfile.write(targetfile.read())

    print('Successfully split SE')


if __name__ == '__main__':
    main(sys.argv)
