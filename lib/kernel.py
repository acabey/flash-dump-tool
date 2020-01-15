#!/usr/bin/env python3

from lib.common import *


def combinehvkernel(hv_dec, kernel_dec) -> bytes:
    """
    Build a combined SE/CE bootloader buffer from HV and kernel parts

    Parameters are in bytes

    Returns bytes
    """
    return bytes(hv_dec + kernel_dec)


def splitbootloader(bootloader_dec) -> bytes:
    """
    Split a combined buffer into HV and kernel parts

    Parameters are in bytes

    Returns tuple of bytes
    """
    return bytes(bootloader_dec[:Constants.HV_SIZE]), bytes(bootloader_dec[Constants.HV_SIZE:])


def main(argv):
    parser = argparse.ArgumentParser()

    arggroup = parser.add_mutually_exclusive_group(required=True)

    arggroup.add_argument('--split', '-s', help="Split decompressed CE/SE into kernel + HV parts", type=str, nargs=1,
                          metavar='se.bin')
    arggroup.add_argument('--combine', '-c', help="Combine split kernel + HV parts back into decompressed CE/SE",
                          type=str, nargs=2, metavar=('hv.bin', 'xboxkrnl.bin'))

    args = parser.parse_args(argv[1:])

    if args.split:

        se = args.split[0]

        hv = se + '_HV.bin'
        kernel = se + '_xboxkrnl.exe'

        with open(se, 'rb') as sefile:
            bootloaderdata = sefile.read()
            hvdata, kerneldata = splitbootloader(bootloaderdata)

            with open(hv, 'w+b') as hvfile:
                hvfile.write(hvdata)
            with open(kernel, 'w+b') as kernelfile:
                kernelfile.write(kerneldata)

        print('Successfully split SE')

    elif args.combine:

        hv, kernel, out = args.combine[0], args.combine[1], 'SE_dec.bin'

        with open(out, 'w+b') as outfile:
            with open(hv, 'rb') as hvfile:
                hvdata = hvfile.read()
            with open(kernel, 'rb') as kernelfile:
                kerneldata = kernelfile.read()
            outfile.write(combinehvkernel(hvdata, kerneldata))

        print('Successfully combined SE')


if __name__ == '__main__':
    import argparse, sys

    main(sys.argv)
