#!/usr/bin/env python3

import argparse
import textwrap
import logging

from lib.xecrypt_rsa import *

logging.basicConfig()
LOGGER = logging.getLogger('XeRSA2Pem')


def main():
    parser = argparse.ArgumentParser(prog='XeRSA2PEM',
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description='Parse big-endian XeRSA* struct formatted binaries into PEM files',
                                     epilog=textwrap.dedent('''
                                     Example Usage:
                                     
                                     Convert 4096-bit private key (XeRsaPriv4096) binary file to pem:
                                     
                                       python3 xersa2pem.py XeRsaPriv4096.bin XeRsaPriv4096.pem
                                       
                                     Convert unknown size private key binary file to pem:
                                     
                                       python3 xersa2pem.py XeRsaPriv.bin XeRsaPriv.pem
                                       
                                     Convert unknown size private key binary file to pem:
                                     
                                       python3 xersa2pem.py XeRsaPriv.bin XeRsaPriv.pem
                                       
                                     Convert key PEM file to appropriate binary:
                                     
                                       python3 xersa2pem.py -r XeRsaPriv.bin XeRsaPriv.pem
                                       
                                     '''))

    parser.add_argument('xersaobj', type=str,
                        help='Path to XeRSA* struct formatted binary file')
    parser.add_argument('pempath', type=str,
                        help='Path to PEM output file')
    parser.add_argument('-r', '--reverse', action='store_true', required=False,
                        help='Reverse process: PEM to binary file')
    parser.add_argument('-v', '--verbose', action='store_true', required=False,
                        help='Set verbose-level output')
    parser.add_argument('-d', '--debug', action='store_true', required=False,
                        help='Set debug-level output')
    args = parser.parse_args()

    if args.verbose:
        LOGGER.setLevel(logging.INFO)
    if args.debug:
        LOGGER.setLevel(logging.DEBUG)

    if args.reverse:
        try:
            with open(args.pempath, 'rb') as pem_file:
                data = pem_file.read()
                LOGGER.info('Read %s (%s) bytes from %s', len(data), hex(len(data)), args.pempath)
                rsa_obj = RSA.import_key(data)  # Passphrase not supported
                xecrypt_obj = XeCrypt_RSA.from_rsa(rsa_obj)

            with open(args.xersaobj, 'wb') as xeobj_file:
                xeobj_file.write(xecrypt_obj.export_key(format='XeCrypt'))

        except (FileNotFoundError, IOError, ValueError) as e:
            LOGGER.error(str(e))

        return

    try:
        with open(args.xersaobj, 'rb') as xeobj_file:
            data = xeobj_file.read()
            LOGGER.info('Read %s (%s) bytes from %s', len(data), hex(len(data)), args.xersaobj)

    except (FileNotFoundError, IOError, ValueError) as e:
        LOGGER.error(str(e))
        return

    try:
        xecrypt_obj = XeCrypt_RSA.from_key(data)
        LOGGER.info('Created XeCrypt_RSA object with %s key, modulus size %s',
                    'private' if xecrypt_obj.has_private() else 'public',
                    str(xecrypt_obj.size_in_bits()))
    except (IndexError, ValueError, Exception) as e:
        LOGGER.error(str(e))
        return

    try:
        with open(args.pempath, 'wb') as pem_file:
            pem_file.write(xecrypt_obj.export_key(format='PEM'))
            LOGGER.info('Wrote PEM to %s', args.pempath)
    except (FileExistsError, IOError, TypeError) as e:
        LOGGER.error(str(e))
        return


if __name__ == '__main__':
    main()
