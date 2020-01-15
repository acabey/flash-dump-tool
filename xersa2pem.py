#!/usr/bin/env python3

import argparse
import textwrap
import logging
from typing import List
from typing import TypeVar

from lib.xecrypt_rsa import *

logging.basicConfig()
LOGGER = logging.getLogger('XeRSA2Pem')

T = TypeVar('T')


def take_nearest(input_list: List[T], target: int) -> T:
    """
    Find the value in the list cloest to the target
    """
    return min(input_list, key=lambda x: abs(x - target))


def guess_private_key_size(data: bytes) -> XeCrypt_RSA:
    """
    Returns the XeCrypt class most likely to match the given size
    :param data:
    :return:
    """
    LOGGER.debug('Guessing private key for struct size %s (%s)', len(data), hex(len(data)))
    table = {
        XeCrypt_RSAPrv_1024.STRUCT_SIZE: XeCrypt_RSAPrv_1024,
        XeCrypt_RSAPrv_1536.STRUCT_SIZE: XeCrypt_RSAPrv_1536,
        XeCrypt_RSAPrv_2048.STRUCT_SIZE: XeCrypt_RSAPrv_2048,
        XeCrypt_RSAPrv_4096.STRUCT_SIZE: XeCrypt_RSAPrv_4096
    }
    return table[take_nearest(table.keys(), len(data))]


def guess_public_key_size(data: bytes) -> XeCrypt_RSA:
    LOGGER.debug('Guessing public key for struct size %s (%s)', len(data), hex(len(data)))
    table = {
        XeCrypt_RSAPub_1024.STRUCT_SIZE: XeCrypt_RSAPub_1024,
        XeCrypt_RSAPub_1536.STRUCT_SIZE: XeCrypt_RSAPub_1536,
        XeCrypt_RSAPub_2048.STRUCT_SIZE: XeCrypt_RSAPub_2048,
        XeCrypt_RSAPub_4096.STRUCT_SIZE: XeCrypt_RSAPub_4096
    }
    return table[take_nearest(table.keys(), len(data))]


def main():
    parser = argparse.ArgumentParser(prog='XeRSA2PEM',
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description='Parse big-endian XeRSA* struct formatted binaries into PEM files',
                                     epilog=textwrap.dedent('''
                                     Example Usage:
                                     
                                     Convert 4096-bit private key (XeRsaPriv4096) binary file to pem:
                                     
                                       python3 xersa2pem.py -t private -s 4096 XeRsaPriv4096.bin XeRsaPriv4096.pem
                                       
                                     Convert unknown size private key binary file to pem:
                                     
                                       python3 xersa2pem.py -t private -s guess XeRsaPriv.bin XeRsaPriv.pem
                                       
                                     Convert unknown size private key binary file to pem:
                                     
                                       python3 xersa2pem.py -t private -s guess XeRsaPriv.bin XeRsaPriv.pem
                                       
                                     Convert key PEM file to appropriate binary:
                                     
                                       python3 xersa2pem.py -r XeRsaPriv.bin XeRsaPriv.pem
                                       
                                     '''))

    parser.add_argument('xersaobj', type=str,
                        help='Path to XeRSA* struct formatted binary file')
    parser.add_argument('pempath', type=str,
                        help='Path to PEM output file')
    parser.add_argument('-t', '--type', type=str, required=True,
                        choices=['public', 'private'],
                        help='Type of XeRSA object')
    parser.add_argument('-s', '--size', default='guess', required=False,
                        choices=['1024', '1536', '2048', '4096', 'guess'],
                        help='Size of XeRSA key')
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
                xeobj_file.write(bytes(xecrypt_obj))

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
        if args.type == 'public':
            xecrypt_class = {
                '1024': XeCrypt_RSAPub_1024,
                '1536': XeCrypt_RSAPub_1536,
                '2048': XeCrypt_RSAPub_2048,
                '4096': XeCrypt_RSAPub_4096,
                'guess': guess_public_key_size(data)
            }.get(args.size)
            LOGGER.debug('Chose class %s with struct size %s (%s)',
                         xecrypt_class, xecrypt_class.STRUCT_SIZE, hex(xecrypt_class.STRUCT_SIZE))
            xecrypt_obj = xecrypt_class(data)
        else:
            xecrypt_class = {
                '1024': XeCrypt_RSAPrv_1024,
                '1536': XeCrypt_RSAPrv_1536,
                '2048': XeCrypt_RSAPrv_2048,
                '4096': XeCrypt_RSAPrv_4096,
                'guess': guess_private_key_size(data)
            }.get(args.size)
            LOGGER.debug('Chose class %s with struct size %s (%s)',
                         xecrypt_class, xecrypt_class.STRUCT_SIZE, hex(xecrypt_class.STRUCT_SIZE))
            xecrypt_obj = xecrypt_class(data)
        LOGGER.info('Created xecrypt object of type: %s', type(xecrypt_obj))
    except (IndexError, ValueError, Exception) as e:
        LOGGER.error(str(e))
        return

    rsa_obj = xecrypt_obj.build_rsa()
    LOGGER.info('Built RSA object')

    try:
        with open(args.pempath, 'wb') as pem_file:
            pem_file.write(rsa_obj.exportKey('PEM'))
            LOGGER.info('Wrote PEM to %s', args.pempath)
    except (FileExistsError, IOError, TypeError) as e:
        LOGGER.error(str(e))
        return


if __name__ == '__main__':
    main()
