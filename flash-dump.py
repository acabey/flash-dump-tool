#!/usr/bin/env python3

"""
Load and dump information from flash dumps and shadowboot ROMs

Detect type of file as well as partial files (ie. extracted bootloader)

Usage: python3 flash-dump.py image.bin -c cpukey -x section

-x  Extract section(s)

    Valid sections are:
        nandheader, keyvault, smc, smcconfig, sb, cb, sc, sd, cd, se, ce, cf, cg, cf1, cg1, kernel, hv

    Use 'all' to extract all sections

    ex. python3 flash-dump.py image.bin -x sb
    ex. python3 flash-dump.py image.bin -x sb sd smc
    ex. python3 flash-dump.py image.bin -x all


-e  Enumerate section(s)

    Enumerate information about the given sections (if available)

    Valid sections are as above

    ex. python3 flash-dump.py image.bin -e se
    ex. python3 flash-dump.py image.bin -e nandheader sb kv
    ex. python3 flash-dump.py image.bin -e all


-r  Replace section
    Provided replacement must be decrypted (plaintext) as well as decompressed in the case of kernel and hv

    Valid sections are as above

    ex. python3 flash-dump.py image.bin -r se se_patched_plain.bin
    ex. python3 flash-dump.py image.bin -r kernel xboxkrnl_patched_plain_dec.bin


-d  Decrypt section(s)

    Attempts to decrypt the given sections in place or treat input as decrypted

    Valid sections are as above

    Used in combination with extract and replace

    ex. python3 flash-dump.py image.bin -d sb smc -x sb sd smc


#-i  Insert section
#    Provided section must be decrypted (plaintext) as well as decompressed in the case of kernel and hv
#
#    Fails if the section already exists in the image
#
#    This should only be used in rare situations as it is difficult to use properly
#
#    Valid sections are as above
#
#    ex. python3 flash-dump.py image.bin -i se se_patched_plain.bin
#    ex. python3 flash-dump.py image.bin -i kernel xboxkrnl_patched_plain_dec.bin


#-ir Insert / Replace section
#    Provided section must be decrypted (plaintext) as well as decompressed in the case of kernel and hv
#
#    Same as -i, but will replace instead of failing if the section already exists
#
#    Valid sections are as above
#
#    ex. python3 flash-dump.py image.bin -ir se se_patched_plain.bin
#    ex. python3 flash-dump.py image.bin -ir kernel xboxkrnl_patched_plain_dec.bin


#-bs Build shadowboot image from sections
#    Provided sections must be decrypted (plaintext)
#
#    Required sections are smc, sb/cb, sc, sd/cd, se
#
#    Will fail if missing required section
#
#    Will warn if mismatch in development (SX) and retail (CX) bootloaders
#
#    Will warn if expected patch slots mismatches from provided
#
#    ex. python3 flash-dump.py image.bin -bs smc_plain.bin sb_plain.bin sc_plain.bin sd_plain.bin se_plain.bin


-c  CPU key
    Required to decrypt bootloaders CD and onward on retails with CB >= 1920
    Required to decrypt keyvault
    Required to replace encrypted sections

    By default the programs looks for a binary file, "cpukey" in the "data" directory

    ex. python3 flash-dump.py image.bin -c 48a3e35253c20bcc796d6ec1d5d3d811


 -k  Key file path

     By default the programs looks for a binary file, "keyfile" in the "data" directory

     This file should be the binary representation of the 1BL key

     ex. python3 flash-dump.py image.bin -x kernel -k /path/to/keys.txt

 -s  Sign
     Provided file must be decrypted (plaintext) SD

     Signs the given 4BL with the 4BL private key

     ex. python3 flash-dump.py -s SD_dec.bin


--debug  Verbose output for debugging


-v  Version

"""

import argparse
import textwrap
import logging

from lib import keys
from lib.image import Image


logging.basicConfig()
LOGGER = logging.getLogger('flash-dump-tool')


def main():
    parser = argparse.ArgumentParser(prog='flash-dump',
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description=textwrap.dedent('''\
        360 Flash Tool - acabey
        --------------------------------
            Load and dump information from flash dumps and shadowboot ROMs
            Should be able to detect type of file as well as partial files
        '''),
                                     epilog=textwrap.dedent('''\
        Valid sections are:
            keyvault, smc, smcconfig, sb, cb, sc, sd, cd, se, ce, cf, cg, cf1, cg1, kernel, hv
        ''')
                                     )

    parser.add_argument('target', type=str, metavar='/path/to/working/file',
                        help='Working file - NAND/Shadowboot/NAND section or output file name')
    parser.add_argument('-e', '--enumerate', nargs='+', metavar='section', type=str, help='Enumerate section(s)')
    parser.add_argument('-d', '--decrypt', nargs='+', metavar='section', type=str, help='Decrypt section(s)')
    parser.add_argument('-x', '--extract', nargs='+', metavar='section', type=str, help='Extract section(s)')
    parser.add_argument('-r', '--replace', nargs=2, type=str, metavar=('section', '/path/to/replacement'),
                        help='Replace decrypted section')
    parser.add_argument('-s', '--sign', nargs=1, type=str, metavar='section', help='Sign section (SD)')
    parser.add_argument('-k', '--keyfile', nargs=1, type=str, metavar='/path/to/keyfile', help='Key file')
    parser.add_argument('-c', '--cpukey', nargs=1, type=str, metavar='cpukey', help='CPU key')
    parser.add_argument('--debug', action='store_true', help='Verbose debug output')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.5', help='Version')
    args = parser.parse_args()

    if args.verbose:
        LOGGER.setLevel(logging.INFO)
    if args.debug:
        LOGGER.setLevel(logging.DEBUG)

    LOGGER.debug('args: ' + str(args))

    # Load image
    """
    Read from the provided image file
    
    - Check valid image
        - Magic bytes (hard)
        - Copyright (soft)
    - Construct NAND header
    """

    # Load input metadata and populate available sections
    """
    ============================================================================
    Input metadata
        Load NAND/shadowboot structures
    ============================================================================
    """
    try:
        Image.identifyAvailableStructures(args.target)
        availablesections = Image.getAvailableStructures()
    except Exception as e:
        LOGGER.error('Failed to identify available structures: ' + str(e))

    """
    ============================================================================
    Manipulate input
    ============================================================================
    """

    # CPU key if available
    if args.cpukey is not None:
        try:
            keys.CPUKEY = bytes.fromhex(args.cpukey[0])
        except Exception as e:
            keys.CPUKEY = None
            LOGGER.error('Failed to set given CPU key: ' + str(e))

    # BL1 key if available
    if args.keyfile is not None:
        try:
            with open(args.keyfile[0], 'rb') as keyfile:
                keys.SECRET_1BL = keyfile.read()
        except Exception as e:
            keys.SECRET_1BL = None
            LOGGER.error('Failed to set 1BL key from keyfile' + str(e))

    # Enumerate if available
    if args.enumerate is not None:
        for section in args.enumerate:
            if section == 'all':
                for availablesection in availablesections:
                    print('==== ' + availablesection + ' ====')
                    print(availablesections[availablesection].enumerate())
                    print('')
                break

            if section in availablesections.keys():
                print('==== ' + section + ' ====')
                print(availablesections[section].enumerate())
            else:
                LOGGER.warning('Section: ' + section + ' is not available in input file')

    # Extract if available
    if args.extract is not None:
        for section in args.extract:
            if section == 'all':
                for availablesection in availablesections:
                    availablesections[availablesection].extract()
                break

            if section in availablesections.keys():
                availablesections[section].extract()
            else:
                LOGGER.warning('Section: ' + section + ' is not available in input file')

    # Replace if available
    if args.replace is not None:
        section = args.replace[0]
        replacementpath = args.replace[1]
        LOGGER.debug(availablesections.keys())
        if section in availablesections.keys():
            try:
                availablesections[section].replace(replacementpath)
                availablesections[section].write(Image.outputpath.path)
            except Exception as e:
                LOGGER.error('Failed to replace ' + section + ': ' + str(e))
        else:
            LOGGER.warning('Section: ' + section + ' is not available in input file')

    # Sign if available
    if args.sign is not None:
        for section in args.sign:
            if section == 'all':
                for availablesection in availablesections:
                    availablesections[availablesection].sign()
                break

            if section in availablesections.keys():
                availablesections[section].sign()
            else:
                LOGGER.warning('Section: ' + section + ' is not available in input file')


if __name__ == '__main__':
    main()
