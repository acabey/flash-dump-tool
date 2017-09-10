#!/usr/bin/env python3

"""
Load and dump information from flash dumps and shadowboot ROMs

Detect type of file as well as partial files (ie. extracted bootloader)

Usage: python3 flash-dump.py image.bin -c cpukey -x section

-c  CPU key
    Required to decrypt bootloaders CD and onward on retails with CB >= 1920
    Required to decrypt keyvault
    Required to replace encrypted sections

    ex. python3 flash-dump.py image.bin -c 48a3e35253c20bcc796d6ec1d5d3d811

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

#-k  Key file path
#
#    By default the programs looks for a plaintext file called "keys" in the local directory
#
#    Provided file must follow the format where line 1 is the 1BL RC4 key and line 2 the 4BL private key
#
#    ex. python3 flash-dump.py image.bin -x kernel -k /path/to/keys.txt
#
#-s  Sign
#    Provided file must be decrypted (plaintext) SD
#
#    Signs the given 4BL with the 4BL private key
#
#    ex. python3 flash-dump.py -s SD_dec.bin

--debug  Verbose output for debugging

-v  Version

"""

import os, sys, argparse, textwrap
from common import *
from nand import NANDHeader, ImageType
from bootloader import *
from smc import SMC
from image import Image

# Load image
"""
Read from the provided image file

- Check valid image
    - Magic bytes (hard)
    - Copyright (soft)
- Construct NAND header
"""

def main(argv):

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

    parser.add_argument('target', type=str, metavar='/path/to/working/file', help='Working file - NAND/Shadowboot/NAND section or output file name')
    parser.add_argument('-e', '--enumerate', nargs='+', metavar='section', type=str, help='Enumerate section(s)')
    parser.add_argument('-d', '--decrypt', nargs='+', metavar='section', type=str, help='Decrypt section(s)')
    parser.add_argument('-x', '--extract', nargs='+', metavar='section', type=str, help='Extract section(s)')
    parser.add_argument('-r', '--replace', nargs=2, type=str, metavar=('section', '/path/to/replacement'), help='Replace decrypted section')
    parser.add_argument('-k', '--keyfile', nargs=1, type=str, metavar='/path/to/keyfile', help='Key file')
    parser.add_argument('-c', '--cpukey', nargs=1, type=str, metavar='cpukey', help='CPU key')
    parser.add_argument('--debug', action='store_true', help='Verbose debug output')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 0.5', help='Version')
    args = parser.parse_args()

    # Load input metadata and populate available sections
    """
    ============================================================================
    Input metadata
        Load NAND/shadowboot structures
    ============================================================================
    """
    Image.identifyAvailableStructures(args.target)
    availablesections = Image.getAvailableStructures()


    """
    ============================================================================
    Manipulate input
    ============================================================================
    """
    dbgprint('args: ' + str(args))

    # Enumerate if available
    if not args.enumerate == None:
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
                warnprint('Section: ' + section + ' is not available in input file')

    # Extract if available
    if not args.extract == None:
        for section in args.extract:
            if section == 'all':
                for availablesection in availablesections:
                    availablesections[availablesection].extract()
                break

            if section in availablesections.keys():
                availablesections[section].extract()
            else:
                warnprint('Section: ' + section + ' is not available in input file')

    # Replace if available
    if not args.replace == None:
        section = args.replace[0]
        replacementpath = args.replace[1]
        dbgprint(availablesections.keys())
        if section in availablesections.keys():
            try:
                availablesections[section].replace(replacementpath)
                availablesections[section].write(Image.outputpath.path)
            except Exception as e:
                failprint('Failed to replace ' + section + ': ' + str(e))
        else:
            warnprint('Section: ' + section + ' is not available in input file')

    """
    ============================================================================
    DEPRECATED

    This is code from prior revisions that I have not refactored.
    It will be kept (inaccesible) as a reference until implemented in new structure

    ============================================================================
    """
    if False:
        nandsections = []

        # Check for SMC
        if not nandheader.smcoffset == 0:
            image.seek(nandheader.smcoffset,0)
            smcdata = image.read(nandheader.smclength)
            # Make sure SMC is not null
            if not all(b == 0 for b in smcdata):
                smc = SMC(smcdata, nandheader.smcoffset)
# TODO Unifying interface for nandsections
#                nandsections.append(smc)
                print('Found valid SMC at ' + str(hex(smc.offset)))
            else:
                print('SMC is null, skipping SMC')
        else:
            print('SMC offset is null, skipping SMC')

# TODO
        # Check for Keyvault
        # Because the keyvault's length is stored in its header, we first create the header object
        if not nandheader.kvoffset == 0:
            image.seek(nandheader.kvoffset,0)
            keyvaultheaderdata = image.read(KeyvaultHeader.HEADER_SIZE)
            # Make sure KV header is not null
            if not all(b == 0 for b in keyvaultheaderdata):
                keyvaultheader = KeyvaultHeader(keyvaultheaderdata, nandheader.kvoffset)

                image.seek(nandheader.kvoffset,0)
                keyvaultdata = image.read(keyvaultheader.length)
                # Make sure KV is not null
                if not all(b == 0 for b in keyvaultdata):
                    keyvault = Keyvault(keyvaultheader, keyvaultdata)
                    nandsections.append(keyvault)
                    print('Found valid keyvault at ' + str(hex(keyvault.offset)))
                else:
                    print('Keyvault data is null, skipping keyvault')
            else:
                print('Keyvault header is null, skipping keyvault')
        else:
            print('Keyvault offset is null, skipping keyvault')

        """
        ============================================================================
        NAND Extras
        ============================================================================
        """

        # Check for 5BL (CF/SE)
        # Retails will have 5BL (CF) and 6BL (CG)
        if imagetype == ImageType.Retail:
            pass
            # Check for 5BL (CF)

            # Check for 6BL (CG)

            # Check for 5BL2 (CF)

            # Check for 6BL2 (CG)
        # Devkits and shadowboot ROMs will have 5BL (SE)
        else:
            # Check for 5BL (SE)
            if bl4header:
                bl5offset = bl4header.offset + bl4header.length
                image.seek(bl5offset, 0)
                bl5headerdata = image.read(BootloaderHeader.HEADER_SIZE)
                # Make sure BL5 header is not null
                if not all(b == 0 for b in bl5headerdata):
                    bl5header = BootloaderHeader(bl5headerdata, bl5offset)

                    image.seek(bl5offset, 0)
                    bl5data = image.read(bl5header.length)
                    # Make sure BL4 is not null
                    if not all(b == 0 for b in bl5data):
                        # Make proper bootloader object
                        bl5 = Bootloader(bl5data, bl5header)
                        nandsections.append(bl5)
                        print('Found valid BL5: ' + bl5.header.name + ' at ' + str(hex(bl5.header.offset)))
                        if bl4:
                            bl5.updateKey(bl4.key)
                            bl5.decrypt()
                            print('Decrypted BL5')
                        else:
                            print('BL4 is null, cannot decrypt BL5')
                    else:
                        print('BL4 data is null, skipping BL5')
                else:
                    print('BL4 header is null, skipping BL5')
            else:
                print('BL4 (header) missing, skipping BL5')

        # Determine if CPU key required (CD)
        """
        Check versions to see if CPU key will be required

        Retail:
        - CB version >= 1920
        - Required for CD, keyvault, SMC config?

        XDK
        - Required for keyvault

        Shadowboot
        - Not required
        """

    sys.exit(0)

if __name__ == '__main__':
    main(sys.argv)
