#!/usr/bin/env python3

"""
Load and dump information from flash dumps and shadowboot ROMs

Should be able to detect type of file as well as partial files

Usage: python3 flash-dump.py image.bin [cpukey]

"""

import os, sys
from nand import NANDHeader, ImageType, Constants
from smc import SMC
from bootloader import BootloaderHeader, CFHeader, Bootloader, BL2, CF

# Load image
"""
Read from the provided image file

- Check valid image
    - Magic bytes (hard)
    - Copyright (soft)
- Construct NAND header
"""

def main(argv):

    target = argv[1] if len(argv) > 1 else None

    if not target:
        print("Usage: flash-dump.py path/to/image.bin")
        sys.exit(1)

    # Parse file header
    with open(target, 'rb') as image:
        nandheader = NANDHeader(image.read(NANDHeader.HEADER_SIZE), 0)
        # TODO: Allow override for magic check
        if not nandheader.validateMagic():
            print('** Failure: magic bytes check: invalid image')
        if not nandheader.validateCopyright():
            print('** Warning: failed copyright notice check invalid or custom image')

        # Detect image type
        """
        Determine dump format (size), retail/XDK/shadowboot

        Differentiates between XDK and retail by bootloader name
        """
        # Check file size
        filesize = os.path.getsize(target)
        if filesize <= Constants.SHADOWBOOT_SIZE:
            imagetype = ImageType.Shadowboot
            print('Detected image by file size as shadowboot')
        else:
            # Check if BL2 is SB or CB
            image.seek(nandheader.bl2offset,0)
            bl2name = image.read(2)
            if bl2name == b'CB':
                imagetype = ImageType.Retail
                print('Detected image by bootloader name as retail')
            elif bl2name == b'SB':
                imagetype = ImageType.Devkit
                print('Detected image by bootloader name as devkit')

        # Newline
        print('')


        # Load structure accordingly
        """
        Identify present structures

        Retail:
        - CB[_A, _B], CD, CE, [CF, CG]
        - Keyvault
        - SMC / SMC config

        XDK
        - SB, SC, SD, SE
        - Keyvault
        - SMC / SMC config

        Shadowboot:
        - SB, SC, SD, SE
        - SMC / SMC config ?
        """
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
#        # Check for Keyvault
#        # Because the keyvault's length is stored in its header, we first create the header object
#        if not nandheader.kvoffset == 0:
#            image.seek(nandheader.kvoffset,0)
#            keyvaultheaderdata = image.read(KeyvaultHeader.HEADER_SIZE)
#            # Make sure KV header is not null
#            if not all(b == 0 for b in keyvaultheaderdata):
#                keyvaultheader = KeyvaultHeader(keyvaultheaderdata, nandheader.keyvaultoffset)
#
#                image.seek(nandheader.kvoffset,0)
#                keyvaultdata = image.read(keyvaultheader.length)
#                # Make sure KV is not null
#                if not all(b == 0 for b in keyvaultdata):
#                    keyvault = Keyvault(keyvaultheader, keyvaultdata)
#                    nandsections.append(keyvault)
#                    print('Found valid keyvault at ' + str(hex(keyvault.offset)))
#                else:
#                    print('Keyvault data is null, skipping keyvault')
#            else:
#                print('Keyvault header is null, skipping keyvault')
#        else:
#            print('Keyvault offset is null, skipping keyvault')

        # Check for 2BL (CB/SB)
        # Because the bootloader's length is stored in its header, we first create the header object
        if not nandheader.bl2offset == 0:
            bl2offset = nandheader.bl2offset
            image.seek(bl2offset,0)
            bl2headerdata = image.read(BootloaderHeader.HEADER_SIZE)
            # Make sure BL2 header is not null
            if not all(b == 0 for b in bl2headerdata):
                bl2header = BootloaderHeader(bl2headerdata, bl2offset)

                image.seek(bl2offset,0)
                bl2data = image.read(bl2header.length)
                # Make sure BL2 is not null
                if not all(b == 0 for b in bl2data):
                    # Make proper bootloader object
                    bl2 = BL2(bl2data, bl2header)
                    nandsections.append(bl2)
                    print('Found valid BL2: ' + bl2.header.name + ' at ' + str(hex(bl2.header.offset)))
                    bl2.updateKey()
                    bl2.decrypt()
                    print('Decrypted BL2')
                else:
                    print('BL2 data is null, skipping BL2')
            else:
                print('BL2 header is null, skipping BL2')
        else:
            print('BL2 offset is null, skipping BL2')

        # Check for 3BL (CD/SC)
        # Because the bootloader's length is stored in its header, we first create the header object
        if bl2header:
            bl3offset = bl2header.offset + bl2header.length
            image.seek(bl3offset, 0)
            bl3headerdata = image.read(BootloaderHeader.HEADER_SIZE)
            # Make sure BL3 header is not null
            if not all(b == 0 for b in bl3headerdata):
                bl3header = BootloaderHeader(bl3headerdata, bl3offset)

                image.seek(bl3offset, 0)
                bl3data = image.read(bl3header.length)
                # Make sure BL2 is not null
                if not all(b == 0 for b in bl3data):
                    # Make proper bootloader object
                    bl3 = Bootloader(bl3data, bl3header)
                    nandsections.append(bl3)
                    print('Found valid BL3: ' + bl3.header.name + ' at ' + str(hex(bl3.header.offset)))
                    if bl2:
                        #bl3.updateKey(bl2.key)
                        # I am not sure why this works, but it decrypts properly
                        bl3.updateKey(bytes('\x00'*0x10, 'ASCII'))
                        bl3.decrypt()
                        print('Decrypted BL3')
                    else:
                        print('BL2 is null, cannot decrypt BL3')
                else:
                    print('BL2 data is null, skipping BL3')
            else:
                print('BL2 header is null, skipping BL3')
        else:
            print('BL2 (header) missing, skipping BL3')

        # Check for 4BL (CE/SD)
        if bl3header:
            bl4offset = bl3header.offset + bl3header.length
            image.seek(bl4offset, 0)
            bl4headerdata = image.read(BootloaderHeader.HEADER_SIZE)
            # Make sure BL4 header is not null
            if not all(b == 0 for b in bl4headerdata):
                bl4header = BootloaderHeader(bl4headerdata, bl4offset)

                image.seek(bl4offset, 0)
                bl4data = image.read(bl4header.length)
                # Make sure BL3 is not null
                if not all(b == 0 for b in bl4data):
                    # Make proper bootloader object
                    bl4 = Bootloader(bl4data, bl4header)
                    nandsections.append(bl4)
                    print('Found valid BL4: ' + bl4.header.name + ' at ' + str(hex(bl4.header.offset)))
                    if bl3:
                        bl4.updateKey(bl3.key)
                        bl4.decrypt()
                        print('Decrypted BL4')
                    else:
                        print('BL3 is null, cannot decrypt BL4')
                else:
                    print('BL3 data is null, skipping BL4')
            else:
                print('BL3 header is null, skipping BL4')
        else:
            print('BL3 (header) missing, skipping BL4')

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

        # Newline
        print('')

        for section in nandsections:
            print(str(section))
            print('')

if __name__ == '__main__':
    main(sys.argv)
