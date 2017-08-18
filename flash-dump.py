#/usr/bin/python3

"""
Load and dump information from flash dumps and shadowboot ROMs

Should be able to detect type of file as well as partial files

Usage: python3 flash-dump.py image.bin [cpukey]

"""

import os

# Load image
"""
Read from the provided image file

- Check valid image
    - Magic bytes (hard)
    - Copyright (soft)
- Construct NAND header
"""

def main(argv):
    target = argv[1] if len(sys.argv) > 1 else None

    if not target:
        sys.exit(1)

    # Parse file header
    with open(target, 'rb') as image:
        nandheader = NANDHeader(image.read(NANDHeader.HEADER_SIZE))
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
                nandsections.append(smc)
                print('Found valid SMC at ' + str(smc.offset))
            else:
                print('SMC is null, skipping')
        else:
            print('SMC offset is null, skipping')

        # Check for Keyvault
        # Because the keyvault's length is stored in its header, we first create the header object
        if not nandheader.kvoffset == 0:
            image.seek(nandheader.kvoffset,0)
            keyvaultheaderdata = image.read(KeyvaultHeader.HEADER_SIZE)
            # Make sure KV header is not null
            if not all(b == 0 for b in keyvaultheaderdata):
                keyvaultheader = KeyvaultHeader(keyvaultheaderdata, nandheader.keyvaultoffset)

                image.seek(nandheader.kvoffset,0)
                keyvaultdata = image.read(keyvaultheader.length)
                # Make sure KV is not null
                if not all(b == 0 for b in keyvaultdata):
                    keyvault = Keyvault(keyvaultheader, keyvaultdata)
                    nandsections.append(keyvault)
                    print('Found valid keyvault at ' + str(keyvault.offset))
                else:
                    print('Keyvault data is null, skipping')
            else:
                print('Keyvault header is null, skipping')
        else:
            print('Keyvault offset is null, skipping')

        # Check for 2BL (CB/SB)
        # Because the bootloader's length is stored in its header, we first create the header object
        if not nandheader.kvoffset == 0:
            image.seek(nandheader.kvoffset,0)
            bl2headerdata = image.read(BL2Header.HEADER_SIZE)
            # Make sure BL2 header is not null
            if not all(b == 0 for b in bl2headerdata):
                bl2header = BootloaderHeader(bl2headerdata, nandheader.bl2offset)

                image.seek(nandheader.bl2offset,0)
                bl2data = image.read(bl2header.length)
                # Make sure BL2 is not null
                if not all(b == 0 for b in bl2data):
                    bl2 = BL2(bl2header, bl2data)
                    nandsections.append(bl2)
                    print('Found valid bl2: ' + bl2.name + ' at ' + str(bl2.offset))
                else:
                    print('BL2 data is null, skipping')
            else:
                print('BL2 header is null, skipping')
        else:
            print('BL2 offset is null, skipping')

        # Check for 3BL (CD/SC)

        # Check for 4BL (CE/SD)

        # Check for 5BL (CF)

        # Check for 6BL (CG)

        # Check for 5BL2 (CF)

        # Check for 6BL2 (CG)

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
