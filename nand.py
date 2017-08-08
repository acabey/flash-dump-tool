#!/bin/python3

import struct

from bootloader import Bootloader, CB, CD, CE, CF, CG

class NANDImage():

    def __init__(self, image, imagesize):
        """

        - read NAND header for SMC offset / length
        - read SMC into object
        - read SB offset from NAND header
        - read SB length from SB header
        - read SB into object
        - read SC offset / length from header
        - read SC into object
        - read SD offset / length from header
        - read SD into object
        - read SE offset / length from header
        - read SE into object
        
        """
        self.bootloaders = []

        currentoffset = 0
        MAX_READ = imagesize
        
        # Read file
        headerdata = image.read(NANDHeader.HEADER_SIZE)
        self.nandheader = NANDHeader(headerdata, currentoffset)

        # Validate image
        self.nandheader.validate()

        # read SB offset from NAND header

        currentoffset += self.nandheader.sboffset
        
        if currentoffset + Bootloader.HEADER_SIZE < MAX_READ:
            # read SB length from SB header
            image.seek(currentoffset, 0)
            sblength = Bootloader(image.read(Bootloader.HEADER_SIZE), currentoffset).length

            # read SB into object
            image.seek(currentoffset, 0)
            sbdata = image.read(sblength)
            self.sb = CB(sbdata, currentoffset)
            self.bootloaders.append(self.sb)

            currentoffset += self.sb.length

        # 3BL
        if currentoffset + Bootloader.HEADER_SIZE < MAX_READ:
            # read SC offset / length from header
            image.seek(currentoffset, 0)
            sclength = Bootloader(image.read(Bootloader.HEADER_SIZE), currentoffset).length

            # read SC into object
            image.seek(currentoffset, 0)
            ###scdata = image.read(sclength)
            scdata = image.read(Bootloader.HEADER_SIZE)
            # TODO Implement SC; however, the whole CX vs SX has to be re-thought
            self.sc = Bootloader(scdata, currentoffset)
            self.bootloaders.append(self.sc)

            currentoffset += self.sc.length


        # 4BL
        if currentoffset + Bootloader.HEADER_SIZE < MAX_READ:
            # read SD offset / length from header
            image.seek(currentoffset, 0)
            sdlength = Bootloader(image.read(Bootloader.HEADER_SIZE), currentoffset).length

            # read SD into object
            image.seek(currentoffset, 0)
            sddata = image.read(sdlength)
            self.sd = CD(sddata, currentoffset)
            self.bootloaders.append(self.sd)

            currentoffset += self.sd.length


        # 5BL
        if currentoffset + Bootloader.HEADER_SIZE < MAX_READ:
            # read SE offset / length from header
            image.seek(currentoffset, 0)
            selength = Bootloader(image.read(Bootloader.HEADER_SIZE), currentoffset).length

            # read SE into object
            image.seek(currentoffset, 0)
            sedata = image.read(selength)
            self.se = CE(sedata, currentoffset)
            self.bootloaders.append(self.se)

            currentoffset += self.se.length

    def printMetadata(self):
        print('=== ' + str(hex(self.nandheader.offset)) + ' ===\n' + str(self.nandheader))
        for bl in self.bootloaders:
            print('=== ' + str(hex(bl.offset)) + ' ===\n' + str(bl))

    def exportParts(self):
        
        random = bytes('\0' * 16, 'ascii')

        # Decrypt and export encrypted BL
        with open('output/'+self.sb.name.decode('ascii') +'_' + str(self.sb.build) + '_enc.bin', 'wb') as sbout:
            sbout.write(self.sb.block_encrypted)

        # Decrypt and export decrypted BL
        with open('output/'+self.sb.name.decode('ascii') +'_' + str(self.sb.build) + '_dec.bin', 'wb') as sbout:
            sbout.write(self.sb.decrypt_CB())

        self.sb.updateKey(random)

        # Decrypt and export decrypted SD
        with open('output/SD_' + str(self.sd.build) + '_enc.bin', 'wb') as sdout:
            sdout.write(self.sd.block_encrypted)

        # Decrypt and export decrypted SD
        with open('output/SD_' + str(self.sd.build) + '_dec.bin', 'wb') as sdout:
            sdout.write(self.sd.decrypt_CD(self.sb))

        self.sd.updateKey(self.sb, random)

        # Decrypt and export decrypted SE
        with open('output/SE_' + str(self.se.build) + '_enc.bin', 'wb') as seout:
            seout.write(self.se.block_encrypted)

        # Decrypt and export decrypted SE
        with open('output/SE_' + str(self.se.build) + '_dec.bin', 'wb') as seout:
            seout.write(self.se.decrypt_CE(self.sd))

class NANDHeader():

    HEADER_SIZE = 0x80
    MAGIC_BYTES = b'\xFF\x4F'
    MS_COPYRIGHT = b'\xa9 2004-2011 Microsoft Corporation. All rights reserved.\x00'

    def __init__(self, header, currentoffset):
        header = struct.unpack('>2s3H2I56s24s4I2H3I', header)
        self.magic = header[0]
        self.build = header[1]
        self.unknown0x4 = header[2]
        self.unknown0x6 = header[3]
        self.sboffset = header[4]
        self.cf1offset = header[5]
        self.copyright = header[6]
        self.unknown0x60 = header[8]
        self.unknown0x64 = header[9]
        self.unknown0x68 = header[10]
        self.kvoffset = header[11]
        self.metadatastyle = header[12]
        self.unknown0x72 = header[13]
        self.unknown0x74 = header[14]
        self.smclength = header[15]
        self.smcoffset = header[16]

        self.offset = currentoffset

    def __str__(self):
        ret = ''
        ret += str(self.magic)
        ret += '\n'
        ret += str(self.build)
        ret += '\n'
        ret += str(hex(self.sboffset))
        ret += '\n'
        ret += str(hex(self.cf1offset))
        ret += '\n'
        ret += str(self.copyright)
        ret += '\n'
        ret += str(hex(self.kvoffset))
        ret += '\n'
        ret += str(hex(self.metadatastyle))
        ret += '\n'
        ret += str(hex(self.smclength))
        ret += '\n'
        ret += str(hex(self.smcoffset))
        return ret

    def validate(self):
        if self.copyright[0:1]+self.copyright[11:] != NANDHeader.MS_COPYRIGHT[0:1]+NANDHeader.MS_COPYRIGHT[11:]:
            print('** Warning: failed copyright notice check invalid or custom image')

        if self.magic != NANDHeader.MAGIC_BYTES:
            print('** Failure: magic bytes check: invalid image')
            return False

