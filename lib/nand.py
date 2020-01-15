#!/usr/bin/env python3

import struct
from enum import Enum

"""
A unifying interface for all NAND sections to generalize and simplify extraction and output
"""


class NANDSection(object):

    def enumerate(self):
        """
        Returns a formatted, printable string representing the metadata for the section

        Printed out as part of enumeration
        """
        raise NotImplementedError()

    def extract(self):
        """
        Write contents to file in output directory
        """
        raise NotImplementedError()


class NANDHeader(NANDSection):
    HEADER_SIZE = 0x80
    MAGIC_BYTES = b'\xFF\x4F'
    MS_COPYRIGHT = b'\xa9 2004-2011 Microsoft Corporation. All rights reserved.\x00'

    """
    See: https://free60.acabey.xyz/index.php/NAND_File_System

    struct NAND_HEADER {
        uint32_t wMagic; // 0xFF4F
        uint32_t wBuild;
        uint32_t wQfe;
        uint32_t wFlags;
        uint64_t dwEntry;
        uint64_t dwSize;
        uint8_t abCopyright[64];
        uint8_t abReserved[16]; // 0x0 filled
        uint64_t dwKeyVaultSize; // size of the keyvault
        uint64_t dwSysUpdateAddr; // offset to first cf
        uint32_t wSysUpdateCount; // number of patch slots
        uint32_t wKeyVaultVersion; // 0x0712
        uint64_t dwKeyVaultAddr; // offset of the keyvault from 0
        uint64_t dwPatchSlotSize; // if == 0 then = 0x10000, patch slot size
        uint64_t dwSmcConfigAddr; // 0x0
        uint64_t dwSmcBootSize; // size of smc.bin
        uint64_t dwSmcBootAddr; // offset of smc.bin from 0
    }

    """

    def __init__(self, header, currentoffset=0):
        if len(header) < NANDHeader.HEADER_SIZE:
            raise ValueError('Invalid size for NAND header')

        header = struct.unpack('>2s3H2I64s16s2I2H5I', header)
        self.magic = header[0]  # 2s
        if self.magic != NANDHeader.MAGIC_BYTES:
            raise ValueError('Failed NAND header magic bytes check')

        self.build = header[1]  # H
        self.qfe = header[2]  # H
        self.flags = header[3]  # H
        self.bl2offset = header[4]  # I
        # The length until reaching 5BL? Not sure what this really is
        self.length = header[5]  # I
        self.copyright = header[6]  # 64s
        self.reserved = header[7]  # 16s
        self.kvlength = header[8]  # I
        self.cf1offset = header[9]  # I
        self.patchslots = header[10]  # H
        self.kvversion = header[11]  # H
        self.kvoffset = header[12]  # I
        self.patchlength = header[13]  # I
        self.smcconfigoffset = header[14]  # I
        self.smclength = header[15]  # I
        self.smcoffset = header[16]  # I

        self.offset = currentoffset

    def __str__(self):
        ret = ''
        ret += str(self.magic)
        ret += '\n'
        ret += str(self.build)
        ret += '\n'
        ret += str(hex(self.bl2offset))
        ret += '\n'
        ret += str(hex(self.cf1offset))
        ret += '\n'
        ret += str(self.copyright)
        ret += '\n'
        ret += str(hex(self.kvoffset))
        ret += '\n'
        ret += str(hex(self.patchlength))
        ret += '\n'
        ret += str(hex(self.smclength))
        ret += '\n'
        ret += str(hex(self.smcoffset))
        return ret

    def enumerate(self):
        ret = 'NANDHeader:'
        ret += '\n'
        ret += 'magic:         '
        ret += str(self.magic)
        ret += '\n'
        ret += 'build:         '
        ret += str(self.build)
        ret += '\n'
        ret += 'sb offset:     '
        ret += str(hex(self.bl2offset))
        ret += '\n'
        ret += 'cf1 offset:    '
        ret += str(hex(self.cf1offset))
        ret += '\n'
        ret += 'copyright:     '
        ret += str(self.copyright)
        ret += '\n'
        ret += 'kv offset:     '
        ret += str(hex(self.kvoffset))
        ret += '\n'
        ret += 'metadatastyle: '
        ret += str(hex(self.patchlength))
        ret += '\n'
        ret += 'smc length:    '
        ret += str(hex(self.smclength))
        ret += '\n'
        ret += 'smc offset:    '
        ret += str(hex(self.smcoffset))
        return ret

    def extract(self):
        """
        Write header contents into Header.<build>.bin
        """
        with open('output/' + 'Header' + '.' + str(self.build) + '.bin', 'w+b') as headerout:
            headerout.write(self.pack())

    def replace(self, replacement):
        """
        Replace data with contents of replacement file
        """
        with open(replacement, 'rb') as replacementdata:
            self = type(self)(replacementdata.read(NANDHeader.HEADER_SIZE), self.offset)

    def write(self, output):
        """
        Write current contents to file
        """
        with open(output, 'r+b') as originaldata:
            originaldata.seek(self.offset, 0)
            originaldata.write(self.pack())

    def validateMagic(self):
        """
        Check if magic bytes at the beginning of header match known NAND/shadowboot magic
        """
        return self.magic == NANDHeader.MAGIC_BYTES

    def validateCopyright(self):
        """
        Check if the copyright notice matches Microsoft's known value except for the years
        """
        return self.copyright[0:1] + self.copyright[11:] != NANDHeader.MS_COPYRIGHT[0:1] + NANDHeader.MS_COPYRIGHT[11:]

    def pack(self):
        """
        Pack back into C style struct
        """
        return struct.pack('>2s3H2I64s16s2I2H5I',
                           self.magic,
                           self.build,
                           self.qfe,
                           self.flags,
                           self.bl2offset,
                           self.length,
                           self.copyright,
                           self.reserved,
                           self.kvlength,
                           self.cf1offset,
                           self.patchslots,
                           self.kvversion,
                           self.kvoffset,
                           self.patchlength,
                           self.smcconfigoffset,
                           self.smclength,
                           self.smcoffset
                           )


class OutputPath(NANDSection):
    def __init__(self, path):
        self.path = path

    def enumerate(self):
        return 'OutputPath:\n' + 'path: ' + self.path

    def extract(self):
        pass


class ImageType(NANDSection, Enum):
    RETAIL, DEVKIT, SHADOWBOOT = range(3)

    def enumerate(self):
        return str(self)

    def extract(self):
        pass
