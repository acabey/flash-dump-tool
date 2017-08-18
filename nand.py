#!/usr/bin/python3

import struct

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
        self.bl2offset = header[4]
        self.bl5offset = header[5]
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

    """
    Check if magic bytes at the beginning of header match known NAND/shadowboot magic
    """
    def validateMagic(self):
        return self.magic != NANDHeader.MAGIC_BYTES

    """
    Check if the copyright notice matches Microsoft's known value except for the years
    """
    def validateCopyright(self):
        return self.copyright[0:1]+self.copyright[11:] != NANDHeader.MS_COPYRIGHT[0:1]+NANDHeader.MS_COPYRIGHT[11:]
