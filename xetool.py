#/bin/python3

import sys
import struct
import os

#import ipdb

class NANDHeader():

    HEADER_SIZE = 0x80
    MAGIC_BYTES = b'\xFF\x4F'
    MS_COPYRIGHT = b'\xa9 2004-2011 Microsoft Corporation. All rights reserved.\x00'

    def __init__(self, header):
        header = struct.unpack('>2s3H2I56s24s4I2H3I', header)
        self.magic = header[0]
        self.build = header[1]
        self.unknown0x4 = header[2]
        self.unknown0x6 = header[3]
        self.sboffset = header[4]
        self.cf1offset = header[5]
        self.copyright = header[6]
        self.unknown0x60 = header[8]
        self.uknown0x64 = header[9]
        self.unknown0x68 = header[10]
        self.kvoffset = header[11]
        self.metadatastyle = header[12]
        self.unknown0x72 = header[13]
        self.unknown0x74 = header[14]
        self.smclength = header[15]
        self.smcoffset = header[16]

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

class Bootloader():

    HEADER_SIZE = 0x20

    def __init__(self, header):
        header = struct.unpack('>2s3H2I16s', header)

        self.name = header[0]
        self.build = header[1]
        self.pairing = header[2]
        self.flags = header[3]
        self.entrypoint = header[4]
        self.length = header[5]
        self.salt = header[6]

    def __str__(self):
        ret = ''
        ret += str(self.name)
        ret += '\n'
        ret += str(self.build)
        ret += '\n'
        ret += str(hex(self.pairing))
        ret += '\n'
        ret += str(hex(self.flags))
        ret += '\n'
        ret += str(hex(self.entrypoint))
        ret += '\n'
        ret += str(hex(self.length))
        ret += '\n'
        ret += str(self.salt)
        return ret
    
    def pack(self):
        return struct.pack('>2p3H2I16p', bytes(self.name), self.build, self.pairing, self.flags, self.entrypoint, self.length, bytes(self.salt))

def main(argv):
    target = argv[1] if len(sys.argv) > 1 else None

    if not target:
        sys.exit(1)

    # Parse file header
    with open(target, 'rb') as image:
        MAX_READ = os.path.getsize(target)
        currentoffset = 0
        
        # Read file
        headerdata = image.read(NANDHeader.HEADER_SIZE)
        nand = NANDHeader(headerdata)

        print('=== ' + str(hex(currentoffset)) + ' ===\n' + str(nand))

        # Validate image
        if nand.magic != NANDHeader.MAGIC_BYTES:
            print('** Failure: magic bytes check: invalid image')
            exit(1)

        if nand.copyright[0:1]+nand.copyright[11:] != NANDHeader.MS_COPYRIGHT[0:1]+NANDHeader.MS_COPYRIGHT[11:]:
            print('** Warning: failed copyright notice check invalid or custom image')
        
        currentoffset += nand.sboffset

        # Move on to 2BL
        if currentoffset + Bootloader.HEADER_SIZE < MAX_READ:
            image.seek(currentoffset, 0)
            headerdata = image.read(Bootloader.HEADER_SIZE)
            sb = Bootloader(headerdata)

            # Validate SB
            ##print(sb)
            print('=== ' + str(hex(currentoffset)) + ' ===\n' + str(sb))
            
            currentoffset += sb.length

        # 3BL
        if currentoffset + Bootloader.HEADER_SIZE < MAX_READ:
            image.seek(currentoffset, 0)
            headerdata = image.read(Bootloader.HEADER_SIZE)
            sc = Bootloader(headerdata)

            # Validate SC
            ##print(sc)
            print('=== ' + str(hex(currentoffset)) + ' ===\n' + str(sc))
            
            currentoffset += sc.length

        # 4BL
        if currentoffset + Bootloader.HEADER_SIZE < MAX_READ:
            image.seek(currentoffset, 0)
            headerdata = image.read(Bootloader.HEADER_SIZE)
            sd = Bootloader(headerdata)

            # Validate SD
            ##print(sd)
            print('=== ' + str(hex(currentoffset)) + ' ===\n' + str(sd))
            
            currentoffset += sd.length

        # 5BL
        if currentoffset + Bootloader.HEADER_SIZE < MAX_READ:
            image.seek(currentoffset, 0)
            headerdata = image.read(Bootloader.HEADER_SIZE)
            se = Bootloader(headerdata)

            # Validate SE
            ##print(se)
            print('=== ' + str(hex(currentoffset)) + ' ===\n' + str(se))
            
            currentoffset += se.length

        # 6BL
        # This will not exist in shadowboot files, just testing algorithm
        if currentoffset + Bootloader.HEADER_SIZE < MAX_READ:
            image.seek(currentoffset, 0)
            headerdata = image.read(Bootloader.HEADER_SIZE)
            sf = Bootloader(headerdata)

            # Validate SF
            ##print(sf)
            print('=== ' + str(hex(currentoffset)) + ' ===\n' + str(sf))
            
            currentoffset += sf.length


    exit(0)

    ## Deprecated

##    SB_OFFSET = 0x8000 # From shadowboot file
##    CB_OFFSET = 0x8400 # From XDK NAND dump
##
##
##    MAX_READ = os.path.getsize(target) - HEADER_SIZE # Cannot read past the size of the file
##    count = 0
##
##    bootloaders = []
##
##    with open(target, 'rb') as shadowboot:
##
##        current_offset = SB_OFFSET
##        
##        while MAX_READ > current_offset and count < 4:
##            #ipdb.set_trace()
##
##            shadowboot.seek(current_offset, 0) # Seek to bootloader
##            header = shadowboot.read(HEADER_SIZE)
##
##            bootloader = Bootloader(header)
##            bootloaders.append(bootloader)
##            current_offset += bootloader.length
##            count += 1
##
##    for bootloader in bootloaders:
##        print(str(bootloader))
##        print(bootloader.pack())

if __name__ == '__main__':
    main(sys.argv)
