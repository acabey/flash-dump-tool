#/bin/python3

# A lot of this code is taken from https://github.com/Free60Project/tools/blob/master/imgbuild/build.py
"""

I need to decide on the scheme for modifying data. Right now I do both inline
modifications (encrypt, decrypt, etc.) as and return the modified data

"""

import sys, struct, os
import hmac, sha, struct, sys
import Crypto.Cipher.ARC4 as RC4

#import ipdb

class NANDHeader():

    HEADER_SIZE = 0x80
    MAGIC_BYTES = b'\xFF\x4F'
    MS_COPYRIGHT = b'\xa9 2004-2011 Microsoft Corporation. All rights reserved.\x00'

    def __init__(self, header):
#        self.magic, self.build, self.unknown0x4, self.unknown0x6, self.sboffset, self.cf1offset,
#        self.copyright, self.unknown0x60, self.unknown0x64, self.unknown0x68, self.kvoffset,
#        self.metadatastyle, self.unknown0x72, self.smclength, self.smcoffset = struct.unpack('>2s3H2I56s24s4I2H3I', header)
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

class SMC():

    SMC_KEY = [0x42, 0x75, 0x4e, 0x79]
    
    def __init__(self, data):
        self.block_encrypted = data
        self.data = None

    def decrypt_SMC(self):
        res = ""
        for i in range(len(self.data)):
            j = ord(self.data[i])
            mod = j * 0xFB
            res += chr(j ^ (SMC.SMC_KEY[i&3] & 0xFF))
            SMC.SMC_KEY[(i+1)&3] += mod
            SMC.SMC_KEY[(i+2)&3] += mod >> 8
        self.data = res
        return res
    
    def encrypt_SMC(self):
        res = ""
        for i in range(len(self.data)):
            j = ord(self.data[i]) ^ (SMC.SMC_KEY[i&3] & 0xFF)
            mod = j * 0xFB
            res += chr(j)
            SMC.SMC_KEY[(i+1)&3] += mod
            SMC.SMC_KEY[(i+2)&3] += mod >> 8
        self.data = res
        return res


class Bootloader():

    HEADER_SIZE = 0x20
    SECRET_1BL = '\xDD\x88\xAD\x0C\x9E\xD6\x69\xE7\xB5\x67\x94\xFB\x68\x56\x3E\xFA'

    def __init__(self, header):
        header = struct.unpack('>2s3H2I16s', header)

        self.name = header[0]
        self.build = header[1]
        self.pairing = header[2]
        self.flags = header[3]
        self.entrypoint = header[4]
        self.length = header[5]
        self.salt = header[6]

    def __getitem__(self, key):
        return self.data[key]

    def __setitem__(self, key, value):
        self.data[key] = value

    def __repr__(self):
        return 'Bootloader({})'.format(self.data)

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


class CB(Bootloader):

    def __init__(self, block_encrypted):
        self.block_encrypted = block_encrypted
        self.data = self.block_encrypted
        self.header = self.block_encrypted[0:Bootloader.HEADER_SIZE]
        Bootloader.__init__(self, self.header)
        self.key = None

    def zeropair_CB(self):
        self.data = self.data[0:0x20] + "\0" * 0x20 + self.data[0x40:]
        return self.data

    def decrypt_CB(self):
        secret = SECRET_1BL
        key = hmac.new(secret, self.salt, sha).digest()[0:0x10]
        cb = self.data[0:0x10] + key + RC4.new(key).decrypt(self.data[0x20:])
        return cb

    def encrypt_CB(self, random):
        secret = SECRET_1BL
        key = hmac.new(secret, random, sha).digest()[0:0x10]
        cb = self.data[0:0x10] + random + RC4.new(key).encrypt(self.data[0x20:])
        self.key = key
        return cb, key

    
class CD(Bootloader):

    def __init__(self, block_encrypted):
        self.block_encrypted = block_encrypted
        self.data = self.block_encrypted
        self.header = self.block_encrypted[0:Bootloader.HEADER_SIZE]
        Bootloader.__init__(self, self.header)
        self.key = None

    def __getitem__(self, key):
        return self.data[key]

    def __setitem__(self, key, value):
        self.data[key] = value

    def __repr__(self):
        return 'MyArray({})'.format(self.data)

    def decrypt_CD(self, cb, cpukey = None):
    # enable this code if you want to extract CD from a flash image and you know the cup key.
    # disable this when this is a zero-paired image.
    #   assert cpukey or build(CD) < 1920
        if self.build > 1920 and not cpukey:
            print('Warning: decrypting CD > 1920 without CPU key')
        #secret = CB[0x10:0x20]
        secret = cb.key
        assert secret is not None, 'No key given to decrypt_CD'
        #key = hmac.new(secret, self.salt, sha).digest()[0:0x10]
        key = hmac.new(secret, self.salt, sha).digest()[0:0x10]
        if cpukey:
                key = hmac.new(cpukey, key, sha).digest()[0:0x10]
        cd = self.data[0:0x10] + key + RC4.new(key).decrypt(self.data[0x20:])
        self.data = cd
        return cd

    def encrypt_CD(self, cb, random):
        secret = cb.key
        assert secret is not None, 'No key given to encrypt_CD'
        key = hmac.new(secret, random, sha).digest()[0:0x10]
        cd = self.data[0:0x10] + random + RC4.new(key).encrypt(self.data[0x20:])
        self.data = cd
        self.key = key
        return cd, key
    

class CE(Bootloader):

    def __init__(self, block_encrypted):
        self.block_encrypted = block_encrypted
        self.data = self.block_encrypted
        self.header = self.block_encrypted[0:Bootloader.HEADER_SIZE]
        Bootloader.__init(self, self.header)
        self.key = None

    def decrypt_CE(self, cd):
        secret = cd.key
        assert secret is not None, 'No key given to decrypt_CE'
        key = hmac.new(secret, self.salt, sha).digest()[0:0x10]
        ce = self.data[0:0x10] + key + RC4.new(key).decrypt(self.data[0x20:])
        self.data = ce
        return ce
    
    def encrypt_CE(self, cd, random):
        secret = cd.key
        assert secret is not None, 'No key given to encrypt_CE'
        key = hmac.new(secret, random, sha).digest()[0:0x10]
        ce = self.data[0:0x10] + random + RC4.new(key).encrypt(self.data[0x20:])
        self.data = ce
        self.key = key # This is never used, storing just to be complete
        return ce


class CF(Bootloader):

    def __init__(self, block_encrypted):
        self.block_encrypted = block_encrypted
        self.data = self.block_encrypted
        self.header = self.block_encrypted[0:Bootloader.HEADER_SIZE]
        Bootloader.__init(self, self.header)

    def zeropair_CF(self):
        self.data = self.data[0:0x21c] + "\0" * 4 + self.data[0x220:]
        return self.data

    # TODO
    """
    Need to look into these salt(?) values from the CF and CG headers
    Document CF structure as it is apparently very different
    """
    def decrypt_CF(CF):
        secret = secret_1BL
        key = hmac.new(secret, CF[0x20:0x30], sha).digest()[0:0x10]
        CF = CF[0:0x20] + key + RC4.new(key).decrypt(CF[0x30:])
        return CF
    
    def decrypt_CG(CG, CF):
        secret = CF[0x330:0x330+0x10]
        key = hmac.new(secret, CG[0x10:0x20], sha).digest()[0:0x10]
        CG = CG[:0x10] + key + RC4.new(key).decrypt(CG[0x20:])
        return CG
    
    def encrypt_CF(CF, random):
        secret = secret_1BL
        key = hmac.new(secret, random, sha).digest()[0:0x10]
        CF_key = CF[0x330:0x330+0x10]
        CF = CF[0:0x20] + random + RC4.new(key).encrypt(CF[0x30:])
        return CF, CF_key
    
    def encrypt_CG(CG, CF_key, random):
        secret = CF_key
        key = hmac.new(secret, random, sha).digest()[0:0x10]
        CG = CG[:0x10] + random + RC4.new(key).encrypt(CG[0x20:])
        return CG
    

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
            print('Failed magic bytes check: invalid image')
            exit(1)

        if nand.copyright[0:1]+nand.copyright[11:] != NANDHeader.MS_COPYRIGHT[0:1]+NANDHeader.MS_COPYRIGHT[11:]:
            print('Failed copyright notice check: invalid image')
            exit(1)
        
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
