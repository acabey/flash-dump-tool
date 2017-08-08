#!/bin/python3

import struct, hmac

class Bootloader():

    HEADER_SIZE = 0x20
    SECRET_1BL = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    def __init__(self, header, currentlocation):
        header = struct.unpack('>2s3H2I16s', header)

        self.name = header[0]
        self.build = header[1]
        self.pairing = header[2]
        self.flags = header[3]
        self.entrypoint = header[4]
        self.length = header[5]
        self.salt = header[6]

        self.offset = currentlocation

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

    def __init__(self, block_encrypted, currentlocation):
        self.block_encrypted = block_encrypted
        self.data = self.block_encrypted
        self.header = self.block_encrypted[0:Bootloader.HEADER_SIZE]
        Bootloader.__init__(self, self.header, currentlocation)
        self.key = None

    def updateKey(self, random):
        secret = Bootloader.SECRET_1BL
        self.key = hmac.new(secret, random, sha).digest()[0:0x10]

    def zeropair_CB(self):
        self.data = self.data[0:0x20] + "\0" * 0x20 + self.data[0x40:]
        return self.data

    def decrypt_CB(self):
        secret = Bootloader.SECRET_1BL
        key = hmac.new(secret, self.salt, sha).digest()[0:0x10]
        cb = self.data[0:0x10] + key + RC4.new(key).decrypt(self.data[0x20:])
        self.data = cb
        return cb

    def encrypt_CB(self, random):
        secret = SECRET_1BL
        key = hmac.new(secret, random, sha).digest()[0:0x10]
        cb = self.data[0:0x10] + random + RC4.new(key).encrypt(self.data[0x20:])
        self.data = cb
        self.key = key
        return cb, key

    
class CD(Bootloader):

    def __init__(self, block_encrypted, currentlocation):
        self.block_encrypted = block_encrypted
        self.data = self.block_encrypted
        self.header = self.block_encrypted[0:Bootloader.HEADER_SIZE]
        Bootloader.__init__(self, self.header, currentlocation)
        self.key = None

    def updateKey(self, cb, random):
        secret = cb.key
        assert secret is not None, 'No key given to updateKey'
        self.key = hmac.new(secret, random, sha).digest()[0:0x10]

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
            print('** Warning: decrypting CD > 1920 without CPU key')

        secret = cb.key
        assert secret is not None, 'No key given to decrypt_CD'

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

    def __init__(self, block_encrypted, currentlocation):
        self.block_encrypted = block_encrypted
        self.data = self.block_encrypted
        self.header = self.block_encrypted[0:Bootloader.HEADER_SIZE]
        Bootloader.__init__(self, self.header, currentlocation)
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

    def __init__(self, block_encrypted, currentlocation):
        self.block_encrypted = block_encrypted
        self.data = self.block_encrypted
        self.header = self.block_encrypted[0:Bootloader.HEADER_SIZE]
        Bootloader.__init__(self, self.header, currentlocation)

    def zeropair_CF(self):
        self.data = self.data[0:0x21c] + "\0" * 4 + self.data[0x220:]
        return self.data

    # TODO
    """
    Need to look into these salt(?) values from the CF and CG headers
    Document CF structure as it is apparently very different
    """
    def decrypt_CF(self):
        secret = Bootloader.SECRET_1BL
        key = hmac.new(secret, self.data[0x20:0x30], sha).digest()[0:0x10]
        cf = self.data[0:0x20] + key + RC4.new(key).decrypt(self.data[0x30:])
        self.data = cf
        return cf
   
    def encrypt_CF(CF, random):
        secret = secret_1BL
        key = hmac.new(secret, random, sha).digest()[0:0x10]
        self.key = self.data[0x330:0x330+0x10]
        cf = self.data[0:0x20] + random + RC4.new(key).encrypt(self.data[0x30:])
        self.data = cf
        return cf, self.key
    
    
class CG(Bootloader):

    def __init__(self, block_encrypted, currentlocation):
        self.block_encrypted = block_encrypted
        self.data = self.block_encrypted
        self.header = self.block_encrypted[0:Bootloader.HEADER_SIZE]
        Bootloader.__init(self, self.header, currentlocation)

    def decrypt_CG(self, cf):
        secret = cf.key
        key = hmac.new(secret, CG[0x10:0x20], sha).digest()[0:0x10]
        cg = self.data[:0x10] + key + RC4.new(key).decrypt(self.data[0x20:])
        self.data = cg
        return cg
    
    def encrypt_CG(self, cf, random):
        secret = cf.key
        key = hmac.new(secret, random, sha).digest()[0:0x10]
        cg = self.data[:0x10] + random + RC4.new(key).encrypt(self.data[0x20:])
        self.data = cg
        return cg

