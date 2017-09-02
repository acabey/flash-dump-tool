#!/usr/bin/env python3

import struct, hmac
import Crypto.Cipher.ARC4 as RC4
from hashlib import sha1 as sha

class BootloaderHeader():

    HEADER_SIZE = 0x20

    """
    See: https://free60.acabey.xyz/index.php/Bootloaders

    struct BOOTLOADER_HEADER {
        uint8_t abName[2];
        uint16_t wBuild;
        uint16_t wPairing;
        uint16_t wFlags;
        uint32_t dwEntry;
        uint32_t dwLength;
        uint8_t bSalt[16];
    }

    """
    def __init__(self, header, currentlocation):
        header = struct.unpack('>2s3H2I16s', header)
        self.name = header[0].decode('ASCII')
        self.build = header[1]
        self.pairing = header[2]
        self.flags = header[3]
        self.entry = header[4]
        self.length = header[5]
        self.salt = header[6]

        self.offset = currentlocation

    def __repr__(self):
        return 'Bootloader({})'.format(self.data)

    def __str__(self):
        ret = ''
        ret += 'Name:    '
        ret += str(self.name)
        ret += '\n'
        ret += 'Build:   '
        ret += str(self.build)
        ret += '\n'
        ret += 'Pairing: '
        ret += str(hex(self.pairing))
        ret += '\n'
        ret += 'Flags:   '
        ret += str(hex(self.flags))
        ret += '\n'
        ret += 'Entry:   '
        ret += str(hex(self.entry))
        ret += '\n'
        ret += 'Length:  '
        ret += str(hex(self.length))
        ret += '\n'
        ret += 'Salt:    '
        ret += '\n'
        ret += str(self.salt)
        return ret

    def pack(self):
        return struct.pack('>2s3H2I16s', bytes(self.name, 'ASCII'), self.build, self.pairing, self.flags, self.entry, self.length, self.salt)

class CFHeader(BootloaderHeader):

    HEADER_SIZE = 0x30

    """
    See: https://free60.acabey.xyz/index.php/Bootloaders#CF

    struct BOOTLOADER_HEADER {
        uint8_t abName[2];
        uint16_t wBuild;
        uint16_t wPairing;
        uint16_t wFlags;
        uint32_t dwEntry;
        uint32_t dwLength;
        uint8_t unknown[16];
        uint8_t bSalt[16];
    }

    """
    def __init__(self, header, currentlocation):
        header = struct.unpack('>4H2I16s16s', header)
        self.name = header[0].decode('ASCII')
        self.build = header[1]
        self.pairing = header[2]
        self.flags = header[3]
        self.entry = header[4]
        self.length = header[5]
        # TODO
        self.unknown = header[6]
        self.salt = header[7]

        self.offset = currentlocation

"""
The generic container for bootloaders


Rather than try to keep track of when data is or is not encrypted, instead I opt to allocate memory for both encrypted and decrypted copies
While this comes at the expense of greater memory usage, it makes modifying data very easy
"""
class Bootloader():

    def __init__(self, data_encrypted, header):
        self.data_encrypted = data_encrypted
        self.data_plaintext = self.data_encrypted
        self.header = header
        self.key = None

    def __str__(self):
        return str(self.header)

    """
    Derive the RC4 encryption key from the previous key and the salt stored in the header

    Before decrypting the data, you must set the correct key by providing the previous key

    When reencrypting the data, you may optionally change the salt so long as the header of the encrypted bootloader contains this salt
    """
    def updateKey(self, previouskey, salt=None):
        if salt:
            self.header.salt = salt
        self.key = hmac.new(previouskey, self.header.salt, sha).digest()[0:0x10]

    """
    Encrypt the plaintext data
    """
    def encrypt(self):

        self.data_encrypted = self.header.pack() + RC4.new(self.key).encrypt(self.data_plaintext[0x20:])

    """
    Decrypt the encrypted data
    """
    def decrypt(self):
        self.data_plaintext = bytes(self.header.pack() + RC4.new(self.key).decrypt(self.data_encrypted[0x20:]))

class BL2(Bootloader):

    SECRET_1BL = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    def __init__(self, data_encrypted, header):
        Bootloader.__init__(self, data_encrypted, header)

    def updateKey(self, salt=None):
        if salt:
            self.header.salt = salt
        self.key = hmac.new(BL2.SECRET_1BL, self.header.salt, sha).digest()[0:0x10]

    def zeropair(self):
        # Can only zeropair once decrypted
        if self.data_plaintext:
            self.data_plaintext = self.data_plaintext[0:0x20] + "\0" * 0x20 + self.data_plaintext[0x40:]
        else:
            print('Error: Cannot zeropair encrypted bootloader ' + self.header.name)

class CE(Bootloader):

    def __init__(self, data_encrypted, header):
        Bootloader.__init__(self, data_encrypted, header)

    def patch(self):
        pass

    def compress(self):
        pass

    def decompress(self):
        pass

class CF(Bootloader):

    def __init__(self, data_encrypted, header):
        Bootloader.__init__(self, data_encrypted, header)

    def zeropair(self):
        self.data = self.data[0:0x21c] + "\0" * 4 + self.data[0x220:]
