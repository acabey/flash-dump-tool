#!/usr/bin/env python3

import struct, hmac
import Crypto.Cipher.ARC4 as RC4
from hashlib import sha1 as sha

from nand import NANDSection

class BootloaderHeader(NANDSection):

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
    def __init__(self, header, currentoffset=0):
        if len(header) < BootloaderHeader.HEADER_SIZE:
            raise ValueError('Invalid size for bootloader header')

        if all(b == 0 for b in header):
            raise ValueError('Null data for bootloader header')

        header = struct.unpack('>2s3H2I16s', header)
        self.name = header[0]
        self.build = header[1]
        self.pairing = header[2]
        self.flags = header[3]
        self.entry = header[4]
        self.length = header[5]
        self.salt = header[6]

        self.offset = currentoffset

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
        ret += str(hex(self.entry))
        ret += '\n'
        ret += str(hex(self.length))
        ret += '\n'
        ret += str(self.salt)
        return ret

    def enumerate(self):
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
    def __init__(self, header, currentoffset=0):
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

        self.offset = currentoffset

"""
The generic container for bootloaders


Rather than try to keep track of when data is or is not encrypted, instead I opt to allocate memory for both encrypted and decrypted copies
While this comes at the expense of greater memory usage, it makes modifying data very easy
"""
class Bootloader(NANDSection):

    def __init__(self, data_encrypted, header):
        if all(b == 0 for b in data_encrypted):
            raise ValueError('Null data for bootloader')

        self.data_encrypted = data_encrypted
        self.data_plaintext = None
        self.header = header
        self.key = None

    def __str__(self):
        return str(self.header)

    def enumerate(self):
        return self.header.enumerate()

    """
    Write bootloader contents into <Bootloader Name>.<Build>_dec.bin and <Bootloader Name>.<Build>_dec.bin
        for plaintext and encrypted data, respectively
    """
    def extract(self):
        if self.data_plaintext:
            with open('output/' + self.header.name.decode('ASCII') + '.' + str(self.header.build) + '_dec' + '.bin', 'w+b') as plaintextout:
                plaintextout.write(self.data_plaintext)

        with open('output/' + self.header.name.decode('ASCII') + '.' + str(self.header.build) + '_enc' + '.bin', 'w+b') as encryptedout:
            encryptedout.write(self.data_encrypted)

    """
    Replace data with contents of provided file

    Defaults to encrypted data, but named parameter can override
    """
    def replace(self, replacement, plaintext=False):
        if plaintext:
            raise NotImplementedError('plaintext replacement not implemented')

        with open(replacement, 'rb') as replacementdata:
            replacementheader = type(self.header)(replacementdata.read(self.header.HEADER_SIZE), self.header.offset)
            replacementdata.seek(0, 0)
            self = type(self)(replacementdata.read(replacementheader.length), replacementheader)

    """
    Write current (encrypted) contents to file
    """
    def write(self, output):
        with open(output, 'r+b') as originaldata:
            originaldata.seek(self.offset, 0)
            originaldata.write(self.pack())

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

    """
    Pack data into C style struct
    """
    def pack(self):
        return bytes(self.header.pack() + self.data_encrypted)

class BL2(Bootloader):

    # TODO Change to constants for 1BL key

    def __init__(self, data_encrypted, header):
        try:
            Bootloader.__init__(self, data_encrypted, header)
        except ValueError as e:
            raise
        except Exception as e:
            raise

    def updateKey(self, salt=None):
        if salt:
            self.header.salt = salt
        self.key = hmac.new(BL2.SECRET_1BL, self.header.salt, sha).digest()[0:0x10]

    def zeropair(self):
        # Can only zeropair once decrypted
        assert self.data_plaintext != None, 'Cannot zeropair encrypted bootloader ' + self.header.name
        self.data_plaintext = self.data_plaintext[0:0x20] + "\0" * 0x20 + self.data_plaintext[0x40:]


class CB(BL2):

    MAGIC_BYTES = b'CB'

    def __init__(self, data_encrypted, header):
        try:
            BL2.__init__(self, data_encrypted, header)
        except ValueError as e:
            raise
        except Exception as e:
            raise

        if self.header.name != CB.MAGIC_BYTES:
            raise ValueError('Failed CB magic bytes check')

class CD(Bootloader):

    MAGIC_BYTES = b'CD'

    def __init__(self, data_encrypted, header):
        try:
            Bootloader.__init__(self, data_encrypted, header)
        except ValueError as e:
            raise
        except Exception as e:
            raise

        if self.header.name != CD.MAGIC_BYTES:
            raise ValueError('Failed CD magic bytes check')

class CE(Bootloader):

    MAGIC_BYTES = b'CD'

    def __init__(self, data_encrypted, header):
        try:
            Bootloader.__init__(self, data_encrypted, header)
        except ValueError as e:
            raise
        except Exception as e:
            raise

        if self.header.name != CE.MAGIC_BYTES:
            raise ValueError('Failed CE magic bytes check')

    def patch(self):
        pass

    def compress(self):
        pass

    def decompress(self):
        pass

class CF(Bootloader):

    MAGIC_BYTES = b'CF'

    def __init__(self, data_encrypted, header):
        try:
            Bootloader.__init__(self, data_encrypted, header)
        except ValueError as e:
            raise
        except Exception as e:
            raise

        if self.header.name != CF.MAGIC_BYTES:
            raise ValueError('Failed CF magic bytes check')

    def zeropair(self):
        # Can only zeropair once decrypted
        assert self.data_plaintext != None, 'Cannot zeropair encrypted bootloader ' + self.header.name
        self.data = self.data[0:0x21c] + "\0" * 4 + self.data[0x220:]

class SB(BL2):

    MAGIC_BYTES = b'SB'

    def __init__(self, data_encrypted, header):
        try:
            BL2.__init__(self, data_encrypted, header)
        except ValueError as e:
            raise
        except Exception as e:
            raise

        if self.header.name != SB.MAGIC_BYTES:
            raise ValueError('Failed SB magic bytes check')

class SC(Bootloader):

    MAGIC_BYTES = b'SC'

    def __init__(self, data_encrypted, header):
        try:
            Bootloader.__init__(self, data_encrypted, header)
        except ValueError as e:
            raise
        except Exception as e:
            raise

        if self.header.name != SC.MAGIC_BYTES:
            raise ValueError('Failed SC magic bytes check')

class SD(Bootloader):

    MAGIC_BYTES = b'SD'

    def __init__(self, data_encrypted, header):
        try:
            Bootloader.__init__(self, data_encrypted, header)
        except ValueError as e:
            raise
        except Exception as e:
            raise

        if self.header.name != SD.MAGIC_BYTES:
            raise ValueError('Failed SD magic bytes check')

class SE(Bootloader):

    MAGIC_BYTES = b'SE'

    def __init__(self, data_encrypted, header):
        try:
            Bootloader.__init__(self, data_encrypted, header)
        except ValueError as e:
            raise
        except Exception as e:
            raise

        if self.header.name != SE.MAGIC_BYTES:
            raise ValueError('Failed SE magic bytes check')

    def patch(self):
        pass

    def compress(self):
        pass

    def decompress(self):
        pass
