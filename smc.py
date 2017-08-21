#!/usr/bin/env python3

class SMC():

    SMC_KEY = [0x42, 0x75, 0x4e, 0x79]

    def __init__(self, data, currentlocation):
        self.name = 'SMC'
        self.data_encrypted = data
        self.data_plaintext = data
        self.decrypt()

        self.offset = currentlocation

    def __str__(self):
        ret = ''
        ret += 'Name:    '
        ret += self.name
        ret += '\n'
        ret += 'Offset:  '
        ret += str(hex(self.offset))
        return ret


    """
    Modify data_plaintext inline to store decrypted data
    """
    def decrypt(self):

        key = SMC.SMC_KEY

        i = 0
        length = len(self.data_plaintext)
        index = 0;

        self.data_plaintext = bytearray(self.data_plaintext)

        while length > 0:
            length -= 1
            mod = self.data_plaintext[index] * 0xFB
            self.data_plaintext[index] ^= key[i] & 0xFF
            index += 1
            i += 1
            i &= 3
            key[i] += mod
            key[(i + 1) & 3] += mod >> 8

        self.data_plaintext = bytes(self.data_plaintext)

    """
    Modify data_encrypted inline to store decrypted data
    """
    # TODO Encryption and CRC calculations
    def encrypt(self):

        key = SMC.SMC_KEY

        i = 0
        length = len(self.data_plaintext)
        index = 0;

        self.data_plaintext = bytearray(self.data_plaintext)

        res = ""
        key = SMC.SMC_KEY
        for i in range(len(self.data_plaintext)):
            j = ord(self.data_plaintext[i]) ^ (key[i&3] & 0xFF)
            mod = j * 0xFB
            res += chr(j)
            key[(i+1)&3] += mod
            key[(i+2)&3] += mod >> 8
        self.data_encrypted = res
