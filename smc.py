#!/usr/bin/env python3

class SMC():

    SMC_KEY = [0x42, 0x75, 0x4e, 0x79]

    def __init__(self, data, currentlocation):
        self.data_encrypted = data
        self.data_plaintext = data
        self.decrypt_SMC()

        self.offset = currentlocation

    def __str__(self):
        ret = ''
        ret += 'Name:    '
        ret += 'SMC'
        ret += '\n'
        ret += 'Offset:  '
        ret += str(hex(self.offset))
        return ret


    """
    Modify data_plaintext inline to store decrypted data
    """
    def decrypt_SMC(self):
        res = ""
        for i in range(len(self.data_plaintext)):
            #j = ord(self.data_plaintext[i])
            j = self.data_plaintext[i]
            mod = j * 0xFB
            res += chr(j ^ (SMC.SMC_KEY[i&3] & 0xFF))
            SMC.SMC_KEY[(i+1)&3] += mod
            SMC.SMC_KEY[(i+2)&3] += mod >> 8
        self.data_plaintext = res

    """
    Modify data_encrypted inline to store decrypted data
    """
    def encrypt_SMC(self):
        res = ""
        for i in range(len(self.data_plaintext)):
            #j = ord(self.data_plaintext[i]) ^ (SMC.SMC_KEY[i&3] & 0xFF)
            j = self.data_plaintext[i] ^ (SMC.SMC_KEY[i&3] & 0xFF)
            mod = j * 0xFB
            res += chr(j)
            SMC.SMC_KEY[(i+1)&3] += mod
            SMC.SMC_KEY[(i+2)&3] += mod >> 8
        self.data_encrypted = res
