#!/bin/python3

class SMC():

    SMC_KEY = [0x42, 0x75, 0x4e, 0x79]
    
    def __init__(self, data, currentlocation):
        self.block_encrypted = data
        self.data = None
        
        self.offset = currentlocation

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

