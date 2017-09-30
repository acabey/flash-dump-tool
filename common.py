#!/usr/bin/env python3

DEBUG = True

class Constants():
    SHADOWBOOT_SIZE = 851968 # Seems to be the max size (bytes) for a shadowboot ROM based on official samples. Don't where limit is imposed
    HV_SIZE = 0x40000
    SECRET_ZERO = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    SECRET_1BL  = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    CPUKEY = None

    # BL4 Key stuff
    BL4_SALT = b'XBOX_ROM_4'

    endianness = 'little'
    signed = False
    modulusFilePath = './data/keys/LE/BL4_signKey_Modulus.bin'
    publicFilePath = './data/keys/LE/BL4_signKey_DP.bin'
    privateFilePath = './data/keys/LE/BL4_signKey_DQ.bin'
    pFilePath = './data/keys/LE/BL4_signKey_P.bin'
    qFilePath = './data/keys/LE/BL4_signKey_Q.bin'
    with open(modulusFilePath, 'rb') as modulusFile:
        with open(publicFilePath, 'rb') as publicFile:
            with open(privateFilePath, 'rb') as privateFile:
                with open(pFilePath, 'rb') as pFile:
                    with open(qFilePath, 'rb') as qFile:
                        BL4_MOD  = int.from_bytes(modulusFile.read(), byteorder=endianness, signed=signed)
                        BL4_PUBEXP  = int.from_bytes(publicFile.read(), byteorder=endianness, signed=signed)
                        BL4_PRIVEXP = int.from_bytes(privateFile.read(), byteorder=endianness, signed=signed)
                        BL4_P = int.from_bytes(pFile.read(), byteorder=endianness, signed=signed)
                        BL4_Q = int.from_bytes(qFile.read(), byteorder=endianness, signed=signed)

    unsignedFilePath = './data/keys/Expected/BL4_unsigned.bin'


def dbgprint(string):
    global DEBUG
    if DEBUG:
        print(string)

def warnprint(warning):
    print('** WARN ** : ' + warning)

def failprint(failure):
    print('** FAIL ** : ' + failure)
