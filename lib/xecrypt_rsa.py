#!/usr/bin/env python3

import struct
from hashlib import sha1

import Crypto.Cipher.ARC4 as RC4
from Crypto.PublicKey import RSA

from lib.xecrypt import XeCryptBnQw_SwapLeBe


class XeCrypt_RSA(object):
    """
    struct XECRYPT_RSA { // [sizeof = 16]
        unsigned long cqw; // data +0x00 [sizeof=4]
        unsigned long dwPubExp; // data +0x04 [sizeof=4]
        unsigned __int64 qwReserved; // data +0x08 [sizeof=8]
    };
    """

    def __init__(self, xecrypt_rsa_be_data: bytes):
        self.data = xecrypt_rsa_be_data[0:0x10]
        self.cqw = int.from_bytes(xecrypt_rsa_be_data[0:4], byteorder='big')
        self.dwPubExp = int.from_bytes(xecrypt_rsa_be_data[0x04:0x08], byteorder='big')
        self.qwReserved = int.from_bytes(XeCryptBnQw_SwapLeBe(xecrypt_rsa_be_data[0x08:0x10], 0x1), byteorder='little')


class XeCrypt_RsaPub_Abs(XeCrypt_RSA):

    def __init__(self, data: bytes):
        super(XeCrypt_RsaPub_Abs, self).__init__(data)
        self.data = None
        self.aqwM = None
        self.rsa = None

    def build_rsa(self):
        n = self.aqwM
        e = self.dwPubExp

        self.rsa = RSA.construct((n, e))
        return self.rsa


class XeCrypt_RsaPrv_Abs(XeCrypt_RsaPub_Abs):

    def __init__(self, data: bytes):
        super(XeCrypt_RsaPrv_Abs, self).__init__(data)
        self.data = None
        self.aqwM = None
        self.aqwP = None
        self.aqwQ = None
        self.aqwDP = None
        self.aqwDQ = None
        self.aqwCR = None
        self.rsa = None

    def build_rsa(self):
        n = self.aqwM
        e = self.dwPubExp
        d = modinv(e, (self.aqwP - 1) * (self.aqwQ - 1))

        self.rsa = RSA.construct((n, e, d))

        return self.rsa


class XeCrypt_RSAPrv_1024(XeCrypt_RsaPrv_Abs):
    """
    struct XECRYPT_RSAPRV_1024 { // [sizeof = 464]
        XECRYPT_RSA Rsa; // data +0x00 [sizeof=16]
        unsigned __int64 aqwM[16]; // data +0x10 [sizeof=128]
        unsigned __int64 aqwP[8]; // data +0x90 [sizeof=64]
        unsigned __int64 aqwQ[8]; // data +0xd0 [sizeof=64]
        unsigned __int64 aqwDP[8]; // data +0x110 [sizeof=64]
        unsigned __int64 aqwDQ[8]; // data +0x150 [sizeof=64]
        unsigned __int64 aqwCR[8]; // data +0x190 [sizeof=64]
    };
    """
    STRUCT_SIZE = 0x1D0

    def __init__(self, data: bytes):
        super(XeCrypt_RSAPrv_1024, self).__init__(data[0:0x10])
        self.data = data[0:self.STRUCT_SIZE]
        self.aqwM = int.from_bytes(XeCryptBnQw_SwapLeBe(data[0x10:0x10 + 0x80], 0x10), byteorder='little')
        self.aqwP = int.from_bytes(XeCryptBnQw_SwapLeBe(data[0x90:0x90 + 0x40], 0x8), byteorder='little')
        self.aqwQ = int.from_bytes(XeCryptBnQw_SwapLeBe(data[0xD0:0xD0 + 0x40], 0x8), byteorder='little')
        self.aqwDP = int.from_bytes(XeCryptBnQw_SwapLeBe(data[0x110:0x110 + 0x40], 0x8), byteorder='little')
        self.aqwDQ = int.from_bytes(XeCryptBnQw_SwapLeBe(data[0x150:0x150 + 0x40], 0x8), byteorder='little')
        self.aqwCR = int.from_bytes(XeCryptBnQw_SwapLeBe(data[0x190:0x190 + 0x40], 0x8), byteorder='little')


class XeCrypt_RSAPrv_1536(XeCrypt_RsaPrv_Abs):
    """
    struct XECRYPT_RSAPRV_1536 { // [sizeof = 688]
        XECRYPT_RSA Rsa; // data +0x00 [sizeof=16]
        unsigned __int64 aqwM[24]; // data +0x10 [sizeof=192]
        unsigned __int64 aqwP[12]; // data +0xd0 [sizeof=96]
        unsigned __int64 aqwQ[12]; // data +0x130 [sizeof=96]
        unsigned __int64 aqwDP[12]; // data +0x190 [sizeof=96]
        unsigned __int64 aqwDQ[12]; // data +0x1f0 [sizeof=96]
        unsigned __int64 aqwCR[12]; // data +0x250 [sizeof=96]
    };

    """
    STRUCT_SIZE = 0x2B0

    def __init__(self, data: bytes):
        super(XeCrypt_RSAPrv_1536, self).__init__(data[0:0x10])
        self.data = data[0:self.STRUCT_SIZE]
        self.aqwM = int.from_bytes(XeCryptBnQw_SwapLeBe(data[0x10:0x10 + 0xC0], 0x18), byteorder='little')
        self.aqwP = int.from_bytes(XeCryptBnQw_SwapLeBe(data[0xD0:0xD0 + 0x60], 0xC), byteorder='little')
        self.aqwQ = int.from_bytes(XeCryptBnQw_SwapLeBe(data[0x130:0x130 + 0x60], 0xC), byteorder='little')
        self.aqwDP = int.from_bytes(XeCryptBnQw_SwapLeBe(data[0x190:0x190 + 0x60], 0xC), byteorder='little')
        self.aqwDQ = int.from_bytes(XeCryptBnQw_SwapLeBe(data[0x1F0:0x1F0 + 0x60], 0xC), byteorder='little')
        self.aqwCR = int.from_bytes(XeCryptBnQw_SwapLeBe(data[0x250:0x250 + 0x60], 0xC), byteorder='little')


class XeCrypt_RSAPrv_2048(XeCrypt_RsaPrv_Abs):
    """
    struct XECRYPT_RSAPRV_2048 { // [sizeof = 912]
        XECRYPT_RSA Rsa; // data +0x00 [sizeof=16]
        unsigned __int128 aqwP[16]; // data +0x110 [sizeof=128]
        unsigned __int128 aqwQ[16]; // data +0x190 [sizeof=128]
        unsigned __int128 aqwDP[16]; // data +0x210 [sizeof=128]
        unsigned __int128 aqwDQ[16]; // data +0x290 [sizeof=128]
        unsigned __int128 aqwCR[16]; // data +0x310 [sizeof=128]
    };
    """
    STRUCT_SIZE = 0x390

    def __init__(self, data: bytes):
        super(XeCrypt_RSAPrv_2048, self).__init__(data[0:0x10])
        self.data = data[0:self.STRUCT_SIZE]
        self.aqwM = int.from_bytes(XeCryptBnQw_SwapLeBe(data[0x10:0x10 + 0x100], 0x20), byteorder='little')
        self.aqwP = int.from_bytes(XeCryptBnQw_SwapLeBe(data[0x110:0x110 + 0x80], 0x10), byteorder='little')
        self.aqwQ = int.from_bytes(XeCryptBnQw_SwapLeBe(data[0x190:0x190 + 0x80], 0x10), byteorder='little')
        self.aqwDP = int.from_bytes(XeCryptBnQw_SwapLeBe(data[0x210:0x210 + 0x80], 0x10), byteorder='little')
        self.aqwDQ = int.from_bytes(XeCryptBnQw_SwapLeBe(data[0x290:0x290 + 0x80], 0x10), byteorder='little')
        self.aqwCR = int.from_bytes(XeCryptBnQw_SwapLeBe(data[0x310:0x310 + 0x80], 0x10), byteorder='little')


class XeCrypt_RSAPrv_4096(XeCrypt_RsaPrv_Abs):
    """
    struct XECRYPT_RSAPRV_4096 { // [sizeof = 1808]
        XECRYPT_RSA Rsa; // data +0x00 [sizeof=16]
        unsigned __int64 aqwM[64]; // data +0x10 [sizeof=512]
        unsigned __int64 aqwP[32]; // data +0x210 [sizeof=256]
        unsigned __int64 aqwQ[32]; // data +0x310 [sizeof=256]
        unsigned __int64 aqwDP[32]; // data +0x410 [sizeof=256]
        unsigned __int64 aqwDQ[32]; // data +0x510 [sizeof=256]
        unsigned __int64 aqwCR[32]; // data +0x610 [sizeof=256]
    };

    """
    STRUCT_SIZE = 0x710

    def __init__(self, data: bytes):
        super(XeCrypt_RSAPrv_4096, self).__init__(data[0:0x10])
        self.data = data[0:self.STRUCT_SIZE]
        self.aqwM = int.from_bytes(XeCryptBnQw_SwapLeBe(self.data[0x10:0x10 + 0x200], 0x40), byteorder='little')
        self.aqwP = int.from_bytes(XeCryptBnQw_SwapLeBe(self.data[0x210:0x210 + 0x100], 0x20), byteorder='little')
        self.aqwQ = int.from_bytes(XeCryptBnQw_SwapLeBe(self.data[0x310:0x310 + 0x100], 0x20), byteorder='little')
        self.aqwDP = int.from_bytes(XeCryptBnQw_SwapLeBe(self.data[0x410:0x410 + 0x100], 0x20), byteorder='little')
        self.aqwDQ = int.from_bytes(XeCryptBnQw_SwapLeBe(self.data[0x510:0x510 + 0x100], 0x20), byteorder='little')
        self.aqwCR = int.from_bytes(XeCryptBnQw_SwapLeBe(self.data[0x610:0x610 + 0x100], 0x20), byteorder='little')


class XeCrypt_RSAPub_1024(XeCrypt_RsaPub_Abs):
    """
    struct XECRYPT_RSAPUB_1024 { // [sizeof = 144]
        XECRYPT_RSA Rsa; // data +0x00 [sizeof=16]
        unsigned __int64 aqwM[16]; // data +0x10 [sizeof=128]
    };
    """
    STRUCT_SIZE = 0x90

    def __init__(self, data: bytes):
        super(XeCrypt_RSAPub_1024, self).__init__(data[0:0x10])
        self.data = data[0:self.STRUCT_SIZE]
        self.aqwM = int.from_bytes(XeCryptBnQw_SwapLeBe(data[0x10:0x10 + 0x80], 0x10), byteorder='little')


class XeCrypt_RSAPub_1536(XeCrypt_RsaPub_Abs):
    """
    struct XECRYPT_RSAPUB_1536 { // [sizeof = 208]
        XECRYPT_RSA Rsa; // data +0x00 [sizeof=16]
        unsigned __int64 aqwM[24]; // data +0x10 [sizeof=192]
    };
    """
    STRUCT_SIZE = 0xD0

    def __init__(self, data: bytes):
        super(XeCrypt_RSAPub_1536, self).__init__(data[0:0x10])
        self.data = data[0:self.STRUCT_SIZE]
        self.aqwM = int.from_bytes(XeCryptBnQw_SwapLeBe(data[0x10:0x10 + 0xC0], 0x18), byteorder='little')


class XeCrypt_RSAPub_2048(XeCrypt_RsaPub_Abs):
    """
    struct XECRYPT_RSAPUB_2048 { // [sizeof = 272]
        XECRYPT_RSA Rsa; // data +0x00 [sizeof=16]
        unsigned __int64 aqwM[32]; // data +0x10 [sizeof=256]
    };
    """
    STRUCT_SIZE = 0x110

    def __init__(self, data: bytes):
        super(XeCrypt_RSAPub_2048, self).__init__(data[0:0x10])
        self.data = data[0:self.STRUCT_SIZE]
        self.aqwM = int.from_bytes(XeCryptBnQw_SwapLeBe(data[0x10:0x10 + 0x100], 0x20), byteorder='little')


class XeCrypt_RSAPub_4096(XeCrypt_RsaPub_Abs):
    """
    struct XECRYPT_RSAPUB_4096 { // [sizeof = 528]
        XECRYPT_RSA Rsa; // data +0x00 [sizeof=16]
        unsigned __int64 aqwM[64]; // data +0x10 [sizeof=512]
    };
    """
    STRUCT_SIZE = 0x210

    def __init__(self, data: bytes):
        super(XeCrypt_RSAPub_4096, self).__init__(data[0:0x10])
        self.data = data[0:self.STRUCT_SIZE]
        self.aqwM = int.from_bytes(XeCryptBnQw_SwapLeBe(data[0x10:0x10 + 0x200], 0x20), byteorder='little')


def XeCryptBnQwBeSigCreate(hash: bytes, salt: bytes, key: XeCrypt_RsaPrv_Abs) -> bytes:
    """
    #bool XeCryptBnQwBeSigCreate(u64* output, const u8* hash, const u8* salt, const XeRsaKey* key)
    # export 356
    # returns:	TRUE if successful
    #			FALSE if error
    """
    if not (key.cqw == 0x00000020):
        raise ValueError('Invalid cqw')

    if not (key.dwPubExp == 0x00010001 or key.dwPubExp == 0x00000011):
        raise ValueError('Invalid public exponent')

    output = XeCryptBnQwBeSigFormat(hash, salt)
    output_bn = int.from_bytes(XeCryptBnQw_SwapLeBe(output[0:0x20], 0x4), byteorder='little')

    # I don't understand this check? There is no way output could have gotten the modulus
    if XeCryptBnQwNeCompare(output_bn, key.aqwM):
        raise ValueError('Invalid sigformat output')

    buffer320 = bytearray(0x20)
    buffer320[0:0x20] = [0] * 0x20  # XeCryptBnQw_Zero

    r11 = 0x00000000FFFFFFFF & key.dwPubExp
    r11 -= 1
    r11 = r11 << 11 & 0xFFFFFFFF00000000  # slwi r11, r11, 11
    buffer320[0:8] = r11.to_bytes(8, byteorder='big', signed=False)

    buffer220 = bytearray(0x20)
    buffer220[0:0x20] = [0] * 0x20  # XeCryptBnQw_Zero

    r11 = 2
    buffer220[0:8] = r11.to_bytes(8, byteorder='big', signed=False)
    XeCryptBnQwNeModExp


def XeCryptBnQwNeCompare(num1: int, num2: int) -> bool:
    """
    int XeCryptBnQwNeCompare(BN* num1, BN* num2, size_t size);
        Compare two big numbers of given size
        Return -1 if different, return 0 if equal value


    Python implementation stores bignumbers as int
    """
    return num1 == num2


def XeCryptBnQwBeSigFormat(hash: bytes, salt: bytes, size=0x100) -> bytes:
    """
    # export 357
    void XeCryptBnQwBeSigFormat(u8* output, const u8* hash, const u8* salt);
    """
    output = bytearray(size)
    output[0:0xE0] = [0] * 0xE0  # Zero out first 0xE0 bytes

    output[0xE0] = 0x1

    output[0xE1:0xE1 + 0xA] = salt  # Copy salt into output starting at 0xE1

    output[0xFF] = 0xBC

    sha_ctx = sha1()
    sha_ctx.update(output[0:8])
    sha_ctx.update(hash[0:0x14])
    sha_ctx.update(salt[0:0xA])

    hash = sha_ctx.digest()  # Re-assign, does not change value in place
    output[0xEB: 0xEB + 0x14] = hash

    rc4_ctx = RC4.new(hash)
    encrypted = rc4_ctx.encrypt(output[0:0xEB])
    output[0:0xEB] = encrypted

    temp = output[0] & 0xD  # lbz r9, 0(output) | clrlwi r9, r9, 25
    index11 = 0xF8
    index10 = 0

    # Skipped what I think is an alignment check? Maybe an endian check?
    # addi r11, output, 0xF8 | cmplw cr6, output, r11 | bge cr6, end
    # if &output & 0x00000000FFFFFFFF > (&output + index11) & 0x00000000FFFFFFFF: return

    output[0] = temp

    while index10 < index11:
        r9 = int.frombytes(output[index11:index11 + 8], byteorder='big',
                           signed=False)  # ld r9, 0(r11) # r9 = (DWORD) r11[0]
        r8 = int.frombytes(output[index10:index10 + 8], byteorder='big',
                           signed=False)  # ld r8, 0(r10) # r8 = (DWORD) r10[0]

        output[index10:index10 + 8] = r9.to_bytes(8, byteorder='big',
                                                  signed=False)  # std r9, 0(r10) # r10[0] = (DWORD) r9
        index10 += 8  # addi r10, r10, 8 # r10 += 0x8

        output[index11:index11 + 8] = r8.to_bytes(8, byteorder='big',
                                                  signed=False)  # std r8, 0(r11) # r11[0] = (DWORD) r8
        index11 -= 8  # addi r11, r11, -8  # r11 -= 0x8
        # cmplw cr6, r10, r11
        # blt cr6, swapping_loop

    return bytes(output)


def XeCryptBnQwBeSigVerify(sig: bytes, hash: bytes, salt: bytes, key: XeCrypt_RsaPub_Abs) -> bool:
    """
    # export 358
    # returns:	TRUE if successful
    #			FALSE if error
    bool XeCryptBnQwBeSigVerify(u64* sig, const u8* hash, const u8* salt, const XeRsaKey* key);
    """
    pass


def XeCryptBnQwNeModExp(input: int, exponent: int, modulus: int) -> int:
    """
    # export 359
    #
    # args:	big number output for result of mod-exp
    #			big number input to get mod-exp of
    #			big number of exponent
    #			big number of modulus
    #			size of big number buffers (in u64 units)
    # returns:	TRUE if successful
    #			FALSE if error
    bool XeCryptBnQwNeModExp(u64* bnOutput, const u64* bnInput, const u64* bnExponent, const u64* bnModulus, s32 size);
    """


def XeCryptBnQwNeModExpRoot(input: int, p: int, q: int, dp: int, dq: int, cr: int) -> int:
    """
    # export 360
    # (basically encrypts data with parts of the rsa private key)
    #
    # args:	output data (encrypted data)
    #			input data  (unencrypted data)
    #			private key - P
    #			private key - Q
    #			private key - DP
    #			private key - DQ
    #			private key - CR (chinese remainder)
    #			size
    # returns:	TRUE if successful
    #			FALSE if error
    bool XeCryptBnQwNeModExpRoot(u64* bnOutput, const u64* bnInput, const u64* P, const u64* Q, const u64* DP, const u64* DQ, const u64* CR, s32 size);
    """
    pass


def XeCryptBnQwNeModInv(num: int) -> int:
    """
    # export 361
    # ??
    #
    # args:	number to calculate mod inverse of ?
    # returns:	calculated value
    u64 XeCryptBnQwNeModInv(u64 num);
    """
    pass


def XeCryptBnQwNeModMul(num1: int, num2: int, mod_inv: int, modulus: int) -> int:
    """
    # export 362
    void XeCryptBnQwNeModMul(const u64* bnNum1, const u64* bnNum2, u64* bnOutput, u64 mod_inv, const u64* bnModulus, s32 bigNumSize);
    """
    pass


def XeCryptBnQwNeRsaPrvCrypt(input: bytes, key: XeCrypt_RsaPrv_Abs) -> bytes:
    """
    # export 364
    # ??
    #
    # returns:	TRUE if successful
    #			FALSE if error
    bool XeCryptBnQwNeRsaPrvCrypt(const u64* input, u64* output, const XeRsaKey* key);

    Encrypt a given Bn input in u64 blocks
    """
    # Unpack the key into it's components
    n = key.aqwM
    e = key.dwPubExp
    d = modinv(e, (key.aqwP - 1) * (key.aqwQ - 1))

    # Encrypt each qw in the plaintext a^b mod m
    cipher_text = bytearray(len(input))
    for i in range(int(len(input) / 8)):
        offset = i * 8

        u64 = struct.unpack(">Q", input[offset:offset + 8])[0]
        cipher_block = int(u64 ** d) % n
        cipher_text[offset:offset + 8] = cipher_block

    return bytes(cipher_text)


def XeCryptBnQwNeRsaPubCrypt(input: bytes, key: XeCrypt_RsaPub_Abs) -> bytes:
    """
    # export 365
    # crypt data with public key
    #
    # args:	input data to crypt
    #			output for crypted data
    #			public key to crypt with
    # returns:	TRUE if successful
    #			FALSE if error
    bool XeCryptBnQwNeRsaPubCrypt(const u64* input, u64* output, const XeRsaKey* key);
    """
    pass


def egcd(a: int, b: int) -> int:
    """
    Calculate the Phi or something

    :param a:
    :param b:
    :return:

    Took from SO https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
    """
    lastremainder, remainder = abs(a), abs(b)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient * x, x
        y, lasty = lasty - quotient * y, y
    return lastremainder, lastx * (-1 if a < 0 else 1), lasty * (-1 if b < 0 else 1)


def modinv(a: int, m: int) -> int:
    """
    Multiplicative modular inverse of a
    :param a:
    :param m:
    :return:
    :raises ValueError if modinv does not exist
    """
    g, x, y = egcd(a, m)
    if g != 1:
        raise ValueError('modinv for {} does not exist'.format(a))
    return x % m
