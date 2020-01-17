#!/usr/bin/env python3

from enum import Enum
from hashlib import sha1
from typing import List

from lib.bitwise_arithmetic import *
from lib.endian import *

# Sizes of blocks and hashes
XE_CRYPT_MD5_HASH_SIZE = 16
XE_CRYPT_SHA_HASH_SIZE = 20
XE_CRYPT_AES_BLOCK_SIZE = 16
XE_CRYPT_DES_BLOCK_SIZE = 8
XE_CRYPT_RC4_KEY_SIZE = 56
XE_CRYPT_HMAC_KEY_SIZE = 64


class RotSumCtx(object):
    """
    Context / output structure for XeCryptRotSum
    """

    def __init__(self, members: List[int]):
        if not len(members) == 4:
            raise ValueError('RotSumCtx must be size 4 (unsigned 64 bit integers')
        self.members = [c_uint64(m) for m in members]

    @classmethod
    def from_bytes(cls, byteinput: bytes):
        return RotSumCtx(struct.unpack('>4Q', byteinput))

    def __getitem__(self, item):
        return self.members[item]

    def __setitem__(self, key, value):
        self.members[key] = value

    def __setslice__(self, i, j, sequence):
        self.members[i:j] = sequence

    def __bytes__(self):
        return struct.pack('>4Q', *[m.value for m in self.members])


def XeCryptBnQw(n: int, size_bytes: int) -> bytes:
    """
    Utility function to convert a given int to quadword (Qw) Big Number (Bn) representation. This is an octet string
    similar to the openSSL BN format, but each 8-bytes is explicitly big-endian.

    :param n: arbitrary integer
    :param size_bytes: how big of a bn is required for the integer
    :return: octet string
    """
    return XeCryptBnQw_SwapLeBe(n.to_bytes(size_bytes, byteorder='little', signed=False), size_bytes // 8)


def XeCryptBnQw_toInt(bn: bytes) -> int:
    """
    Utility function to convert a given quadword (Qw) Big Number (Bn) to the Python native int representation.

    :param bn: octet string
    :return: int representation
    """
    return int.from_bytes(XeCryptBnQw_SwapLeBe(bn, len(bn) // 8), byteorder='little', signed=False)


def XeCryptBnQw_SwapLeBe(input: bytes, size: int) -> bytes:
    """
     export 369
     swap endian on u64 blocks

     args:	input buffer of u64 blocks to swap
                ouput buffer for swapped u64 blocks
                number of u64 blocks
    void XeCryptBnQw_SwapLeBe(const u64* input, u64* output, s32 size);

    https://stackoverflow.com/questions/27506474/how-to-byte-swap-a-32-bit-integer-in-python
    """
    return struct.pack(">" + str(size) + "Q", *struct.unpack("<" + str(size) + "Q", input))


def XeCryptBnDw_SwapLeBe(input: bytes, size: int) -> bytes:
    """
     export 369
     swap endian on u32 blocks

     args:	input buffer of u32 blocks to swap
                ouput buffer for swapped u64 blocks
                number of u32 blocks
    void XeCryptBnQw_SwapLeBe(const u32* input, u32* output, s32 size);

    https://stackoverflow.com/questions/27506474/how-to-byte-swap-a-32-bit-integer-in-python
    """
    return struct.pack(">" + str(size) + "L", *struct.unpack("<" + str(size) + "L", input))


def XeCryptRotSum(rotsumctx: RotSumCtx, rotsum_input: bytearray, input_size: int) -> None:
    """
    void XeCryptRotSum(RotSumCtx* rotsum_ctx, u64[] input, size_t input_size);

    Near direct translation from PPC assembly, implementing unsigned, 64-bit arithmetic / types using ctypes

    :param rotsumctx: RotSumCtx struct object (struct consisting of 4 u64 members). Modified in place
    :param rotsum_input: arbitrary length u64* input
    :param input_size: number of u64s (NOT bytes) in rotsum_input
    """
    r7 = rotsumctx[0]
    r9 = rotsumctx[1]
    r6 = rotsumctx[2]
    r10 = rotsumctx[3]

    if input_size == 0:
        return

    offset = 0
    for i in range(input_size):
        r11 = c_uint64(struct.unpack('>Q', rotsum_input[offset:offset + 8])[0])
        r8 = add(r11, r9)

        if r8.value < r11.value:
            r9 = c_uint64(1)
        else:
            r9 = c_uint64(0)

        r10 = subf(r11, r10)
        r7 = add(r7, r9)

        r9 = extldi(r8, 64, 29)

        if r10.value > r11.value:
            r11 = c_uint64(1)
        else:
            r11 = c_uint64(0)

        r6 = subf(r11, r6)
        r10 = extldi(r10, 64, 31)

        offset += 8

    rotsumctx[0] = r7
    rotsumctx[1] = r9
    rotsumctx[2] = r6
    rotsumctx[3] = r10


def XeCryptRotSumSha(input_1: bytearray, input_2: bytearray, digest_size=20) -> bytes:
    """
    Compute the RotSumSha of given byte data
    void XeCryptRotSumSha(const u8* input1, s32 input1Size,
                          const u8* input2, s32 input2Size,
                          u8* digest, s32 digestSize);
    """
    input_1_size = len(input_1)
    input_2_size = len(input_2)

    rotsum_ctx = RotSumCtx([0] * 4)

    XeCryptRotSum(rotsum_ctx, input_1, input_1_size >> 3)
    XeCryptRotSum(rotsum_ctx, input_2, input_2_size >> 3)

    sha_ctx = sha1()
    sha_ctx.update(bytes(rotsum_ctx))
    sha_ctx.update(bytes(rotsum_ctx))
    sha_ctx.update(input_1)
    sha_ctx.update(input_2)

    # Flip each u64
    for i in range(len(rotsum_ctx.members)):
        rotsum_ctx[i] = c_uint64(~rotsum_ctx[i].value)

    sha_ctx.update(bytes(rotsum_ctx))
    sha_ctx.update(bytes(rotsum_ctx))

    if digest_size > XE_CRYPT_SHA_HASH_SIZE:
        digest_size = XE_CRYPT_SHA_HASH_SIZE

    return sha_ctx.digest()[:digest_size]
