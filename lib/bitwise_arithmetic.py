#!/usr/bin/env python3

from ctypes import c_uint64


def mask(total_bits, start_bit, end_bit):
    """
    Create a mask from the perspective of a CPU (big-endian)
    Examples:
        mask(8, 4, 7) = 00001111 = 15
        mask(8, 2, 5) = 00111100 = 60
        mask(8, 3, 5) = 00011100 = 28

        mask(8, 0, 7) = 0000000111111111

    :param total_bits: size of the field to be masked (in bits)
    :param start_bit: high order bit index from which the mask will start (indexing starts at 0)
    :param end_bit: low order bit index where the mask will end (indexing starts at 0)
    :return:
    """
    if end_bit < start_bit:
        raise ValueError('Start bit must be less than (left of) end bit')
    if total_bits < start_bit or total_bits < end_bit:
        raise ValueError('Total bits must be greater than start and end (index bits)')

    num = 2 ** (1 + end_bit - start_bit) - 1
    num <<= total_bits - (end_bit + 1)
    return num


def ror(n, rotations, width):
    """Return a given number of bitwise right rotations of an integer n,
       for a given bit field width.
    """
    rotated_carry = (n << (width - rotations)) & (2 ** width) - 1
    shifted = (n >> rotations) & (2 ** width) - 1
    return shifted | rotated_carry & (2 ** width) - 1


def rol(n: int, rotations: int, width: int) -> c_uint64:
    """Return a given number of bitwise right rotations of an integer n,
       for a given bit field width.
    """
    rotated_carry = (n >> (width - rotations)) & (2 ** width) - 1
    shifted = (n << rotations) & (2 ** width) - 1
    return shifted | rotated_carry & (2 ** width) - 1


def rldicr(rs: c_uint64, sh: int, me: int) -> c_uint64:
    rotated = rol(rs.value, sh, 64)
    left_mask = mask(64, 0, me)
    return c_uint64(rotated & left_mask)


def extldi(ry: c_uint64, n: int, b: int) -> c_uint64:
    return rldicr(ry, b, n - 1)


def subf(ra: c_uint64, rb: c_uint64) -> c_uint64:
    mask64 = mask(64, 0, 63)
    return c_uint64(((rb.value & mask64) - (ra.value & mask64)) & mask64)


def add(ra: c_uint64, rb: c_uint64) -> c_uint64:
    mask64 = mask(64, 0, 63)
    return c_uint64(((rb.value & mask64) + (ra.value & mask64)) & mask64)
