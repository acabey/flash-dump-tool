#!/usr/bin/env python3

import struct
from typing import Union


def GETU32BE(data: Union[bytes, bytearray], offset: int) -> int:
    """
    Get a 32-bit integer value from the given bytes / bytearray, starting at the given offset

    :param data:
    :param offset:
    :return: value
    """
    return struct.unpack('>L', data[offset:])


def GETU64BE(data: Union[bytes, bytearray], offset: int) -> int:
    """
    Get a 64-bit integer value from the given bytes / bytearray, starting at the given offset

    :param data:
    :param offset:
    :return: value
    """
    return struct.unpack('>Q', data[offset:])


def SETU32BE(data: Union[bytes, bytearray], offset: int, value: int) -> None:
    """

    :param data:
    :param offset:
    :param value:
    :return:
    """
    # value_bytes = struct.pack('>L', (value)) # Alternatively
    value_bytes = value.to_bytes(32, 'big', signed=False)
    data[offset:len(value_bytes)] = value_bytes


def SETU64BE(data: Union[bytes, bytearray], offset: int, value: int) -> None:
    """

    :param data:
    :param offset:
    :param value:
    :return:
    """
    # value_bytes = struct.pack('>Q', (value)) # Alternatively
    value_bytes = value.to_bytes(64, 'big', signed=False)
    data[offset:len(value_bytes)] = value_bytes
