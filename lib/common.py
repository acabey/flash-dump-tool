#!/usr/bin/env python3

class Constants():
    # Seems to be the max size (bytes) for a shadowboot ROM based on official samples. Don't where limit is imposed
    SHADOWBOOT_SIZE = 851968

    HV_SIZE = 0x40000

    SECRET_ZERO = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    # BL4 Key stuff
    BL4_SALT = b'XBOX_ROM_4'
