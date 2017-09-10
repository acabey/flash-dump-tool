#!/usr/bin/env python3

DEBUG = True

class Constants():
    SHADOWBOOT_SIZE = 851968 # Seems to be the max size (bytes) for a shadowboot ROM based on official samples. Don't where limit is imposed
    HV_SIZE = 0x40000
    SECRET_1BL = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    CPUKEY = None
    #CPUKEY = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

def dbgprint(string):
    global DEBUG
    if DEBUG:
        print(string)

def warnprint(warning):
    print('** WARN ** : ' + warning)

def failprint(failure):
    print('** FAIL ** : ' + failure)
