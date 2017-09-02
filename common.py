#!/usr/bin/env python3

def dbgprint(string):
    global debug
    if debug:
        print(string)

def warnprint(warning):
    print('** WARN ** : ' + warning)

def failprint(failure):
    print('** FAIL **': + failure)
