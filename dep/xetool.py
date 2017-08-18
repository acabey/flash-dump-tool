#/bin/python3

# A lot of this code is taken from https://github.com/Free60Project/tools/blob/master/imgbuild/build.py
"""

I need to decide on the scheme for modifying data. Right now I do both inline
modifications (encrypt, decrypt, etc.) as and return the modified data

"""

import sys, os
from bootloader import Bootloader, CB, CD, CE, CF, CG
from nand import NANDHeader, NANDImage

def main(argv):
    target = argv[1] if len(sys.argv) > 1 else None

    if not target:
        sys.exit(1)

    # Parse file header
    with open(target, 'rb') as image:
        nand = NANDImage(image, os.path.getsize(target))

    nand.printMetadata()
    nand.exportParts()

if __name__ == '__main__':
    main(sys.argv)
