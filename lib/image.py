#!/usr/bin/env python3

from os import path

from lib.bootloader import *
from lib.common import *
from lib.nand import NANDHeader, ImageType, OutputPath

"""
Stores structures from NAND data

Provides methods to identify structures from RAW data reads
"""


class Image(object):
    outputpath = None
    imagetype = None
    nandheader = None
    kv = None
    smc = None
    smcconfig = None
    sb = None
    cb = None
    sc = None
    sd = None
    cd = None
    se = None
    ce = None
    cf = None
    cg = None
    cf1 = None
    cg1 = None
    kernel = None
    hv = None

    def getAvailableStructures(self):
        # All variable members of this class that are not None
        return {k: v for k, v in vars(Image).items() if
                not callable(getattr(Image, k)) and not k.startswith('__') and v is not None}
        # return vars(Image)['_data']


    def identifyBL2(image):
        """
        Identifies bootloaders given previous is available and proper seek
        """

        try:
            bl2header = None
            offset = image.tell()
            bl2header = BootloaderHeader(image.read(BootloaderHeader.HEADER_SIZE), currentoffset=offset)
        except ValueError as e:
            dbgprint('Failed BL2 header check: ' + str(e))
        except Exception as e:
            raise

        if bl2header:
            try:
                Image.cb = CB(image.read(bl2header.length), bl2header)
                dbgprint(bl2header)
            except ValueError as e:
                dbgprint('Failed CB header check: ' + str(e))
            except Exception as e:
                raise
            try:
                image.seek(bl2header.offset, 0)
                Image.sb = SB(image.read(bl2header.length), bl2header)
                dbgprint(bl2header)
            except ValueError as e:
                dbgprint('Failed SB check: ' + str(e))
            except Exception as e:
                raise

    def identifyCD(image):
        # assert(Image.cb != None)

        try:
            bl4header = None
            offset = image.tell()
            bl4header = BootloaderHeader(image.read(BootloaderHeader.HEADER_SIZE), currentoffset=offset)
            dbgprint(bl4header)
        except ValueError as e:
            dbgprint('Failed CD header check: ' + str(e))
        except Exception as e:
            raise

        if bl4header:
            try:
                image.seek(bl4header.offset, 0)
                Image.cd = CD(image.read(bl4header.length), bl4header)
            except ValueError as e:
                dbgprint('Failed CD check: ' + str(e))
            except Exception as e:
                raise

    def identifyCE(image):
        # assert(Image.cd != None)

        try:
            bl5header = None
            offset = image.tell()
            bl5header = BootloaderHeader(image.read(BootloaderHeader.HEADER_SIZE), currentoffset=offset)
            dbgprint(bl5header)
        except ValueError as e:
            dbgprint('Failed CE header check: ' + str(e))
        except Exception as e:
            raise

        if bl5header:
            try:
                image.seek(bl5header.offset, 0)
                Image.ce = CE(image.read(bl5header.length), bl5header)
            except ValueError as e:
                dbgprint('Failed CE check: ' + str(e))
            except Exception as e:
                raise

    def identifySC(image):
        # assert(Image.sb != None)

        try:
            bl3header = None
            offset = image.tell()
            bl3header = BootloaderHeader(image.read(BootloaderHeader.HEADER_SIZE), currentoffset=offset)
            dbgprint(bl3header)
        except ValueError as e:
            dbgprint('Failed SC header check: ' + str(e))
        except Exception as e:
            raise

        if bl3header:
            try:
                image.seek(bl3header.offset, 0)
                Image.sc = SC(image.read(bl3header.length), bl3header)
            except ValueError as e:
                dbgprint('Failed SC check: ' + str(e))
            except Exception as e:
                raise

    def identifySD(image):
        # assert(Image.sc != None)

        try:
            bl4header = None
            offset = image.tell()
            bl4header = BootloaderHeader(image.read(BootloaderHeader.HEADER_SIZE), currentoffset=offset)
            dbgprint(bl4header)
        except ValueError as e:
            dbgprint('Failed SD header check: ' + str(e))
        except Exception as e:
            raise

        if bl4header:
            try:
                image.seek(bl4header.offset, 0)
                Image.sd = SD(image.read(bl4header.length), bl4header)
            except ValueError as e:
                dbgprint('Failed SD check: ' + str(e))
            except Exception as e:
                raise

    def identifySE(image):
        # assert(Image.sd != None)

        try:
            bl5header = None
            offset = image.tell()
            bl5header = BootloaderHeader(image.read(BootloaderHeader.HEADER_SIZE), currentoffset=offset)
            dbgprint(bl5header)
        except ValueError as e:
            dbgprint('Failed SE header check: ' + str(e))
        except Exception as e:
            raise

        if bl5header:
            try:
                image.seek(bl5header.offset, 0)
                Image.se = SE(image.read(bl5header.length), bl5header)
            except ValueError as e:
                dbgprint('Failed SE check: ' + str(e))
            except Exception as e:
                raise

    def identifyAvailableStructures(target):

        # Assume that the path is valid. There will be an unhandled exception if we try to write to a bad path
        Image.outputpath = OutputPath(target)

        # Is the target an existing file to analyze and manipulate or an output path?
        if not path.isfile(target):
            return

        # If real file, begin populating available

        with open(target, 'rb') as image:
            # First check for the NAND header, if that exists, check if it is a full NAND / Shadowboot image
            # If this fails, fall back to individual parts

            # Check for NAND/Shadowboot header
            try:
                offset = image.tell()
                Image.nandheader = NANDHeader(image.read(NANDHeader.HEADER_SIZE), currentoffset=offset)
            except ValueError as e:
                dbgprint('Failed NAND header check: ' + str(e))
            except Exception as e:
                raise

            # If valid header, check for subsequent parts
            if Image.nandheader:
                image.seek(Image.nandheader.bl2offset, 0)

                # Identifies either SB or CB given an image at the proper seek
                Image.identifyBL2(image)

                # Identify retail NAND structures
                if Image.cb:
                    Image.cb.updateKey()
                    Image.cb.decrypt()

                    image.seek(Image.cb.header.offset + Image.cb.header.length, 0)
                    Image.identifyCD(image)

                    if Image.cd:
                        Image.cd.updateKey(Image.cb.key)
                        Image.cd.decrypt()

                        image.seek(Image.cd.header.offset + Image.cd.header.length, 0)
                        Image.identifyCE(image)

                        if Image.ce:
                            Image.ce.updateKey(Image.cd.key)
                            Image.ce.decrypt()

                            # Set image type
                            # TODO This AND is redundent
                            if Image.nandheader and Image.cb and Image.cd and Image.ce:
                                Image.imagetype = ImageType.RETAIL

                # Identify devkit NAND structures
                elif Image.sb:
                    Image.sb.updateKey()
                    Image.sb.decrypt()

                    image.seek(Image.sb.header.offset + Image.sb.header.length, 0)
                    Image.identifySC(image)

                    if Image.sc:
                        Image.sc.updateKey(Constants.SECRET_ZERO)
                        Image.sc.decrypt()

                        image.seek(Image.sc.header.offset + Image.sc.header.length, 0)
                        Image.identifySD(image)

                        if Image.sd:
                            Image.sd.updateKey(Image.sc.key)
                            Image.sd.decrypt()

                            image.seek(Image.sd.header.offset + Image.sd.header.length, 0)
                            Image.identifySE(image)

                            if Image.se:
                                Image.se.updateKey(Image.sd.key)
                                Image.se.decrypt()

                                # TODO This AND is redundent
                                if Image.nandheader and Image.sb and Image.sc and Image.sd and Image.se:
                                    # Determine devkit vs shadowboot by file size
                                    Image.imagetype = ImageType.SHADOWBOOT if path.getsize(
                                        target) <= Constants.SHADOWBOOT_SIZE else ImageType.DEVKIT

        # TODO Fall back to individual structures
        # image.seek(0, 0)
