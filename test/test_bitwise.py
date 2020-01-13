from unittest import TestCase

from lib.bitwise_arithmetic import add, subf
from lib.bitwise_arithmetic import mask
from lib.bitwise_arithmetic import ror
from ctypes import c_uint64


class TestArithmetic(TestCase):

    def test_add_overflow(self):
        self.assertEquals(add(0xFFFFFFFFFFFFFFFF, 0x1).value, c_uint64(0x0).value)

    def test_sub_underflow(self):
        self.assertEquals(subf(0x1020304050607, 0).value, c_uint64(0xfffefdfcfbfaf9f9).value)


class TestMask(TestCase):

    def test_normal(self):
        self.assertEquals(mask(8, 4, 7), 0b00001111)
        self.assertEquals(mask(8, 2, 5), 0b00111100)
        self.assertEquals(mask(8, 3, 5), 0b00011100)

    def test_zero(self):
        self.assertEquals(mask(8, 0, 0), 0b10000000)

    def test_one(self):
        self.assertEquals(mask(8, 7, 7), 0b00000001)

    def test_max(self):
        self.assertEquals(mask(8, 0, 7), 0b11111111)


class TestRor(TestCase):
    def test_normal(self):
        # 0000110100100000
        self.assertEquals(ror(0b01101001, 3, 8), 0b00101101)
        self.assertEquals(ror(0b1101, 3, 4), 0b1011)

    def test_ones(self):
        self.assertEquals(ror(0b1111, 2, 4), 0b1111)

    def test_circle(self):
        self.assertEquals(ror(0b01101001, 8, 8), 0b01101001)

