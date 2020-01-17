from unittest import TestCase

from Crypto.PublicKey import RSA
from lib.xecrypt_rsa import *

from lib.keys import *


class TestXeCrypt_RSA(TestCase):

    def test_create_xersa_1024(self):
        rsa_obj = RSA.generate(1024)
        # Create an XeRSA object and check that its components are equal to the RSA objects components
        #self.assertEqual(xersa_obj.aqwP, rsa_obj.p)
        #self.assertEqual(xersa_obj.aqwQ, rsa_obj.q)
        #self.assertEqual(xersa_obj.aqwCR, rsa_obj.u)
        self.fail()


    def test_from_rsa_1024(self):
        rsa_obj = RSA.generate(1024)

        size_bits = rsa_obj.size_in_bits()
        size_bytes = rsa_obj.size_in_bytes()
        size_bytes_half = int(size_bytes / 2)

        cqw_be = struct.pack(">L", 0x00000020)
        dwPubExp_be = struct.pack(">L", rsa_obj.e)
        qwReserved_be = struct.pack(">Q", 0x0000000000000000)
        aqwM_be = rsa_obj.n.to_bytes(size_bytes, byteorder='big', signed=False)

        xeKeyPub = cqw_be + dwPubExp_be + qwReserved_be + aqwM_be

        xecrypt_class = XeCrypt_RSAPrv_1024

        aqwP_be = rsa_obj.p.to_bytes(size_bytes_half, byteorder='big', signed=False)
        aqwQ_be = rsa_obj.q.to_bytes(size_bytes_half, byteorder='big', signed=False)
        aqwDP_be = (rsa_obj.d % (rsa_obj.p - 1)).to_bytes(size_bytes_half, byteorder='big', signed=False)
        aqwDQ_be = (rsa_obj.d % (rsa_obj.q - 1)).to_bytes(size_bytes_half, byteorder='big', signed=False)
        aqwCR_be = rsa_obj.u.to_bytes(size_bytes_half, byteorder='big', signed=False)

        xecrypt_obj = xecrypt_class(xeKeyPub + aqwP_be + aqwQ_be + aqwDP_be + aqwDQ_be + aqwCR_be)
        xecrypt_obj.build_rsa()

        self.assertEqual(xecrypt_obj.rsa, rsa_obj)

    def test_from_rsa_privkey(self):
        xekeys_obj = XEKEY_RSA_PRIV_2048_LIVE_DEVKIT_4BL
        rsa_obj = xekeys_obj.rsa

        size_bits = rsa_obj.size_in_bits()
        size_bytes = rsa_obj.size_in_bytes()
        size_bytes_half = int(size_bytes / 2)

        cqw_be = struct.pack(">L", 0x00000020)
        dwPubExp_be = struct.pack(">L", rsa_obj.e)
        qwReserved_be = struct.pack(">Q", 0x0000000000000000)

        aqwM_be = XeCryptBnQw(rsa_obj.n, size_bytes)

        xeKeyPub_be = cqw_be + dwPubExp_be + qwReserved_be + aqwM_be

        self.assertEqual(rsa_obj.e, xekeys_obj.dwPubExp)
        self.assertEqual(rsa_obj.d, modinv(xekeys_obj.dwPubExp, (xekeys_obj.aqwP - 1) * (xekeys_obj.aqwQ - 1)))
        self.assertEqual(rsa_obj.n, xekeys_obj.aqwM)
        self.assertEqual(rsa_obj.p, xekeys_obj.aqwP)
        self.assertEqual(rsa_obj.q, xekeys_obj.aqwQ)

        u = modinv(rsa_obj.q, rsa_obj.p)
        self.assertEqual(u, xekeys_obj.aqwCR)

        self.assertEqual(rsa_obj.u, xekeys_obj.aqwCR)

        aqwP_be = XeCryptBnQw(rsa_obj.p, size_bytes_half)
        aqwQ_be = XeCryptBnQw(rsa_obj.q, size_bytes_half)
        aqwDP_be = XeCryptBnQw((rsa_obj.d % (rsa_obj.p - 1)), size_bytes_half)
        aqwDQ_be = XeCryptBnQw((rsa_obj.d % (rsa_obj.q - 1)), size_bytes_half)
        aqwCR_be = XeCryptBnQw(rsa_obj.u, size_bytes_half)

        xeKeyAll_be = xeKeyPub_be + aqwP_be + aqwQ_be + aqwDP_be + aqwDQ_be + aqwCR_be

        self.assertEqual(cqw_be, test_cqwtest_be)
        self.assertEqual(dwPubExp_be, test_dwPubExptest_be)
        self.assertEqual(qwReserved_be, test_qwReserved_be)
        self.assertEqual(aqwM_be, test_aqwMtest_be)
        self.assertEqual(aqwP_be, test_aqwPtest_be)
        self.assertEqual(aqwQ_be, test_aqwQtest_be)
        self.assertEqual(aqwDP_be, test_aqwDPtest_be)
        self.assertEqual(aqwDQ_be, test_aqwDQtest_be)
        self.assertEqual(aqwCR_be, test_aqwCRtest_be)
        self.assertEqual(xeKeyAll_be, XEKEY_RSA_PRIV_2048_LIVE_DEVKIT_4BL_BN)
