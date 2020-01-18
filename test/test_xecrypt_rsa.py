from unittest import TestCase

import struct

from Crypto.PublicKey import RSA
from lib.xecrypt_rsa import XeCrypt_RSA

from lib.xecrypt import XeCryptBnQw


class TestXeCrypt_RSA(TestCase):

    def test_from_rsa_1024(self):
        rsa_obj = RSA.generate(1024)

        size_bytes = rsa_obj.size_in_bytes()

        cqw_be = struct.pack(">L", rsa_obj.size_in_bytes() // 8)
        dwPubExp_be = struct.pack(">L", rsa_obj.e)
        qwReserved_be = struct.pack(">Q", 0x0000000000000000)
        aqwM_be = XeCryptBnQw(rsa_obj.n, size_bytes)

        xecrypt_rsa_pub_bn = cqw_be + dwPubExp_be + qwReserved_be + aqwM_be

        # If p > q, p and q are swapped internally
        aqwP_be = XeCryptBnQw(rsa_obj.q, size_bytes // 2)
        aqwQ_be = XeCryptBnQw(rsa_obj.p, size_bytes // 2)
        aqwDP_be = XeCryptBnQw((rsa_obj.d % (rsa_obj.q - 1)), size_bytes // 2)
        aqwDQ_be = XeCryptBnQw((rsa_obj.d % (rsa_obj.p - 1)), size_bytes // 2)
        aqwCR_be = XeCryptBnQw(rsa_obj.u, size_bytes // 2)

        xecrypt_rsa_prv_bn = xecrypt_rsa_pub_bn + aqwP_be + aqwQ_be + aqwDP_be + aqwDQ_be + aqwCR_be

        xecrypt_obj = XeCrypt_RSA.from_xecrypt_rsa_bn(xecrypt_rsa_prv_bn)

        self.assertEqual(xecrypt_obj.n, rsa_obj.n)
        self.assertEqual(xecrypt_obj.e, rsa_obj.e)
        self.assertEqual(xecrypt_obj.d, rsa_obj.d)
        self.assertEqual(xecrypt_obj.u, rsa_obj.u)

    def test_from_rsa_1024_pass(self):
        rsa_obj = RSA.construct((102662869710609346050730342844181640203790240597878825117096296086433787535212076261481166462240983214179088332764344949929344355051368606414118520935774143122957209319046956180571781037814440244974200565912648605418047700870676639194051723363243354999016397818477091892270701393227034493622349059120738829769,
                                 65537,
                                 7295130754265647261215057244386436645391933571331029625559873825083878550307195006633165879040179727916017125679899208566473238956226613974862290797532692832062595139131276355325765857920182279492125541693413988482757993670675138324084052531535999270805796137540990341814670092138702503301501916466190442257))

        size_bytes = rsa_obj.size_in_bytes()

        cqw_be = struct.pack(">L", rsa_obj.size_in_bytes() // 8)
        dwPubExp_be = struct.pack(">L", rsa_obj.e)
        qwReserved_be = struct.pack(">Q", 0x0000000000000000)
        aqwM_be = XeCryptBnQw(rsa_obj.n, size_bytes)

        xecrypt_rsa_pub_bn = cqw_be + dwPubExp_be + qwReserved_be + aqwM_be

        # If p > q, p and q are swapped internally
        aqwP_be = XeCryptBnQw(rsa_obj.q, size_bytes // 2)
        aqwQ_be = XeCryptBnQw(rsa_obj.p, size_bytes // 2)
        aqwDP_be = XeCryptBnQw((rsa_obj.d % (rsa_obj.q - 1)), size_bytes // 2)
        aqwDQ_be = XeCryptBnQw((rsa_obj.d % (rsa_obj.p - 1)), size_bytes // 2)
        aqwCR_be = XeCryptBnQw(rsa_obj.u, size_bytes // 2)

        xecrypt_rsa_prv_bn = xecrypt_rsa_pub_bn + aqwP_be + aqwQ_be + aqwDP_be + aqwDQ_be + aqwCR_be

        xecrypt_obj = XeCrypt_RSA.from_xecrypt_rsa_bn(xecrypt_rsa_prv_bn)

        self.assertEqual(xecrypt_obj.n, rsa_obj.n)
        self.assertEqual(xecrypt_obj.e, rsa_obj.e)
        self.assertEqual(xecrypt_obj.d, rsa_obj.d)
        self.assertEqual(xecrypt_obj.u, rsa_obj.u)

    def test_from_rsa(self):
        rsa_obj = RSA.generate(1024)
        xecrypt_obj = XeCrypt_RSA.from_rsa_obj(rsa_obj)

        self.assertEqual(xecrypt_obj.n, rsa_obj.n)
        self.assertEqual(xecrypt_obj.e, rsa_obj.e)
        self.assertEqual(xecrypt_obj.d, rsa_obj.d)
        self.assertEqual(xecrypt_obj.u, rsa_obj.u)

    def test_to_xecrypt_pass(self):
        rsa_obj = RSA.construct((102662869710609346050730342844181640203790240597878825117096296086433787535212076261481166462240983214179088332764344949929344355051368606414118520935774143122957209319046956180571781037814440244974200565912648605418047700870676639194051723363243354999016397818477091892270701393227034493622349059120738829769,
                                 65537,
                                 7295130754265647261215057244386436645391933571331029625559873825083878550307195006633165879040179727916017125679899208566473238956226613974862290797532692832062595139131276355325765857920182279492125541693413988482757993670675138324084052531535999270805796137540990341814670092138702503301501916466190442257))
        xecrypt_obj = XeCrypt_RSA.from_rsa_obj(rsa_obj)

        self.assertEqual(xecrypt_obj.size_in_bytes(), 128)

        xecrypt_rsa_prv_bn = xecrypt_obj.export_key('XeCrypt')
        xecrypt_obj_new = XeCrypt_RSA.from_xecrypt_rsa_bn(xecrypt_rsa_prv_bn)

        self.assertEqual(xecrypt_obj.n, xecrypt_obj_new.n)
        self.assertEqual(xecrypt_obj.e, xecrypt_obj_new.e)
        self.assertEqual(xecrypt_obj.d, xecrypt_obj_new.d)
        self.assertEqual(xecrypt_obj.u, xecrypt_obj_new.u)

    def test_to_xecrypt_lcm(self):
        # In this case, calculation of d requires an lcm for the totient
        rsa_obj = RSA.construct((134011293428901909047609358281338516963575633558842848199966819245470336377410968036099247702587684683832746153415503067983772903481846771167592841995883397222578351983540201958565722170610278058848860933479211336275164509816257655215943684414890367229602423299717328829125667980022417592279034033750451000999,
                                 65537,
                                 37967174126693870580610750566683749846974847431280262812653675272598234137778325968693604860121714991028953327182238326667206362595162883922887530612609129927088226376758450065147723921538370194185915152616809616547098685619221936820644380376459826906065851081152282315676737077402730317458741775371523191373))
        xecrypt_obj = XeCrypt_RSA.from_rsa_obj(rsa_obj)

        xecrypt_rsa_prv_bn = xecrypt_obj.export_key('XeCrypt')
        xecrypt_obj_new = XeCrypt_RSA.from_xecrypt_rsa_bn(xecrypt_rsa_prv_bn)

        self.assertEqual(xecrypt_obj.n, xecrypt_obj_new.n)
        self.assertEqual(xecrypt_obj.e, xecrypt_obj_new.e)
        self.assertEqual(xecrypt_obj.d, xecrypt_obj_new.d)
        self.assertEqual(xecrypt_obj.u, xecrypt_obj_new.u)

