#!/usr/bin/env python3

import struct

from typing import Union

from Crypto.Math.Numbers import Integer
from Crypto.PublicKey import RSA

from lib.xecrypt import XeCryptBnQw, XeCryptBnQw_toInt


class XeCrypt_RSA(RSA.RsaKey):
    """
    Thin wrapper around the RSA.RsaKey object supporting the XeCrypt RSA functions and export modes.
    """

    def __init__(self, **kwargs):
        super(XeCrypt_RSA, self).__init__(**kwargs)

    @classmethod
    def construct(cls, rsa_components, consistency_check=True):
        r"""Construct an RSA key from a tuple of valid RSA components.

        The modulus **n** must be the product of two primes.
        The public exponent **e** must be odd and larger than 1.

        In case of a private key, the following equations must apply:

        .. math::

            \begin{align}
            p*q &= n \\
            e*d &\equiv 1 ( \text{mod lcm} [(p-1)(q-1)]) \\
            p*u &\equiv 1 ( \text{mod } q)
            \end{align}

        Args:
            rsa_components (tuple):
                A tuple of integers, with at least 2 and no
                more than 6 items. The items come in the following order:

                1. RSA modulus *n*.
                2. Public exponent *e*.
                3. Private exponent *d*.
                   Only required if the key is private.
                4. First factor of *n* (*p*).
                   Optional, but the other factor *q* must also be present.
                5. Second factor of *n* (*q*). Optional.
                6. CRT coefficient *q*, that is :math:`p^{-1} \text{mod }q`. Optional.

            consistency_check (boolean):
                If ``True``, the library will verify that the provided components
                fulfil the main RSA properties.

        Raises:
            ValueError: when the key being imported fails the most basic RSA validity checks.

        Returns: An RSA key object (:class:`XeCrypt_RSA`).
        """
        return cls.from_rsa_obj(RSA.construct(rsa_components, consistency_check))

    @classmethod
    def from_rsa_obj(cls, rsa: RSA.RsaKey):
        if not rsa.has_private():
            return XeCrypt_RSA(n=rsa._n, e=rsa._e)
        else:
            return XeCrypt_RSA(n=rsa._n, e=rsa._e, d=rsa._d, p=rsa._p, q=rsa._q, u=rsa._u)

    @classmethod
    def from_xecrypt_rsa_bn(cls, key: bytes):
        """
        Extract (n, e) from public keys
        Extract (n, e, d, p, q, u) from private keys

        struct XECRYPT_RSA { // [sizeof = 16]
            unsigned long cqw; // data +0x00 [sizeof=4]
            unsigned long dwPubExp; // data +0x04 [sizeof=4]
            unsigned __int64 qwReserved; // data +0x08 [sizeof=8]
        };

        struct XECRYPT_RSAPRV_1024 { // [sizeof = 464]
            XECRYPT_RSA Rsa; // data +0x00 [sizeof=16]
            unsigned __int64 aqwM[cqw]; // data +0x10 [sizeof=8cqw]
            unsigned __int64 aqwP[cqw//2]; // data +0x10 + 8cqw + 0 * (cqw//2) [sizeof=8cqw//2]
            unsigned __int64 aqwQ[cqw//2]; // data +0x10 + 8cqw + 1 * (cqw//2) [sizeof=8cqw//2]
            unsigned __int64 aqwDP[cqw//2]; // data +0x10 + 8cqw + 2 * (cqw//2) [sizeof=8cqw//2]
            unsigned __int64 aqwDQ[cqw//2]; // data +0x10 + 8cqw + 3 * (cqw//2) [sizeof=8cqw//2]
            unsigned __int64 aqwCR[cqw//2]; // data +0x10 + 8cqw + 4 * (cqw//2) [sizeof=8cqw//2]
        };
        """
        if len(key) < 0x10:
            raise ValueError('Given XeCrypt_RSA does not container a header')

        cqw, dwPubExp, qwReserved = struct.unpack(">LLQ", key[0x0:0x10])

        modsize_bytes = cqw * 8

        # n, e, d, p, q, u
        offset = 0x10
        aqwM = XeCryptBnQw_toInt(key[offset:offset + modsize_bytes])
        offset += modsize_bytes

        n = aqwM
        e = dwPubExp

        # Public key members (n, e) only
        if not len(key) > offset:
            return XeCrypt_RSA.construct((n, e))

        # Get remaining private key components
        aqwP = XeCryptBnQw_toInt(key[offset: offset + modsize_bytes // 2])
        offset += modsize_bytes // 2
        aqwQ = XeCryptBnQw_toInt(key[offset: offset + modsize_bytes // 2])
        offset += modsize_bytes // 2
        aqwDP = XeCryptBnQw_toInt(key[offset: offset + modsize_bytes // 2])
        offset += modsize_bytes // 2
        aqwDQ = XeCryptBnQw_toInt(key[offset: offset + modsize_bytes // 2])
        offset += modsize_bytes // 2
        aqwCR = XeCryptBnQw_toInt(key[offset: offset + modsize_bytes // 2])

        p = aqwQ  # Specific to pycryptodome implementation. CR coefficient = p^-1 mod q
        q = aqwP  # Swap p and q such that u (CR) is calculated to be the same
        lcm = Integer(p - 1).lcm(Integer(q - 1))  # generate() calculates lcm before taking modinv
        d = int(Integer(e).inverse(lcm))
        u = aqwCR

        return XeCrypt_RSA.construct((n, e, d, p, q, u))

    @classmethod
    def from_key(cls, extern_key: Union[str, bytes], passphrase: Union[str, bytes]=None):
        """Import an RSA key (public or private).

        Args:
          extern_key (string or byte string):
            The RSA key to import.

            The following formats are supported for an RSA **public key**:

            - X.509 certificate (binary or PEM format)
            - X.509 ``subjectPublicKeyInfo`` DER SEQUENCE (binary or PEM
              encoding)
            - `PKCS#1`_ ``RSAPublicKey`` DER SEQUENCE (binary or PEM encoding)
            - An OpenSSH line (e.g. the content of ``~/.ssh/id_ecdsa``, ASCII)

            The following formats are supported for an RSA **private key**:

            - PKCS#1 ``RSAPrivateKey`` DER SEQUENCE (binary or PEM encoding)
            - `PKCS#8`_ ``PrivateKeyInfo`` or ``EncryptedPrivateKeyInfo``
              DER SEQUENCE (binary or PEM encoding)
            - OpenSSH (text format, introduced in `OpenSSH 6.5`_)

            For details about the PEM encoding, see `RFC1421`_/`RFC1423`_.

          passphrase (string or byte string):
            For private keys only, the pass phrase that encrypts the key.

        Returns: An RSA key object (:class:`RsaKey`).

        Raises:
          ValueError/IndexError/TypeError:
            When the given key cannot be parsed (possibly because the pass
            phrase is wrong).

        .. _RFC1421: http://www.ietf.org/rfc/rfc1421.txt
        .. _RFC1423: http://www.ietf.org/rfc/rfc1423.txt
        .. _`PKCS#1`: http://www.ietf.org/rfc/rfc3447.txt
        .. _`PKCS#8`: http://www.ietf.org/rfc/rfc5208.txt
        .. _`OpenSSH 6.5`: https://flak.tedunangst.com/post/new-openssh-key-format-and-bcrypt-pbkdf
        """
        return RSA.import_key(extern_key, passphrase)

    def export_key(self, format:str='PEM', passphrase:str=None, pkcs:int=1,
                   protection:str=None, randfunc:int=None) -> bytes:
        """Export this RSA key.

        Args:
          format (string):
            The format to use for wrapping the key:

            - *'PEM'*. (*Default*) Text encoding, done according to `RFC1421`_/`RFC1423`_.
            - *'DER'*. Binary encoding.
            - *'XeCrypt'*. Binary encoding, done according to XeCrypt_RSA_BnQw structs.
            - *'OpenSSH'*. Textual encoding, done according to OpenSSH specification.
              Only suitable for public keys (not private keys).

          passphrase (string):
            (*For private keys only*) The pass phrase used for protecting the output.

          pkcs (integer):
            (*For private keys only*) The ASN.1 structure to use for
            serializing the key. Note that even in case of PEM
            encoding, there is an inner ASN.1 DER structure.

            With ``pkcs=1`` (*default*), the private key is encoded in a
            simple `PKCS#1`_ structure (``RSAPrivateKey``).

            With ``pkcs=8``, the private key is encoded in a `PKCS#8`_ structure
            (``PrivateKeyInfo``).

            .. note::
                This parameter is ignored for a public key.
                For DER and PEM, an ASN.1 DER ``SubjectPublicKeyInfo``
                structure is always used.

          protection (string):
            (*For private keys only*)
            The encryption scheme to use for protecting the private key.

            If ``None`` (default), the behavior depends on :attr:`format`:

            - For *'DER'*, the *PBKDF2WithHMAC-SHA1AndDES-EDE3-CBC*
              scheme is used. The following operations are performed:

                1. A 16 byte Triple DES key is derived from the passphrase
                   using :func:`Crypto.Protocol.KDF.PBKDF2` with 8 bytes salt,
                   and 1 000 iterations of :mod:`Crypto.Hash.HMAC`.
                2. The private key is encrypted using CBC.
                3. The encrypted key is encoded according to PKCS#8.

            - For *'XeCrypt'*, no protection scheme is used and the parameter is ignored.

            - For *'PEM'*, the obsolete PEM encryption scheme is used.
              It is based on MD5 for key derivation, and Triple DES for encryption.

            Specifying a value for :attr:`protection` is only meaningful for PKCS#8
            (that is, ``pkcs=8``) and only if a pass phrase is present too.

            The supported schemes for PKCS#8 are listed in the
            :mod:`Crypto.IO.PKCS8` module (see :attr:`wrap_algo` parameter).

          randfunc (callable):
            A function that provides random bytes. Only used for PEM encoding.
            The default is :func:`Crypto.Random.get_random_bytes`.

        Returns:
          byte string: the encoded key

        Raises:
          ValueError:when the format is unknown or when you try to encrypt a private
            key with *DER* format and PKCS#1.

        .. warning::
            If you don't provide a pass phrase, the private key will be
            exported in the clear!

        .. _RFC1421:    http://www.ietf.org/rfc/rfc1421.txt
        .. _RFC1423:    http://www.ietf.org/rfc/rfc1423.txt
        .. _`PKCS#1`:   http://www.ietf.org/rfc/rfc3447.txt
        .. _`PKCS#8`:   http://www.ietf.org/rfc/rfc5208.txt
        """
        # Revert to original definition for anything but XeCrypt
        if not format == 'XeCrypt':
            super(XeCrypt_RSA, self).exportKey(format, passphrase, pkcs, protection, randfunc)

        size_bytes = self.size_in_bytes()
        cqw_be = struct.pack(">L", self.size_in_bytes() // 8)
        dwPubExp_be = struct.pack(">L", self.e)
        qwReserved_be = struct.pack(">Q", 0x0000000000000000)
        aqwM_be = XeCryptBnQw(self.n, size_bytes)

        xecrypt_rsa_pub_bn = cqw_be + dwPubExp_be + qwReserved_be + aqwM_be

        if not self.has_private():
            return xecrypt_rsa_pub_bn

        aqwP_be = XeCryptBnQw(self.q, size_bytes // 2)  # Swap P and Q due to CR coefficent calculation in pycryptodome
        aqwQ_be = XeCryptBnQw(self.p, size_bytes // 2)
        aqwDP_be = XeCryptBnQw((self.d % (self.q - 1)), size_bytes // 2)
        aqwDQ_be = XeCryptBnQw((self.d % (self.p - 1)), size_bytes // 2)
        aqwCR_be = XeCryptBnQw(self.u, size_bytes // 2)

        xecrypt_rsa_prv_bn = xecrypt_rsa_pub_bn + aqwP_be + aqwQ_be + aqwDP_be + aqwDQ_be + aqwCR_be

        return xecrypt_rsa_prv_bn

    # Backward compatibility
    exportKey = export_key

    def _encrypt_pub(self, plaintext):
        if not 0 < plaintext < self._n:
            raise ValueError("Plaintext too large")
        return int(pow(Integer(plaintext), self._d, self._n))

    def XeCryptBnQwNeRsaPrvCrypt(self, message_input: bytes) -> bytes:
        """
        Export 364

        bool XeCryptBnQwNeRsaPrvCrypt(const u64* message_input, u64* output, const XeRsaKey* key);

        Encrypt a given Bn message_input with private key in u64 blocks

        returns:   TRUE if successful
                   FALSE if error

        """
        # Encrypt each qw in the plaintext a^b mod m
        cipher_text = bytearray(len(message_input))
        for i in range(len(message_input) // 8):
            offset = i * 8

            u64 = struct.unpack(">Q", message_input[offset:offset + 8])[0]
            cipher_block = self._encrypt(u64)
            cipher_text[offset:offset + 8] = cipher_block

        return bytes(cipher_text)

    def XeCryptBnQwNeRsaPubCrypt(self, message_input: bytes) -> bytes:
        """
        Export 365

        bool XeCryptBnQwNeRsaPubCrypt(const u64* message_input, u64* output, const XeRsaKey* key);

        Encrypt data with public key

        args:    message_input data to crypt
                    output for crypted data
                    public key to crypt with
        returns:    TRUE if successful
                    FALSE if error
        """
        cipher_text = bytearray(len(message_input))
        for i in range(len(message_input) // 8):
            offset = i * 8

            u64 = struct.unpack(">Q", message_input[offset:offset + 8])[0]
            cipher_block = self._encrypt_pub(u64)
            cipher_text[offset:offset + 8] = cipher_block

        return bytes(cipher_text)


#: `Object ID`_ for the RSA encryption algorithm. This OID often indicates
#: a generic RSA key, even when such key will be actually used for digital
#: signatures.
#:
#: .. _`Object ID`: http://www.alvestrand.no/objectid/1.2.840.113549.1.1.1.html
oid = "1.2.840.113549.1.1.1"


