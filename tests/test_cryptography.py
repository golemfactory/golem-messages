# pylint: disable=no-self-use
# Based on:
# https://github.com/ethereum/pydevp2p/blob/develop/devp2p/tests/test_crypto.py
#
#
# The MIT License (MIT)
#
# Copyright (c) 2015 Heiko Hees
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
#

from unittest import TestCase

from golem_messages.cryptography import ECCx, mk_privkey, privtopub, sha3, \
        ecdsa_verify, ECIES

from golem_messages import exceptions


def get_ecc(secret=''):
    return ECCx(raw_privkey=mk_privkey(secret))


class TestCrypto(TestCase):

    def setUp(self):
        self.ecies = ECIES()

    def test_asymmetric(self):
        bob = get_ecc('secret2')

        # enc / dec
        plaintext = b"Hello Bob"
        ciphertext = self.ecies.encrypt(plaintext, bob.raw_pubkey)
        decrypted = self.ecies.decrypt(ciphertext, bob.raw_privkey)
        self.assertEqual(decrypted, plaintext)

    def test_signature(self):
        bob = get_ecc('secret2')

        # sign
        message = sha3("Hello Alice")
        signature = bob.sign(message)

        # verify signature
        assert ecdsa_verify(bob.raw_pubkey, signature, message) is True

        # wrong signature
        message = sha3("Hello Alicf")
        with self.assertRaises(exceptions.InvalidSignature):
            ecdsa_verify(bob.raw_pubkey, signature, message)

    def test_en_decrypt_shared_mac_data(self):
        bob = ECCx(None)
        text = b'test'
        shared_mac_data = b'shared mac data'
        ciphertext = self.ecies.encrypt(
            data=text,
            raw_pubkey=bob.raw_pubkey,
            shared_mac_data=shared_mac_data)
        decrypted = self.ecies.decrypt(
            data=ciphertext,
            raw_privkey=bob.raw_privkey,
            shared_mac_data=shared_mac_data)
        self.assertEqual(decrypted, text)

    def test_en_decrypt_shared_mac_data_fail(self):
        bob = ECCx(None)
        ciphertext = self.ecies.encrypt(
            data=b'test',
            raw_pubkey=bob.raw_pubkey,
            shared_mac_data=b'shared mac data')
        with self.assertRaises(exceptions.DecryptionError):
            self.ecies.decrypt(
                data=ciphertext,
                raw_privkey=bob.raw_privkey,
                shared_mac_data=b'wrong')

    def test_privtopub(self):
        priv = mk_privkey('test')
        pub = privtopub(priv)
        pub2 = ECCx(raw_privkey=priv).raw_pubkey
        assert pub == pub2
