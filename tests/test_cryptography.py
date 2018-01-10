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

from golem_messages.cryptography import ECCx, mk_privkey, privtopub

from golem_messages import exceptions


def get_ecc(secret=''):
    return ECCx(raw_privkey=mk_privkey(secret))


class TestCrypto(TestCase):

    def test_asymetric(self):
        bob = get_ecc('secret2')

        # enc / dec
        plaintext = b"Hello Bob"
        ciphertext = ECCx.encrypt(plaintext, bob.raw_pubkey)
        assert bob.decrypt(ciphertext) == plaintext

    def test_en_decrypt(self):
        alice = ECCx(None)
        bob = ECCx(None)
        msg = b'test'
        ciphertext = alice.encrypt(msg, bob.raw_pubkey)
        assert bob.decrypt(ciphertext) == msg

    def test_en_decrypt_shared_mac_data(self):
        alice, bob = ECCx(None), ECCx(None)
        ciphertext = alice.encrypt(b'test', bob.raw_pubkey,
                                   shared_mac_data=b'shared mac data')
        assert bob.decrypt(ciphertext,
                           shared_mac_data=b'shared mac data') == b'test'

    def test_en_decrypt_shared_mac_data_fail(self):
        with self.assertRaises(exceptions.DecryptionError):
            alice, bob = ECCx(None), ECCx(None)
            ciphertext = alice.encrypt(b'test', bob.raw_pubkey,
                                       shared_mac_data=b'shared mac data')
            bob.decrypt(ciphertext, shared_mac_data=b'wrong')

    def test_privtopub(self):
        priv = mk_privkey('test')
        pub = privtopub(priv)
        pub2 = ECCx(raw_privkey=priv).raw_pubkey
        assert pub == pub2
