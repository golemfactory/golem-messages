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
        ecdsa_verify

from golem_messages import exceptions


def get_ecc(secret=''):
    return ECCx(raw_privkey=mk_privkey(secret))


class TestCrypto(TestCase):

    def test_asymmetric(self):
        bob = get_ecc('secret2')

        # enc / dec
        plaintext = b"Hello Bob"
        ciphertext = ECCx.encrypt(plaintext, bob.raw_pubkey)
        assert bob.decrypt(ciphertext) == plaintext

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

    def test_pyelliptic_unbound_local_error(self):
        "Proof of pyelliptic UnboundLocalError bug"
        # See https://github.com/golemfactory/golem-messages/issues/121
        invalid_data = b'\x04\x14\xd9\x8a4\x91\xf0\xb5j\\2\xd9\x16\x13\x97\x12\xf2\x1f)\x8f)P\xc9\x8f\x8c\xb2Z\x91\xe5\xe0_\xf3\xa2 K\xab\xda\x7f\x17\xb9\x05a\xcb\x7f\x00\xc2k\xe4\xa7\x94G\xe56\xa2\xccX\x1c\xdc\x0f\xafkY\xd7AX\xa8\xe3\x02\x80\x9fR\xc6{\x0f\xe0\xc3i\xde\x8b)\\\xff\xbd\t\x11\x08a\xba\xdf\xef>S\\W>z\x06\xff$E$\'\x96\x0c\x9d\x19in\xb5\x1d\xcf\xd7L\xe9SZ\xf3\x9f\xec$Z\xb7>\x14\xec\x06\xe1\x9a\xfe\xb7\xe9B\xabI\xa1\x94\xb2\xc3\x98i2\xab\x0b\xfd"G\xf3\xd47\xfb\x97]\x1e\x03\x1e\xac\xbd\xd6+\xfc;\xdbU\xa3\xca\xc3"A *?\x02>S\xb7\x02\xeeE\xdc \xbez\xf8a><l\r6\xe0\xd3\xd9\xb3\xc4 \x12\x90\xebR\x1a\xde\xd5\x084\xbc\x15\xc7\x12\xdf\xfb\xd0\x01WJ;\xc5\x16RT\xc4\xba\xe7}!\xce\x9b\x95\x1e\x9e\xe0\xd6\xc69\xcc^z\xa0\xab\xa8\xdc\xe6\xe4\x05\xcb\x07^\x9bE\xc4M\r\x89\xcc\xfdI\x81\x1f\x9b\x83\x15\x18/\xe4\xb6\xdb|\x14\x87\x9d\xb2\x10\xf1\xef\x996E\x07Y\x8c\xfc<8k\x91}\xc5\x1a\xcd\x0b,\x98\x93\x0f\x01\xf8\xef\x1b\xb4#y\x00\xd3\xc0t\x9c\x08\x99\x8c\xde\n\xd7/\xdf\xd9\x96J\x1do+\x94[\xccp\x15\xfeB=1_\xf9\xb2'  # noqa pylint: disable=line-too-long
        invalid_key = ECCx(b'<\xc4\x92X\xe6\t8\x14Q\xcd\x83\xa7]U\xe4\x0fF\x04=\xfe\xfc\x0eo\xf8_O\x94\xbf\xe1G.@')  # noqa pylint: disable=line-too-long
        with self.assertRaises(UnboundLocalError):
            invalid_key.decrypt(invalid_data)
