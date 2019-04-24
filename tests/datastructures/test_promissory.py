
import unittest

from golem_messages import cryptography
from golem_messages import utils
from golem_messages.datastructures import promissory


class PromissoryNoteTest(unittest.TestCase):
    def setUp(self) -> None:
        # some arbitrary keypair and the associated address
        self.privkey = b'\xa9\x85\x1f\xa4\xf2\x17! P\x85\xbb\xce4Ek\xf8' \
                       b'\xa5Fb\xbd"I\xab\x99\x9a\xf3i\xa8\x87)\x18R'

        self.pubkey = b'w\xb3]\xc3\xa2\x90Q\x8b\xe1a`|\xc6\x0bO\xb6SH\x13,' \
                      b'\x17h\xd3Z\x88R\xadK\xd7\xa3K\xe8W\xdf\xfe\xb1\xf4' \
                      b'\xa1\x02\xf7\x06\x0c\x05\xa0\xbb\xbd\xbd\xa5\xfc\x9e' \
                      b'\x8a_%{ \xbd\x12\xe5\r\xdb(6\x8e\x9f'

        # an arbitrary `to` and `amount`
        self.address_to = '0x8bbd87311EA35490B6BE9c7C81e2ae5BCD6f111D'
        self.amount = 667

        # and not so arbitrary `subtask_id` + bytes
        self.subtask_id = '84ef2787-9daa-abad-0a0b-77b35dc3a290'
        self.subtask_id_bytes = b"\x84\xef'\x87\x9d\xaa\xab\xad\n\x0bw\xb3]" \
                                b"\xc3\xa2\x90\x00\x00\x00\x00\x00\x00\x00" \
                                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00"

    @property
    def address_from(self):
        return utils.pubkey_to_address(
            utils.encode_hex(self.pubkey)
        )

    @property
    def promissory_note(self):
        return promissory.PromissoryNote(
            address_from=self.address_from,
            address_to=self.address_to,
            amount=self.amount,
            subtask_id=self.subtask_id,
        )

    def test_hexmsg(self):
        # address_from + address_to + amount + subtask_id
        hexmsg = '0x'\
                 '459bC6422378156c3dbf3d7Ad4ec3411BA488f40' \
                 '8bbd87311EA35490B6BE9c7C81e2ae5BCD6f111D' \
                 '00000000000000000000000000000000' \
                 '0000000000000000000000000000029b' \
                 '84ef27879daaabad0a0b77b35dc3a290' \
                 '00000000000000000000000000000000'
        self.assertEqual(self.promissory_note.hexmsg, hexmsg)

    def test_hash(self):
        pn_hash = b'\xf2Co>E\x1b9)a\x92-\xc8\xd2\x1b0S' \
                   b'\xbe\xc3\\1\xe5!(\xc6~K\xd3\x1f]\xd7Te'
        self.assertEqual(self.promissory_note.hash, pn_hash)

    def test_sign(self):
        sig = self.promissory_note.sign(privkey=self.privkey)
        self.assertIsInstance(sig, promissory.PromissoryNoteSig)
        self.assertIsInstance(sig.v, int)
        self.assertIsInstance(sig.r, bytes)
        self.assertIsInstance(sig.s, bytes)

    def test_sig_valid(self):
        sig = self.promissory_note.sign(privkey=self.privkey)
        self.assertTrue(self.promissory_note.sig_valid(sig))

    def test_not_sig_valid_broken_content(self):
        sig = promissory.PromissoryNote(
            address_from=self.address_from,
            address_to=self.address_from,  # purposefully broken
            amount=self.amount,
            subtask_id=self.subtask_id
        ).sign(
            self.privkey
        )
        self.assertFalse(self.promissory_note.sig_valid(sig))

    def test_not_sig_valid_wrong_signature_key(self):
        sig = self.promissory_note.sign(cryptography.ECCx(None).raw_privkey)
        self.assertFalse(self.promissory_note.sig_valid(sig))

    def test_not_sig_valid_empty(self):
        self.assertFalse(self.promissory_note.sig_valid(None))

    def test_not_sig_valid_corrupted(self):
        with self.assertRaises(TypeError):
            self.promissory_note.sig_valid((1, 2, ))
