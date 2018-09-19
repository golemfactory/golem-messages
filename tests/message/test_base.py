import datetime
import struct
import unittest
import unittest.mock as mock

from golem_messages import exceptions
from golem_messages.message import base
from golem_messages.register import library


class MessageTestCase(unittest.TestCase):
    def test_decryptions_fails(self):
        # See https://github.com/golemfactory/golem-messages/issues/121
        decrypt = mock.Mock(side_effect=UnboundLocalError)
        header = struct.pack(
            base.Message.HDR_FORMAT,
            library.get_type(base.RandVal),
            int(datetime.datetime.utcnow().timestamp()),
            True,
        )
        with self.assertRaises(exceptions.DecryptionError):
            base.Message.deserialize(
                header+b'*' * 100,
                decrypt,
                check_time=False,
            )
        decrypt.assert_called_once_with(mock.ANY)


@library.register(-1)
class VerifySlotChild(base.Message):
    __slots__ = base.Message.__slots__


@library.register(-2)
class VerifySlotParent(base.Message):
    __slots__ = [
        'child'
    ] + base.Message.__slots__

    @base.verify_slot('child', VerifySlotChild)
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)


@library.register(-3)
class VerifySlotListParent(base.Message):
    __slots__ = [
        'child_list'
    ] + base.Message.__slots__

    @base.verify_slot_list('child_list', VerifySlotChild)
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)


@library.register(-4)
class VerifySlotParentAllowNone(base.Message):
    __slots__ = [
        'child'
    ] + base.Message.__slots__

    @base.verify_slot('child', VerifySlotChild, allow_none=True)
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)


@library.register(-5)
class VerifySlotListParentAllowNone(base.Message):
    __slots__ = [
        'child_list'
    ] + base.Message.__slots__

    @base.verify_slot_list('child_list', VerifySlotChild, allow_none=True)
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)


class VerifySlotTest(unittest.TestCase):
    def setUp(self):
        self.child = VerifySlotChild()

    def test_verify_slot(self):
        msg = VerifySlotParent(slots=[('child', self.child), ])
        self.assertIsInstance(msg.child, VerifySlotChild)

    def test_verify_slot_not_expected_class(self):
        with self.assertRaises(exceptions.FieldError):
            VerifySlotParent(slots=[('child', base.RandVal()), ])

    def test_verify_slot_none_disallowed(self):
        with self.assertRaises(exceptions.FieldError):
            VerifySlotParent(slots=[('child', None), ])

    def test_verify_slot_list(self):
        msg = VerifySlotListParent(slots=[('child_list', [self.child, ]), ])
        self.assertIsInstance(msg.child_list[0], VerifySlotChild)

    def test_verify_slot_list_not_list(self):
        with self.assertRaises(exceptions.FieldError):
            VerifySlotListParent(slots=[('child_list', self.child), ])

    def test_verify_slot_list_not_expected_class(self):
        with self.assertRaises(exceptions.FieldError):
            VerifySlotListParent(slots=[('child_list', [base.RandVal(), ]), ])

    def test_verify_slot_list_none_disallowed(self):
        with self.assertRaises(exceptions.FieldError):
            VerifySlotListParent(slots=[('child_list', [None])])

    def test_verify_slot_none_allowed(self):
        msg = VerifySlotParentAllowNone(slots=[('child', None), ])
        self.assertIsNone(msg.child)

    def test_verify_slot_list_none_allowed(self):
        msg = VerifySlotListParentAllowNone(slots=[('child_list', [None])])
        self.assertIsNone(msg.child_list[0])
