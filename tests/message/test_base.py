import datetime
import struct
import unittest
import unittest.mock as mock

from golem_messages import exceptions
from golem_messages.message import base
from golem_messages.register import library

from tests.message import helpers


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


MAX_MESSAGE_ID = 2 ** 16


@library.register(MAX_MESSAGE_ID - 1)
class VerifySlotChild(base.Message):
    __slots__ = base.Message.__slots__


@library.register(MAX_MESSAGE_ID - 2)
class VerifySlotParent(base.Message):
    __slots__ = [
        'child'
    ] + base.Message.__slots__
    MSG_SLOTS = {
        'child': base.MessageSlotDefinition(VerifySlotChild),
    }


@library.register(MAX_MESSAGE_ID - 3)
class VerifySlotListParent(base.Message):
    __slots__ = [
        'child_list'
    ] + base.Message.__slots__
    MSG_SLOTS = {
        'child_list': base.MessageSlotDefinition(VerifySlotChild, is_list=True),
    }


@library.register(MAX_MESSAGE_ID - 4)
class VerifySlotParentAllowNone(base.Message):
    __slots__ = [
        'child'
    ] + base.Message.__slots__
    MSG_SLOTS = {
        'child': base.MessageSlotDefinition(VerifySlotChild, allow_none=True),
    }


@library.register(MAX_MESSAGE_ID - 5)
class VerifySlotListParentAllowNone(base.Message):
    __slots__ = [
        'child_list'
    ] + base.Message.__slots__
    MSG_SLOTS = {
        'child_list': base.MessageSlotDefinition(
            VerifySlotChild,
            is_list=True,
            allow_none=True,
        ),
    }


class VerifySlotTest(unittest.TestCase):
    def setUp(self):
        self.child = VerifySlotChild()

    def test_verify_slot(self):
        msg = VerifySlotParent(slots=[
            ('child', helpers.single_nested(self.child)),
        ])
        self.assertIsInstance(msg.child, VerifySlotChild)

    def test_verify_slot_none_disallowed(self):
        with self.assertRaises(exceptions.FieldError):
            VerifySlotParent(slots=[('child', [False, None]),])

    def test_verify_slot_list(self):
        msg = VerifySlotListParent(
            slots=[
                (
                    'child_list',
                    helpers.list_nested([self.child]),
                ),
            ])
        self.assertIsInstance(msg.child_list[0], VerifySlotChild)

    def test_verify_slot_list_not_list(self):
        with self.assertRaises(exceptions.FieldError):
            helpers.dump_and_load(VerifySlotListParent(
                slots=[
                    ('child_list', helpers.single_nested(self.child)),
                ],
            ))

    def test_verify_slot_list_none_disallowed(self):
        with self.assertRaises(exceptions.FieldError):
            VerifySlotListParent(slots=[('child_list', [False, None])])

    def test_verify_slot_none_allowed(self):
        msg = VerifySlotParentAllowNone(slots=[('child', [False, None]), ])
        self.assertIsNone(msg.child)

    def test_verify_slot_list_none_allowed(self):
        msg = VerifySlotListParentAllowNone(slots=[('child_list', [True, [None]])])
        self.assertIsNone(msg.child_list[0])
