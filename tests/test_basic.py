# pylint: disable=protected-access
import calendar
import datetime
import unittest
import unittest.mock as mock

import semantic_version
from freezegun import freeze_time

import golem_messages
from golem_messages import exceptions
from golem_messages import message
from golem_messages import serializer

one_second = datetime.timedelta(seconds=1)


def dt_to_ts(dt):
    return calendar.timegm(dt.utctimetuple())


class BasicTestCase(unittest.TestCase):
    def setUp(self):
        self.ecc = golem_messages.ECCx(None)
        self.ecc2 = golem_messages.ECCx(None)

    def test_total_basic(self):
        msg = message.Ping()
        payload = golem_messages.dump(msg, self.ecc.raw_privkey,
                                      self.ecc.raw_pubkey)
        msg2 = golem_messages.load(payload, self.ecc.raw_privkey,
                                   self.ecc.raw_pubkey)
        self.assertEqual(msg, msg2)

    def test_equality(self):
        msg1 = message.RandVal(rand_val=1)
        golem_messages.dump(msg1, self.ecc.raw_privkey, None)  # sign
        msg2 = message.RandVal(
            header=msg1.header,
            sig=msg1.sig,
            slots=msg1.slots(),
        )
        self.assertIsNot(msg1, msg2)
        self.assertEqual(msg1, msg2)

    def test_inequal_slots(self):
        msg1 = message.RandVal(rand_val=1)
        msg2 = message.RandVal(rand_val=2)
        self.assertNotEqual(msg1, msg2)

    def test_inequal_header(self):
        msg1 = message.Ping()
        msg2 = message.Ping()
        msg2.encrypted = True
        self.assertNotEqual(msg1, msg2)

    def test_inequal_sig(self):
        msg1 = message.Ping()
        msg1.sig = 1
        msg2 = message.Ping()
        msg2.sig = 2
        self.assertNotEqual(msg1, msg2)

    def test_deserialization(self):
        """Deserialization should work even if we haven't created any messages
        """
        serialized_ping = message.p2p.Ping().serialize()
        deserialized = message.Message.deserialize(serialized_ping, None)
        self.assertIsInstance(deserialized, message.p2p.Ping)

    @mock.patch('golem_messages.serializer.dumps', wraps=serializer.dumps)
    def test_slots_reselialization_optimization(self, dumps_mock):
        """Don't reserialize message slots immediately after deserialization"""
        msg = message.p2p.Ping()
        payload = golem_messages.dump(msg, self.ecc.raw_privkey,
                                      self.ecc.raw_pubkey)
        # One call for slots and second for hash_header
        self.assertEqual(dumps_mock.call_count, 2)

        dumps_mock.reset_mock()
        golem_messages.load(payload, self.ecc.raw_privkey, self.ecc.raw_pubkey)
        # One call for hash_header
        dumps_mock.assert_called_once_with(mock.ANY)

    def test_deserialize_verify(self):
        """Basic verificating deserializer"""
        ping = message.Ping()
        result = message.base.deserialize_verify(
            key='ping',
            verify_key='ping',
            value=ping,
            verify_class=message.Ping,
        )
        self.assertEqual(result, ping)

    def test_deserialize_verify_different_key(self):
        task_to_compute = message.TaskToCompute()
        result = message.base.deserialize_verify(
            key='abracadabra',
            verify_key='ping',
            value=task_to_compute,
            verify_class=message.Ping,
        )
        self.assertEqual(result, task_to_compute)

    def test_deserialize_verify_fail(self):
        task_to_compute = message.TaskToCompute()
        with self.assertRaises(exceptions.FieldError):
            message.base.deserialize_verify(
                key='ping',
                verify_key='ping',
                value=task_to_compute,
                verify_class=message.Ping,
            )

    @mock.patch('golem_messages.__version__')
    def test_hello_version(self, v_mock):
        msg = message.Hello()
        self.assertEqual(msg._version, v_mock)

        msg = message.Hello(deserialized=True)
        self.assertFalse(hasattr(msg, '_version'))

        version_kwarg = object()
        msg_kwarg = message.Hello(_version=version_kwarg)
        self.assertEqual(msg_kwarg._version, version_kwarg)

        version_slot = object()
        msg_slot = message.Hello(
            slots=[('_version', version_slot), ],
        )
        # Slots with '_' should be ignored
        self.assertEqual(msg_slot._version, v_mock)

    @mock.patch('golem_messages.message.base.verify_version')
    def test_hello_version_verify(self, v_mock):
        msg = message.Hello()
        serialized = golem_messages.dump(
            msg,
            self.ecc.raw_privkey,
            self.ecc.raw_pubkey,
        )
        golem_messages.load(
            serialized,
            self.ecc.raw_privkey,
            self.ecc.raw_pubkey,
        )
        v_mock.assert_called_once_with(golem_messages.__version__)

    def test_hello_version_signature(self):
        msg = message.Hello()
        serialized = golem_messages.dump(
            msg,
            self.ecc.raw_privkey,
            self.ecc.raw_pubkey,
        )
        msg = golem_messages.load(
            serialized,
            self.ecc.raw_privkey,
            self.ecc.raw_pubkey,
        )
        msg._version = 'haxior'
        with self.assertRaises(exceptions.InvalidSignature):
            self.ecc.verify(msg.sig, msg.get_short_hash())

    @mock.patch('golem_messages.message.base.Message.__eq__')
    def test_hello_version_equality(self, eq_mock):
        eq_mock.return_value = True
        msg1 = message.Hello()
        msg2 = message.Hello()
        self.assertEqual(msg1, msg2)
        eq_mock.assert_called_once_with(msg2)

    @mock.patch('golem_messages.message.base.Message.__eq__')
    def test_hello_version_inequality(self, eq_mock):
        msg1 = message.Hello()
        msg2 = message.Hello()
        msg2._version = 'haxior'
        self.assertNotEqual(msg1, msg2)
        eq_mock.assert_not_called()

    @mock.patch("golem_messages.message.base.RandVal")
    def test_init_messages_error(self, mock_message_rand_val):
        copy_registered = dict(message.registered_message_types)
        message.registered_message_types = {}
        mock_message_rand_val.__name__ = "randvalmessage"
        mock_message_rand_val.TYPE = message.Hello.TYPE
        with self.assertRaises(RuntimeError):
            message.init_messages()
        message.registered_message_types = copy_registered

    def test_slots(self):
        for cls in message.registered_message_types.values():
            # only __slots__ can be present in objects
            self.assertFalse(
                hasattr(cls(), '__dict__'),
                "{} instance has __dict__".format(cls)
            )
            assert not hasattr(cls.__new__(cls), '__dict__')
            # slots are properly set in class definition
            assert len(cls.__slots__) >= len(message.Message.__slots__)

    def test_deserialize_old_timestamp(self):
        import struct
        raw_header = struct.pack('!HQ?', 1, 1516272285269707, False)
        with self.assertRaises(exceptions.HeaderError):
            message.base.Message.deserialize_header(raw_header)

    def test_signature_overwriting(self):
        msg = message.p2p.Ping()

        # First signature generated
        serialized = msg.serialize()
        msg2 = message.base.Message.deserialize(serialized, None)
        self.assertIsNotNone(msg2.sig)

        # Serialization with default sig_func should succeed
        msg2.serialize()

        with self.assertRaises(exceptions.SignatureAlreadyExists):
            golem_messages.dump(msg, self.ecc.raw_privkey, self.ecc.raw_pubkey)


testnow = datetime.datetime.utcnow().replace(microsecond=0)


@freeze_time(testnow)
class TimestampTestCase(unittest.TestCase):
    """Time limits verification

    Based on Concent_analiza_integracji_PL "Limity czasu w komunikacji" chapter
    """

    def setUp(self):
        self.ecc = golem_messages.ECCx(None)
        # mmtt - Maximum Message Transport Time, maximum transport time
        #        allowed for transmission of a small message (if ping time is
        #        greater than this, it means the communication is lagged).
        self.mmtt = datetime.timedelta(minutes=0, seconds=30)
        # mtd - Maximum Time Difference, maximum time difference from actual
        #       time. (Time synchronisation)
        self.mtd = datetime.timedelta(minutes=2, seconds=30)
        # mat - Maximum Action Time, maximum time needed to perform simple
        #       simple machine operation.
        self.mat = datetime.timedelta(minutes=2, seconds=15)

    def test_timestamp_within_range_low(self):
        """Proper timestamp low border"""

        now = datetime.datetime.utcnow()
        timestamp = dt_to_ts(
            now - (self.mtd * 2) - self.mmtt - (self.mat * 2)
        )
        message.base.verify_time(timestamp)

    def test_timestamp_within_range_middle(self):  # pylint: disable=no-self-use
        """Proper timestamp inside"""

        now = datetime.datetime.utcnow()
        timestamp = dt_to_ts(now)
        message.base.verify_time(timestamp)

    def test_timestamp_within_range_high(self):
        """Proper timestamp high border"""

        now = datetime.datetime.utcnow()
        timestamp = dt_to_ts(now + (self.mtd * 2))
        message.base.verify_time(timestamp)

    def test_ancient_timestamp(self):
        """Message too old"""

        now = datetime.datetime.utcnow()
        timestamp = dt_to_ts(
            now - (self.mtd * 2) - self.mmtt - (self.mat * 2) - one_second
        )
        with self.assertRaises(exceptions.MessageTooOldError):
            message.base.verify_time(timestamp)

    def test_timestamp_from_future(self):
        """Message from the future"""

        now = datetime.datetime.utcnow()
        timestamp = dt_to_ts(now + (self.mtd * 2) + one_second)
        with self.assertRaises(exceptions.MessageFromFutureError):
            message.base.verify_time(timestamp)

    @mock.patch('golem_messages.message.base.verify_time')
    def test_deserialization_with_time_verification(self, vft_mock):
        msg = message.Ping()
        payload = golem_messages.dump(msg, self.ecc.raw_privkey,
                                      self.ecc.raw_pubkey)
        self.assertEqual(vft_mock.call_count, 0)
        golem_messages.load(payload, self.ecc.raw_privkey, self.ecc.raw_pubkey)
        self.assertEqual(vft_mock.call_count, 1)

    @mock.patch('datetime.datetime.utcfromtimestamp')
    def test_year_is_out_of_range(self, timestamp_mock):
        for err in (TypeError, OSError, OverflowError, ValueError):
            timestamp_mock.side_effect = err
            with self.assertRaises(exceptions.TimestampError):
                msg = message.Ping()
                message.base.verify_time(msg.timestamp)


class SlotSerializationTestCase(unittest.TestCase):
    def test_enum_slots(self):
        msg = message.Disconnect(
            reason=message.Disconnect.REASON.DuplicatePeers
        )
        s = msg.serialize()
        msg2 = message.Message.deserialize(s, decrypt_func=None)
        self.assertIs(msg2.reason,
                      message.Disconnect.REASON.DuplicatePeers)

    def test_enum_slot_by_value(self):
        msg = message.Disconnect(
            reason='duplicate_peers'
        )
        s = msg.serialize()
        msg2 = message.Message.deserialize(s, decrypt_func=None)
        self.assertIs(msg2.reason,
                      message.Disconnect.REASON.DuplicatePeers)

    def test_enum_slot_invalid_value(self):
        msg = message.Disconnect(
            reason='Every man is the builder of a temple called his body. —HDT'
        )
        s = msg.serialize()
        with self.assertRaises(exceptions.FieldError):
            message.Message.deserialize(s, decrypt_func=None)


class NestedMessageTestCase(unittest.TestCase):
    def test_valid_task_to_compute(self):
        TEST_SIG = (b'jak przystalo na bistro czesto sie zmienia'
                    b'i jest wypisywane na tablicy w lokalu'
                   )[:message.Message.SIG_LEN]  # noqa
        for class_ in message.registered_message_types.values():
            if 'task_to_compute' not in class_.__slots__:
                continue
            msg = class_()
            msg.task_to_compute = message.TaskToCompute(sig=TEST_SIG)
            msg.task_to_compute.compute_task_def = message.ComputeTaskDef()
            s = msg.serialize()
            msg2 = message.Message.deserialize(s, decrypt_func=None)
            self.assertEqual(msg2.task_to_compute.sig, TEST_SIG)

    def test_invalid_task_to_compute(self):
        for class_ in message.registered_message_types.values():
            if 'task_to_compute' not in class_.__slots__:
                continue
            msg = class_()
            msg.task_to_compute = (
                "There’s so much to learn when you’re slinging"
                "paint and pencil"
            )
            s = msg.serialize()
            with self.assertRaises(exceptions.FieldError):
                message.Message.deserialize(s, decrypt_func=None)

    def test_reject_report_computed_task_with_cannot_compute_task(self):
        msg = message.RejectReportComputedTask()
        msg.reason = message.RejectReportComputedTask.REASON.GotMessageCannotComputeTask  # noqa
        msg.cannot_compute_task = message.CannotComputeTask()
        msg.cannot_compute_task.reason =\
            message.CannotComputeTask.REASON.WrongCTD
        msg.cannot_compute_task.task_to_compute = message.TaskToCompute()
        invalid_deadline = ("You call it madness, "
                            "but I call it Love -- Nat King Cole")
        msg.cannot_compute_task.task_to_compute.compute_task_def =\
            message.ComputeTaskDef({'deadline': invalid_deadline, })
        s = msg.serialize()
        msg2 = message.Message.deserialize(s, None)
        self.assertEqual(
            msg2.cannot_compute_task.task_to_compute.compute_task_def['deadline'],  # noqa
            invalid_deadline
        )


class ComputeTaskDefTestCase(unittest.TestCase):
    def test_type(self):
        ctd = message.ComputeTaskDef()
        ctd['src_code'] = "custom code"
        msg = message.TaskToCompute(compute_task_def=ctd)
        s = msg.serialize()
        msg2 = message.Message.deserialize(s, None)
        self.assertEqual(ctd, msg2.compute_task_def)
        self.assertIsInstance(msg2.compute_task_def, message.ComputeTaskDef)


gm_version = semantic_version.Version(golem_messages.__version__)


class VerifyVersionTestCase(unittest.TestCase):
    # pylint: disable=expression-not-assigned
    def test_golem_messages_version_higher_minor(self):
        with self.assertRaises(exceptions.VersionMismatchError):
            message.base.verify_version(
                str(gm_version.next_minor()),
            ),

    def test_golem_messages_version_higher_patch(self):
        self.assertIsNone(
            message.base.verify_version(
                str(gm_version.next_patch()),
            ),
        )

    def test_golem_messages_version_equal(self):
        self.assertIsNone(
            message.base.verify_version(
                str(gm_version),
            ),
        )

    def test_golem_messages_version_lower_patch(self):
        with mock.patch.object(golem_messages, '__version__', new='1.1.1'):
            self.assertIsNone(
                message.base.verify_version(
                    '1.1.2',
                ),
            )

    def test_golem_messages_version_lower_minor(self):
        with mock.patch.object(golem_messages, '__version__', new='1.1.1'):
            with self.assertRaises(exceptions.VersionMismatchError):
                message.base.verify_version(
                    '1.0.9',
                ),

    def test_golem_messages_version_None(self):
        with mock.patch.object(golem_messages, '__version__', new='1.1.1'):
            with self.assertRaises(exceptions.VersionMismatchError):
                message.base.verify_version(
                    None,
                ),

    def test_golem_messages_version_invalid(self):
        with mock.patch.object(golem_messages, '__version__', new='1.1.1'):
            with self.assertRaises(exceptions.VersionMismatchError):
                message.base.verify_version(
                    ('Czy to bajka, czy nie bajka,'
                     'Myślcie sobie, jak tam chcecie.'),
                ),
    # pylint: enable=expression-not-assigned
