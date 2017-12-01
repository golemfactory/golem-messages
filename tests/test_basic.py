import calendar
import datetime
from freezegun import freeze_time
import golem_messages
from golem_messages import exceptions
from golem_messages import message
import unittest
import unittest.mock as mock

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

    """ Deserialization should work even if we haven't created any message first
    """
    @mock.patch('golem_messages.message.verify_time')
    def test_deserialization(self, verify_time):
        verify_time.return_value = True
        serialized_ping = b'\x03\xe9\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'\
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'\
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'\
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'\
            b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'\
            b'\xd8\x1c\x80'
        deserialized = message.Message.deserialize(serialized_ping, None)
        assert deserialized is not None
        assert deserialized.TYPE == message.Ping.TYPE


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
        message.verify_time(timestamp)

    def test_timestamp_within_range_middle(self):
        """Proper timestamp inside"""

        now = datetime.datetime.utcnow()
        timestamp = dt_to_ts(now)
        message.verify_time(timestamp)

    def test_timestamp_within_range_high(self):
        """Proper timestamp high border"""

        now = datetime.datetime.utcnow()
        timestamp = dt_to_ts(now + (self.mtd * 2))
        message.verify_time(timestamp)

    def test_ancient_timestamp(self):
        """Message too old"""

        now = datetime.datetime.utcnow()
        timestamp = dt_to_ts(
            now - (self.mtd * 2) - self.mmtt - (self.mat * 2) - one_second
        )
        with self.assertRaises(exceptions.MessageTooOldError):
            message.verify_time(timestamp)

    def test_timestamp_from_future(self):
        """Message from the future"""

        now = datetime.datetime.utcnow()
        timestamp = dt_to_ts(now + (self.mtd * 2) + one_second)
        with self.assertRaises(exceptions.MessageFromFutureError):
            message.verify_time(timestamp)

    @mock.patch('golem_messages.message.verify_time')
    def test_deserialization_with_time_verification(self, vft_mock):
        msg = message.Ping()
        payload = golem_messages.dump(msg, self.ecc.raw_privkey,
                                      self.ecc.raw_pubkey)
        self.assertEqual(vft_mock.call_count, 0)
        golem_messages.load(payload, self.ecc.raw_privkey, self.ecc.raw_pubkey)
        self.assertEqual(vft_mock.call_count, 1)


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
        msg2 = message.Message.deserialize(s, decrypt_func=None)
        self.assertIs(msg2, None)


class NestedMessageTestCase(unittest.TestCase):
    def test_valid_task_to_compute(self):
        TEST_SIG = b'jak przystalo na bistro czesto sie zmienia i jest wypisywane na tablicy w lokalu'[:message.Message.SIG_LEN]  # noqa
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
            msg2 = message.Message.deserialize(s, decrypt_func=None)
            self.assertIs(msg2, None)


class ComputeTaskDefTestCase(unittest.TestCase):
    def test_type(self):
        ctd = message.ComputeTaskDef()
        ctd['src_code'] = ("Nie mamy w Polsce monarchy,"
                           "Same w niej golce lub parchy:"
                           "Michalik został nam jeden,"
                           "By sztuki stworzyć w niej Eden."
                           )
        msg = message.TaskToCompute(compute_task_def=ctd)
        s = msg.serialize()
        msg2 = message.Message.deserialize(s, None)
        self.assertEqual(ctd, msg2.compute_task_def)
        self.assertIsInstance(msg2.compute_task_def, message.ComputeTaskDef)
