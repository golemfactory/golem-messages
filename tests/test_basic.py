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
        msg = message.MessagePing()
        payload = golem_messages.dump(msg, self.ecc.raw_privkey, self.ecc.raw_pubkey)
        msg2 = golem_messages.load(payload, self.ecc.raw_privkey, self.ecc.raw_pubkey)
        self.assertEqual(msg, msg2)

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
        msg = message.MessagePing()

        # Proper timestamp low border
        now = datetime.datetime.utcnow()
        msg.timestamp = dt_to_ts(
            now - (self.mtd * 2) - self.mmtt - (self.mat * 2)
        )
        message.verify_time(msg)

    def test_timestamp_within_range_middle(self):
        msg = message.MessagePing()

        # Proper timestamp inside
        now = datetime.datetime.utcnow()
        msg.timestamp = dt_to_ts(now)
        message.verify_time(msg)

    def test_timestamp_within_range_high(self):
        msg = message.MessagePing()

        # Proper timestamp high border
        now = datetime.datetime.utcnow()
        msg.timestamp = dt_to_ts(now + (self.mtd * 2))
        message.verify_time(msg)

    def test_ancient_timestamp(self):
        msg = message.MessagePing()

        # Message too old
        now = datetime.datetime.utcnow()
        msg.timestamp = dt_to_ts(
            now - (self.mtd * 2) - self.mmtt - (self.mat * 2) - one_second
        )
        with self.assertRaises(exceptions.MessageTooOldError):
            message.verify_time(msg)

    def test_timestamp_from_future(self):
        msg = message.MessagePing()

        # Message from the future
        now = datetime.datetime.utcnow()
        msg.timestamp = dt_to_ts(now + (self.mtd * 2) + one_second)
        with self.assertRaises(exceptions.MessageFromFutureError):
            message.verify_time(msg)

    @mock.patch('golem_messages.message.verify_time')
    def test_deserialization_with_time_verification(self, vft_mock):
        msg = message.MessagePing()
        payload = golem_messages.dump(msg, self.ecc.raw_privkey,
                                      self.ecc.raw_pubkey)
        self.assertEqual(vft_mock.call_count, 0)
        msg2 = golem_messages.load(payload, self.ecc.raw_privkey,
                                   self.ecc.raw_pubkey)
        self.assertEqual(vft_mock.call_count, 1)
