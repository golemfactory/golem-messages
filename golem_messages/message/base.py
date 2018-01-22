import calendar
import datetime
import enum
import hashlib
import logging
import struct
import time

import golem_messages

from golem_messages import datastructures
from golem_messages import exceptions
from golem_messages import serializer
from golem_messages import settings

logger = logging.getLogger('golem.network.transport.message')


def verify_time(timestamp):
    """ Verify message timestamp. If message is to old or has timestamp from
    distant future raise TimestampError.

    NOTE: This method deliberately ignores microseconds - precision=1s
    """
    now = datetime.datetime.utcnow()
    try:
        msgdt = datetime.datetime.utcfromtimestamp(timestamp)
    except (TypeError, OSError, OverflowError, ValueError) as e:
        logger.debug('Error parsing timestamp: %r', timestamp, exc_info=True)
        raise exceptions.TimestampError(str(e))
    delta = now - msgdt
    delta_future = msgdt - now
    logger.debug('msgdt %s Δ %s Δfuture %s', msgdt, delta, delta_future)
    if delta > settings.MSG_TTL:
        raise exceptions.MessageTooOldError()
    if delta_future > settings.FUTURE_TIME_TOLERANCE:
        raise exceptions.MessageFromFutureError()


def _fake_sign(_):
    return b'\0' * Message.SIG_LEN


def verify_slot_type(value, class_):
    if not isinstance(value, (class_, type(None))):
        raise TypeError(
            "Invalid nested message type {} should be {}".format(
                type(value),
                class_
            )
        )


class Message():
    """ Communication message that is sent in all networks """

    __slots__ = ['timestamp', 'encrypted', 'sig', '_raw']

    HDR_LEN = 11
    SIG_LEN = 65
    PAYLOAD_IDX = HDR_LEN + SIG_LEN

    TYPE = None
    ENCRYPT = True
    ENUM_SLOTS = {}

    def __init__(self, timestamp=None, encrypted=False, sig=None,  # noqa TODO #88 pylint: disable=too-many-arguments
                 raw=None, slots=None, deserialized=False, **kwargs):

        """Create a new message
        :param timestamp: message timestamp
        :param encrypted: whether message was encrypted
        :param sig: signed message hash
        :param raw: original message bytes
        :param deserialized: was message created by .deserialize()?
        """

        # Child message slots
        self.load_slots(slots)

        # Set attributes
        for key in kwargs:
            if getattr(self, key, None) is None:
                setattr(self, key, kwargs[key])

        # Header
        if deserialized and not timestamp:
            logger.warning('Message without timestamp %r', self)
        # Since epoch differs between OS, we use calendar.timegm() to unify it
        if not timestamp:
            timestamp = calendar.timegm(time.gmtime())
        self.timestamp = int(timestamp)
        self.encrypted = bool(encrypted)
        self.sig = sig

        # Encoded data
        self._raw = raw  # whole message

    def __eq__(self, obj):
        if not isinstance(obj, Message):
            return False
        if not self.TYPE == obj.TYPE:
            return False
        return self.__slots__ == obj.__slots__

    @property
    def raw(self):
        """Returns a raw copy of the message"""
        return self._raw[:]

    def get_short_hash(self, payload=None):
        """Return short message representation for signature
        :return bytes: sha1(TYPE, timestamp, encrypted, payload)
        """
        if payload is None:
            payload = serializer.dumps(self.slots())
        sha = hashlib.sha1()

        # We can't use self.serialize_header() because it includes
        # self.encrypted. And nested messages are decrypted, but they
        # still need to have a valid signature.
        # SEE: test_serializer.MessageTestCase.test_message_sig()
        hash_header = serializer.dumps(
            [self.TYPE, self.timestamp, ]
        )
        sha.update(hash_header)
        sha.update(payload or b'')
        return sha.digest()

    def serialize(self, sign_func=None, encrypt_func=None):
        """ Return serialized message
        :return str: serialized message """

        if sign_func is None:
            sign_func = _fake_sign

        try:
            self.encrypted = bool(self.ENCRYPT and encrypt_func)
            payload = serializer.dumps(self.slots())

            # When nesting one message inside another it's important
            # not to overwrite original signature.
            if self.sig is None:
                self.sig = sign_func(self.get_short_hash(payload))

            if self.encrypted:
                payload = encrypt_func(payload)

            return (
                self.serialize_header() +
                self.sig +
                payload
            )

        except Exception as exc:
            logger.exception("Error serializing message: %r", exc)
            raise

    def serialize_header(self):
        """ Serialize message's header
        H unsigned short (2 bytes) big-endian
        Q unsigned long long (8 bytes) big-endian
        ? bool (1 byte)

        11 bytes in total

        :return: serialized header
        """
        return struct.pack('!HQ?', self.TYPE,
                           self.timestamp,
                           self.encrypted)

    def serialize_slot(self, key, value):  # noqa pylint: disable=unused-argument, no-self-use
        if isinstance(value, enum.Enum):
            value = value.value
        return value

    def deserialize_slot(self, key, value):
        if (key in self.ENUM_SLOTS) and (value is not None):
            value = self.ENUM_SLOTS[key](value)
        return value

    @classmethod
    def deserialize_header(cls, data):
        """ Deserialize message's header

        :param data: bytes
        :return: datastructures.MessageHeader
        """
        assert len(data) == cls.HDR_LEN
        header = datastructures.MessageHeader(*struct.unpack('!HQ?', data))

        if header.timestamp > 10**10:
            # Old timestamp format. Remove after 0.11 golem core release
            timestamp = header.timestamp // 10**6
            header = datastructures.MessageHeader(header[0], timestamp,
                                                  header[2])

        return header

    @classmethod
    def deserialize(cls, msg, decrypt_func, check_time=True, verify_func=None): # noqa TODO: #52 pylint: disable=inconsistent-return-statements
        """
        Deserialize single message
        :param str msg: serialized message
        :param function(data) decrypt_func: decryption function
        :return Message|None: deserialized message or none if this message
                              type is unknown
        """

        from golem_messages.message import registered_message_types

        if not msg or len(msg) <= cls.PAYLOAD_IDX:
            logger.info("Message error: message too short")
            return  # TODO: #52 pylint: disable=inconsistent-return-statements

        raw_header = msg[:cls.HDR_LEN]
        sig = msg[cls.HDR_LEN:cls.PAYLOAD_IDX]
        data = msg[cls.PAYLOAD_IDX:]

        try:
            header = cls.deserialize_header(raw_header)
            logger.debug("msg_type: %r", header.type_)
            if header.encrypted:
                data = decrypt_func(data)
            slots = serializer.loads(data)
        except Exception as exc:  # pylint: disable=broad-except
            logger.info("Message error: invalid data: %r", exc)
            logger.debug("Failing message hdr: %r data: %r", raw_header, data)
            return  # TODO: #52 pylint: disable=inconsistent-return-statements

        if check_time:
            try:
                verify_time(header.timestamp)
            except exceptions.TimestampError as e:
                logger.info(
                    "Message error: invalid timestamp: %r %s",
                    header.timestamp,
                    e,
                )
                return  # noqa TODO: #52 pylint: disable=inconsistent-return-statements

        if header.type_ not in registered_message_types:
            logger.info('Message error: invalid type %d', header.type_)
            return  # TODO: #52 pylint: disable=inconsistent-return-statements

        try:
            instance = registered_message_types[header.type_](
                timestamp=header.timestamp,
                encrypted=header.encrypted,
                sig=sig,
                raw=msg,
                slots=slots,
                deserialized=True,
            )
        except Exception as exc:  # pylint: disable=broad-except
            logger.info("Message error: invalid data: %r", exc)
            return  # TODO: #52 pylint: disable=inconsistent-return-statements
        if verify_func is not None:
            try:
                verify_func(instance.get_short_hash(data), sig)
            except Exception:
                logger.debug('Failed to verify signature: %r', instance)
                raise
        return instance

    def __repr__(self):
        return "{}(timestamp={}, encrypted={}, sig={}, slots={})".format(
            self.__class__.__name__,
            getattr(self, 'timestamp', None),
            getattr(self, 'encrypted', None),
            getattr(self, 'sig', None),
            self.slots(),
        )

    def load_slots(self, slots):
        try:
            slots_dict = dict(slots)
        except (TypeError, ValueError):
            slots_dict = {}

        for name in self.__slots__:
            if hasattr(self, name):
                continue
            if not self.valid_slot(name):
                continue

            try:
                value = slots_dict[name]
            except KeyError:
                value = None
            else:
                value = self.deserialize_slot(name, value)
            setattr(self, name, value)

    def slots(self):
        """Returns a list representation of any subclass message"""
        processed_slots = []
        for key in self.__slots__:
            if not self.valid_slot(key):
                continue
            value = getattr(self, key, None)
            value = self.serialize_slot(key, value)
            processed_slots.append([key, value])
        return processed_slots

    def valid_slot(self, name):
        return (name not in Message.__slots__) and (name in self.__slots__)


class AbstractReasonMessage(Message):
    __slots__ = [
        'reason',
    ] + Message.__slots__

    @property
    def ENUM_SLOTS(self):
        return {
            'reason': self.REASON,
        }


##################
# Basic Messages #
##################


class Hello(Message):
    TYPE = 0
    ENCRYPT = False

    __slots__ = [
        'rand_val',
        'proto_id',
        'golem_messages_version',
        'node_name',
        'node_info',
        'port',
        'client_ver',
        'client_key_id',
        'solve_challenge',
        'challenge',
        'difficulty',
        'metadata',
    ] + Message.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        deserialized = kwargs.pop('deserialized', False)
        if not deserialized and self.golem_messages_version is None:
            self.golem_messages_version = golem_messages.__version__


class RandVal(Message):
    """Message with signed random value"""

    TYPE = 1

    __slots__ = ['rand_val'] + Message.__slots__


class Disconnect(AbstractReasonMessage):
    TYPE = 2
    ENCRYPT = False

    __slots__ = AbstractReasonMessage.__slots__

    class REASON(enum.Enum):
        DuplicatePeers = 'duplicate_peers'
        TooManyPeers = 'too_many_peers'
        Refresh = 'refresh'
        Unverified = 'unverified'
        ProtocolVersion = 'protocol_version'
        BadProtocol = 'bad_protocol'
        Timeout = 'timeout'
        NoMoreMessages = 'no_more_messages'
        WrongEncryption = 'wrong_encryption'
        ResourceHandshakeFailure = 'resource_handshake'
        KeyNotDifficult = 'key_not_difficult'
        Bootstrap = 'bootstrap'


class ChallengeSolution(Message):
    TYPE = 3

    __slots__ = ['solution'] + Message.__slots__


def deserialize_verify(key, value, verify_key, verify_class):
    if key == verify_key:
        verify_slot_type(value, verify_class)
    return value
