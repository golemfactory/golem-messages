import calendar
import datetime
import enum
import hashlib
import logging
import struct
import time
import warnings

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

    __slots__ = ['header', 'sig']

    HDR_FORMAT = '!HQ?'
    HDR_LEN = struct.calcsize(HDR_FORMAT)
    SIG_LEN = 65
    PAYLOAD_IDX = HDR_LEN + SIG_LEN

    TYPE = None
    ENCRYPT = True
    ENUM_SLOTS = {}

    def __init__(self,
                 header: datastructures.MessageHeader = None,
                 sig=None,
                 slots=None,
                 deserialized=False,
                 **kwargs):

        """Create a new message
        :param deserialized: was message created by .deserialize()?
        """

        # Child message slots
        try:
            self.load_slots(slots)
        except exceptions.FieldError:
            raise
        except Exception as e:
            raise exceptions.MessageError('Load slots failed') from e

        # Set attributes
        for key in kwargs:
            if getattr(self, key, None) is None:
                setattr(self, key, kwargs[key])

        if deserialized and not (header and header.timestamp):
            warnings.warn(
                'Message without header {}'.format(self),
                RuntimeWarning
            )

        # Header
        if header is None:
            header = datastructures.MessageHeader(
                self.TYPE,
                # Since epoch differs between OS, we use calendar.timegm()
                # instead of time.time() to unify it.
                calendar.timegm(time.gmtime()),
                False,
            )
        self.header = header
        self.sig = sig

    def __eq__(self, obj):
        if not isinstance(obj, Message):
            return False
        if not self.TYPE == obj.TYPE:
            return False
        return self.__slots__ == obj.__slots__

    def __repr__(self):
        return "{name}(header={header}, sig={sig}, slots={slots})".format(
            name=self.__class__.__name__,
            header=getattr(self, 'header', None),
            sig=getattr(self, 'sig', None),
            slots=self.slots(),
        )

    @property
    def timestamp(self):
        return self.header.timestamp

    @property
    def encrypted(self):
        return self.header.encrypted

    @encrypted.setter
    def encrypted(self, value):
        self.header = datastructures.MessageHeader(
            self.header.type_,
            self.header.timestamp,
            value,
        )

    def get_short_hash(self, payload=None):
        """Return short message representation for signature
        :return bytes: sha1(TYPE, timestamp, payload)
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

    def serialize_header(self):
        """ Serialize message's header
        H unsigned short (2 bytes) big-endian
        Q unsigned long long (8 bytes) big-endian
        ? bool (1 byte)

        11 bytes in total

        :return: serialized header
        """
        return struct.pack(
            self.HDR_FORMAT,
            self.TYPE,
            self.timestamp,
            self.encrypted,
        )

    def serialize_slot(self, key, value):  # noqa pylint: disable=unused-argument, no-self-use
        if isinstance(value, enum.Enum):
            value = value.value
        return value

    def deserialize_slot(self, key, value):
        if (key in self.ENUM_SLOTS) and (value is not None):
            try:
                value = self.ENUM_SLOTS[key](value)
            except ValueError as e:
                raise exceptions.FieldError(field=key, value=value) from e
        return value

    @classmethod
    def deserialize_header(cls, data):
        """ Deserialize message's header

        :param data: bytes
        :return: datastructures.MessageHeader
        """
        try:
            header = datastructures.MessageHeader(
                *struct.unpack(cls.HDR_FORMAT, data),
            )
        except (struct.error, TypeError) as e:
            raise exceptions.HeaderError() from e

        logger.debug("deserialize_header(): %r", header)
        if not settings.MIN_TIMESTAMP < header.timestamp < \
                settings.MAX_TIMESTAMP:
            raise exceptions.HeaderError(
                "Invalid timestamp {got}. Should be between {min_} and {max_}"
                .format(
                    got=header.timestamp,
                    min_=settings.MIN_TIMESTAMP,
                    max_=settings.MAX_TIMESTAMP,
                )
            )

        from golem_messages.message import registered_message_types

        if header.type_ not in registered_message_types:
            raise exceptions.HeaderError(
                "Invalid type {got}".format(got=header.type_),
            )
        return header

    @classmethod
    def deserialize(cls, msg, decrypt_func, check_time=True, verify_func=None):
        """
        Deserialize single message
        :param str msg: serialized message
        :param function(data) decrypt_func: decryption function
        :return Message|None: deserialized message or none if this message
                              type is unknown
        """

        from golem_messages.message import registered_message_types

        if not msg or len(msg) <= cls.PAYLOAD_IDX:
            raise exceptions.MessageError("Message too short")

        raw_header = msg[:cls.HDR_LEN]
        sig = msg[cls.HDR_LEN:cls.PAYLOAD_IDX]
        data = msg[cls.PAYLOAD_IDX:]

        header = cls.deserialize_header(raw_header)
        if header.encrypted:
            data = decrypt_func(data)
        slots = serializer.loads(data)

        if check_time:
            verify_time(header.timestamp)

        instance = registered_message_types[header.type_](
            header=header,
            sig=sig,
            slots=slots,
            deserialized=True,
        )

        if verify_func is not None:
            verify_func(instance.get_short_hash(data), sig)
        return instance

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
        try:
            verify_slot_type(value, verify_class)
        except TypeError as e:
            raise exceptions.FieldError(field=key, value=value) from e
    return value
