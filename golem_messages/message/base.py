import calendar
import datetime
import enum
import functools
import hashlib
import logging
import struct
import time
import warnings

import semantic_version

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
        raise exceptions.MessageTooOldError(
            "delta {} > {}".format(delta, settings.MSG_TTL),
        )
    if delta_future > settings.FUTURE_TIME_TOLERANCE:
        raise exceptions.MessageFromFutureError(
            "delta_future {} > {}".format(
                delta_future,
                settings.FUTURE_TIME_TOLERANCE
            ),
        )


def _fake_sign(_):
    return b'\0' * Message.SIG_LEN


def verify_version(msg_version):
    try:
        theirs_v = semantic_version.Version(msg_version)
    except ValueError as e:
        raise exceptions.VersionMismatchError(
            "Invalid version received: {msg_version}".format(
                msg_version=msg_version,
            )
        ) from e
    ours_v = semantic_version.Version(golem_messages.__version__)
    spec_str = '>={major}.{minor}.0,<{next_minor}'.format(
        major=ours_v.major,
        minor=ours_v.minor,
        next_minor=ours_v.next_minor(),
    )
    spec = semantic_version.Spec(spec_str)
    if theirs_v not in spec:
        raise exceptions.VersionMismatchError(
            "Incompatible version received:"
            " {ours} (ours) != {theirs} (theirs)".format(
                ours=ours_v,
                theirs=theirs_v,
            )
        )


def _verify_slot_type(value, class_):
    if not isinstance(value, (class_, type(None))):
        raise TypeError(
            "Invalid nested message type {} should be {}".format(
                type(value),
                class_
            )
        )


def _validate_slot(key, value, verify_class):
    try:
        _verify_slot_type(value, verify_class)
    except TypeError as e:
        raise exceptions.FieldError(
            "Should an instance of {should_be} not {is_now}".format(
                should_be=verify_class,
                is_now=type(value),
            ),
            field=key,
            value=value,
        ) from e


def deserialize_verify(key, value, verify_key, verify_class):
    if key == verify_key:
        _validate_slot(key, value, verify_class)
    return value


def deserialize_verify_list(key, value, verify_key, verify_class):
    if key == verify_key:
        try:
            for v in value:
                _validate_slot(key, v, verify_class)
        except TypeError as e:
            raise exceptions.FieldError(
                "Should be a list of {verify_class}".format(
                    verify_class=verify_class,
                ),
                field=key,
                value=value,
            ) from e
    return value


def verify_slot(slot_name, slot_class):
    """
    decorator for Message's `deserialize_slot` method
    ensures that the slot identified by `slot_name` is an instance of the
    message class given in `slot_class`

    :param slot_name: the name of the slot
    :param slot_class: the class to check against
    :return: the verified value
    :raises: FieldError

    :Example:

        @base.verify_slot('wrapped_msg', WrappedMessageClass)
        def deserialize_slot(self, key, value):
            return super().deserialize_slot(key, value)

    """
    def deserialize_slot(method):
        @functools.wraps(method)
        def _(self, key, value):
            return functools.partial(
                deserialize_verify,
                verify_key=slot_name,
                verify_class=slot_class,
            )(
                key, method(self, key, value)
            )
        return _
    return deserialize_slot


def verify_slot_list(slot_name, item_class):
    """
    decorator for Message's `deserialize_slot` method
    ensures that the slot identified by `slot_name` is a list of messages with
    the given instance type (provided in `item_class`)

    :param slot_name: the name of the slot to verify
    :param item_class: the class to check list items against
    :return: the verified value
    :raises: FieldError
    """

    def deserialize_slot(method):
        @functools.wraps(method)
        def _(self, key, value):
            return functools.partial(
                deserialize_verify_list,
                verify_key=slot_name,
                verify_class=item_class,
            )(
                key, method(self, key, value)
            )
        return _
    return deserialize_slot


class Message():
    """ Communication message that is sent in all networks """

    __slots__ = ['header', 'sig']

    HDR_FORMAT = '!HQ?'
    HDR_LEN = struct.calcsize(HDR_FORMAT)
    SIG_LEN = 65

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
        if not self.header == obj.header:
            return False
        if not self.sig == obj.sig:
            return False
        return self.slots() == obj.slots()

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
        elif self.sig is not None:
            # If you wish to overwrite signature,
            # first set it to None explicitly
            raise exceptions.SignatureAlreadyExists()

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
                raise exceptions.FieldError(
                    "Invalid value for enum slot",
                    field=key,
                    value=value,
                ) from e
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
                "Unknown message type {got}".format(got=header.type_),
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

        if not msg or len(msg) <= cls.HDR_LEN + cls.SIG_LEN:
            raise exceptions.MessageError("Message too short")

        raw_header = msg[:cls.HDR_LEN]
        data = msg[cls.HDR_LEN:]

        header = cls.deserialize_header(raw_header)
        if check_time:
            verify_time(header.timestamp)

        class_ = registered_message_types[header.type_]
        return class_.deserialize_with_header(
            header,
            data,
            decrypt_func,
            verify_func,
        )

    @classmethod
    def deserialize_with_header(cls, header, data, decrypt_func, verify_func,
                                **kwargs):
        sig = data[:cls.SIG_LEN]
        payload = data[cls.SIG_LEN:]

        if header.encrypted:
            try:
                payload = decrypt_func(payload)
            except exceptions.MessageError:
                raise
            except Exception as e:
                raise exceptions.DecryptionError(
                    "Unknown decryption problem"
                ) from e
        slots = serializer.loads(payload)

        instance = cls(
            header=header,
            sig=sig,
            slots=slots,
            deserialized=True,
            **kwargs,
        )

        if verify_func is not None:
            verify_func(instance.get_short_hash(payload), sig)
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
        return (not name.startswith('_')) \
            and (name not in Message.__slots__) \
            and (name in self.__slots__)


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
    VERSION_FORMAT = '!32p'
    VERSION_LENGTH = struct.calcsize(VERSION_FORMAT)

    __slots__ = [
        'rand_val',
        'proto_id',
        'node_name',
        'node_info',
        'port',
        'client_ver',
        'client_key_id',
        'solve_challenge',
        'challenge',
        'difficulty',
        'metadata',
        '_version',
    ] + Message.__slots__

    @classmethod
    def deserialize_with_header(cls, header, data, *args, **kwargs):  # noqa pylint: disable=arguments-differ
        raw_version = data[-cls.VERSION_LENGTH:]
        data = data[:-cls.VERSION_LENGTH]
        try:
            str_version = struct.unpack(cls.VERSION_FORMAT, raw_version)[0] \
                .decode('ascii', 'replace')
        except struct.error as e:
            raise exceptions.VersionMismatchError(
                "Unreadable version {raw_version}".format(
                    raw_version=raw_version,
                )
            ) from e
        verify_version(str_version)
        instance = super().deserialize_with_header(
            header,
            data,
            _version=str_version,
            *args,
            **kwargs,
        )
        return instance

    def serialize(self, *args, **kwargs):  # pylint: disable=arguments-differ
        serialized = super().serialize(*args, **kwargs)
        version = struct.pack(
            self.VERSION_FORMAT,
            self._version.encode('ascii', 'replace')
        )
        return serialized + version

    def get_short_hash(self, *args, **kwargs):  # noqa pylint: disable=arguments-differ
        return super().get_short_hash(*args, **kwargs) \
            + self._version.encode('ascii', 'replace')

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        deserialized = kwargs.pop('deserialized', False)
        if not deserialized and not hasattr(self, '_version'):
            self._version = golem_messages.__version__

    def __repr__(self):
        return "<{} _version:{}>".format(
            super().__repr__(),
            getattr(self, '_version', '<undefined>'),
        )

    def __eq__(self, obj):
        if not self._version == getattr(obj, '_version', None):
            return False
        return super().__eq__(obj)


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
