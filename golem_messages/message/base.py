import calendar
import collections
import datetime
import enum
import hashlib
import logging
import struct
import time
import warnings
import typing

import semantic_version

import golem_messages

from golem_messages import cryptography
from golem_messages import datastructures
from golem_messages import exceptions
from golem_messages import serializer
from golem_messages import settings
from golem_messages.datastructures import p2p as dt_p2p
from golem_messages.register import library

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


class Message():
    """ Communication message that is sent in all networks """

    __slots__ = ['header', 'sig']

    HDR_FORMAT = '!HQ?'
    HDR_LEN = struct.calcsize(HDR_FORMAT)
    SIG_LEN = 65

    ENCRYPT = True
    SIGN = True
    ENUM_SLOTS = {}
    MSG_SLOTS = {}

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
                try:
                    setattr(self, key, kwargs[key])
                except AttributeError:
                    raise AttributeError(
                        "Can't set attribute `%s` on `%s`" % (
                            key, self.__class__.__name__))

        if deserialized and not (header and header.timestamp):
            warnings.warn(
                'Message without header {}'.format(self),
                RuntimeWarning
            )

        # Header
        if header is None:
            header = datastructures.MessageHeader(
                library.get_type(self.__class__),
                # On AppVeyorCI time.time() returns unreliable values thus
                # we use calendar.timegm() instead of time.time() to unify it.
                calendar.timegm(time.gmtime()),
                False,
            )
        self.header = header
        self.sig = sig

    def __eq__(self, obj):
        """
        for the equality check, we're concerned with the message type,
        timestamp, and most importantly its content and signature

        we're specifically ignoring the `encrypted` flag as it doesn't
        pertain to the message's content but rather to its mode of transport
        """

        return (
            self.__class__ is obj.__class__
            and self.header.type_ == obj.header.type_
            and self.timestamp == obj.timestamp
            and self.sig == obj.sig
            and self.slots() == obj.slots()
        )

    def __repr__(self):
        try:
            slots_ = self.slots()
        except exceptions.FieldError:
            slots_ = '<unserializable>'
        template = "{name!r}(header={header!r}, sig={sig!r}, slots={slots!r})"
        return template.format(
            name=self.__class__.__name__,
            header=getattr(self, 'header', None),
            sig=getattr(self, 'sig', None),
            slots=slots_,
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

    def get_short_hash(self, payload=None) -> bytes:
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
            [self.header.type_, self.timestamp, ]
        )
        sha.update(hash_header)
        sha.update(payload or b'')
        return sha.digest()

    def serialize(
            self,
            sign_as: typing.Optional[bytes] = None,
            encrypt_func=None,
    ) -> bytes:
        """Returns serialized message"""

        if sign_as and self.sig:
            # If you wish to overwrite signature,
            # first set it to None explicitly
            raise exceptions.SignatureAlreadyExists()

        self.encrypted = bool(self.ENCRYPT and encrypt_func)
        payload = serializer.dumps(self.slots())

        # When nesting one message inside another it's important
        # not to overwrite original signature.
        if self.sig is None:
            if sign_as and self.SIGN:
                self.sign_message(
                    private_key=sign_as,
                    msg_hash=self.get_short_hash(payload)
                )
            else:
                self._fake_sign()

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
            library.get_type(self.__class__),
            self.timestamp,
            self.encrypted,
        )

    def serialize_slot(self, key, value):
        if isinstance(value, enum.Enum):
            return value.value
        if key in self.MSG_SLOTS:
            return self.serialize_message(key, value)
        return value

    def serialize_message(self, key, value):
        slot_definition: MessageSlotDefinition = self.MSG_SLOTS[key]
        if value is None:
            if not slot_definition.allow_none:
                raise exceptions.FieldError(
                    "Disallowed None for message slot",
                    field=key,
                    value=value,
                )
            return False, None

        if not isinstance(value, list):
            return False, self.serialize_message_single(key, value)
        return True, [self.serialize_message_single(key, msg) for msg in value]

    def serialize_message_single(self, key, value):
        slot_definition = self.MSG_SLOTS[key]
        if not isinstance(value, slot_definition.klass):
            raise exceptions.FieldError(
                "Should be instance of {}".format(slot_definition.klass),
                field=key,
                value=value,
            )
        return value.header, value.sig, value.slots()

    def deserialize_slot(self, key, value):
        if (key in self.ENUM_SLOTS) and (value is not None):
            try:
                return self.ENUM_SLOTS[key](value)
            except ValueError as e:
                raise exceptions.FieldError(
                    "Invalid value for enum slot",
                    field=key,
                    value=value,
                ) from e
        if key in self.MSG_SLOTS:
            return self.deserialize_message(key, value)
        return value

    def deserialize_message(self, key, value):
        slot_definition: MessageSlotDefinition = self.MSG_SLOTS[key]
        try:
            is_list, value = value
        except (TypeError, ValueError):
            raise exceptions.FieldError(
                "Invalid nested message format",
                field=key,
                value=value,
            )

        if value and (is_list != slot_definition.is_list):
            raise exceptions.FieldError(
                "Invalid nested message format (is_list: {})".format(
                    slot_definition.is_list,
                ),
                field=key,
                value=value,
            )
        if value and is_list:
            if not isinstance(value, list):
                raise exceptions.FieldError(
                    "Should be List[{}]".format(slot_definition.klass),
                    field=key,
                    value=value,
                )
            result = [
                self.deserialize_message_single(key, serialized_msg)
                for serialized_msg
                in value
            ]
            return result

        return self.deserialize_message_single(key, value)

    def deserialize_message_single(self, key, value):
        slot_definition: MessageSlotDefinition = self.MSG_SLOTS[key]
        if value is None:
            if not slot_definition.allow_none:
                raise exceptions.FieldError(
                    "Disallowed None for message slot",
                    field=key,
                    value=value,
                )
            return None
        try:
            nested = datastructures.NestedMessage(*value)
        except TypeError:
            raise exceptions.FieldError(
                "Invalid nested message format",
                field=key,
                value=value,
            )
        try:
            result = slot_definition.klass(
                header=datastructures.MessageHeader(*nested.header),
                sig=nested.sig,
                slots=nested.slots,
            )
        except exceptions.FieldError:
            raise
        except Exception as e:
            raise exceptions.FieldError(
                "Invalid value for message slot",
                field=key,
                value=value,
            ) from e
        return result

    @classmethod
    def unpack_header(cls, data: bytes) -> datastructures.MessageHeader:
        """Unpack message's header"""
        try:
            header = datastructures.MessageHeader(
                *struct.unpack(cls.HDR_FORMAT, data),
            )
        except (struct.error, TypeError) as e:
            raise exceptions.HeaderError() from e
        return header

    @classmethod
    def deserialize_header(cls, data):
        """ Deserialize message's header

        :param data: bytes
        :return: datastructures.MessageHeader
        """

        header = cls.unpack_header(data)
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

        if header.type_ not in library:
            raise exceptions.HeaderError(
                "Unknown message type {got}".format(got=header.type_),
            )
        return header

    @classmethod
    def deserialize(cls, msg,
                    decrypt_func,
                    check_time=True,
                    sender_public_key: typing.Optional[bytes] = None):
        """
        Deserialize single message
        :param str msg: serialized message
        :param bool check_time: whether the message's timestamp
                                should be validated
        :param function(data) decrypt_func: decryption function
        :param bytes sender_public_key: if specified, sender's public key
                                against which the signature is verified
        :return Message|None: deserialized message or none if this message
                              type is unknown
        """

        if not msg or len(msg) <= cls.HDR_LEN + cls.SIG_LEN:
            raise exceptions.MessageError("Message too short")

        raw_header = msg[:cls.HDR_LEN]
        data = msg[cls.HDR_LEN:]

        header = cls.deserialize_header(raw_header)
        if check_time:
            verify_time(header.timestamp)

        class_ = library[header.type_]
        return class_.deserialize_with_header(
            header,
            data,
            decrypt_func,
            sender_public_key=sender_public_key,
        )

    @classmethod
    def deserialize_with_header(
            cls, header, data,
            decrypt_func, sender_public_key: typing.Optional[bytes] = None,
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

        if sender_public_key and cls.SIGN:
            instance.verify_signature(
                sender_public_key, msg_hash=instance.get_short_hash(payload))
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

    def _verify_signature(
            self, signature: bytes, public_key: bytes,
            msg_hash: typing.Optional[bytes] = None
    ) -> bool:
        """
        Verify a signature against the provided public key and message hash.

        :param public_key: the public key of the expected signer
        :param msg_hash: if provided, a call to `get_short_hash()`
                         will be skipped and the provided hash used instead
        :return: `True` if the signature is correct.
        :raises: `exceptions.InvalidSignature` if the signature is corrupted
        """
        return cryptography.ecdsa_verify(
            pubkey=public_key,
            signature=signature,
            message=msg_hash or self.get_short_hash()
        )

    def verify_signature(
            self,
            public_key: bytes,
            msg_hash: typing.Optional[bytes] = None
    ) -> bool:
        """
        Verify the message's signature using the provided public key.
        Ensures that the message's content is intact and that it has been
        indeed signed by the expected party.

        :param public_key: the public key of the expected sender
        :param msg_hash: maybe optionally provided to skip generation
                         of the message hash during the verification
        :return: `True` if the signature is correct.
        :raises: `exceptions.InvalidSignature` if the signature is corrupted
        """
        return self._verify_signature(self.sig, public_key, msg_hash)

    def _get_signature(
            self,
            private_key: bytes,
            msg_hash: typing.Optional[bytes] = None
    ) -> bytes:
        """
        Calculate message signature using the provided private key.

        :param private_key: th private key used to generate the signature
        :param msg_hash: if given, a call to `get_short_hash()`
                         will be skipped and the provided hash used instead
        """
        return cryptography.ecdsa_sign(
            privkey=private_key,
            msghash=msg_hash or self.get_short_hash()
        )

    def sign_message(
            self,
            private_key: bytes,
            msg_hash: typing.Optional[bytes] = None
    ) -> None:
        """
        Calculate and set message signature using the provided private key.

        :param private_key: sender's private key
        :param msg_hash: may be optionally provided to skip generation
                         of the message hash while signing
        """
        self.sig = self._get_signature(private_key, msg_hash)

    def _fake_sign(self):
        self.sig = b'\0' * Message.SIG_LEN


MessageSlotDefinition_ = collections.namedtuple(
    "MessageSlotDefinition",
    ["klass", "allow_none", "is_list"],
    # defaults added in python3.7
    # defaults=[False, False],
)


def MessageSlotDefinition(klass, allow_none=False, is_list=False):
    # Overcome python3.6 limitation and set default values
    return MessageSlotDefinition_(klass, allow_none, is_list)


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


@library.register(0)
class Hello(Message, dt_p2p.NodeSlotMixin):
    ENCRYPT = False
    VERSION_FORMAT = '!32p'
    VERSION_LENGTH = struct.calcsize(VERSION_FORMAT)
    NODE_SLOTS = (
        'node_info',
    )

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


@library.register(1)
class RandVal(Message):
    """Message with signed random value"""
    __slots__ = ['rand_val'] + Message.__slots__


@library.register(2)
class Disconnect(AbstractReasonMessage):
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


@library.register(3)
class ChallengeSolution(Message):
    __slots__ = ['solution'] + Message.__slots__
