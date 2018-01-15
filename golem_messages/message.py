import calendar
import datetime
import enum
import functools
import hashlib
import logging
import struct
import time

import golem_messages

from . import datastructures
from . import exceptions
from . import serializer
from . import settings

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


class ComputeTaskDef(datastructures.FrozenDict):
    """Represents SUBTASK metadata."""
    ITEMS = {
        'task_id': '',
        'subtask_id': '',
        # deadline represents subtask timeout in UTC timestamp (float or int)
        # If you're looking for whole TASK deadline SEE: task_header.deadline
        # Task headers are received in MessageTasks.tasks.
        'deadline': '',
        'src_code': '',
        'extra_data': {},  # safe because of copy in parent.__missing__()
        'short_description': '',
        'return_address': '',
        'return_port': 0,
        'task_owner': None,
        'key_id': 0,
        'working_directory': '',
        'performance': 0,
        'environment': '',
        'docker_images': None,
    }


def _fake_sign(s):  # pylint: disable=unused-argument
    return b'\0' * Message.SIG_LEN


def verify_slot_type(value, class_):
    if not isinstance(value, (class_, type(None))):
        raise TypeError(
            "Invalid nested message type {} should be {}".format(
                type(value),
                class_
            )
        )


# Message types that are allowed to be sent in the network
registered_message_types = {}


class Message():
    """ Communication message that is sent in all networks """

    __slots__ = ['timestamp', 'encrypted', 'sig', '_raw']

    HDR_LEN = 11
    SIG_LEN = 65

    TYPE = None
    ENCRYPT = True
    ENUM_SLOTS = {}

    def __init__(self, timestamp=None, encrypted=False, sig=None,
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
        :return: tuple of (TYPE, timestamp, encrypted)
        """
        assert len(data) == cls.HDR_LEN
        return struct.unpack('!HQ?', data)

    @classmethod
    def deserialize(cls, msg, decrypt_func, check_time=True, verify_func=None):
        """
        Deserialize single message
        :param str msg: serialized message
        :param function(data) decrypt_func: decryption function
        :return Message|None: deserialized message or none if this message
                              type is unknown
        """

        payload_idx = cls.HDR_LEN + cls.SIG_LEN

        if not msg or len(msg) <= payload_idx:
            logger.info("Message error: message too short")
            return  # TODO: #52 pylint: disable=inconsistent-return-statements

        header = msg[:cls.HDR_LEN]
        sig = msg[cls.HDR_LEN:payload_idx]
        payload = msg[payload_idx:]
        data = payload

        try:
            msg_type, msg_ts, msg_enc = cls.deserialize_header(header)
            logger.debug("msg_type: %r", msg_type)
            if msg_enc:
                data = decrypt_func(payload)
            slots = serializer.loads(data)
        except Exception as exc:
            logger.info("Message error: invalid data: %r", exc)
            logger.debug("Failing message hdr: %r data: %r", header, data)
            return  # TODO: #52 pylint: disable=inconsistent-return-statements

        if msg_ts > 10**10:
            # Old timestamp format. Remove after 0.11 golem core release
            msg_ts /= 10**6
            msg_ts = int(msg_ts)

        if check_time:
            try:
                verify_time(msg_ts)
            except exceptions.TimestampError as e:
                logger.info(
                    "Message error: invalid timestamp: %r %s",
                    msg_ts,
                    e,
                )
                return  # noqa TODO: #52 pylint: disable=inconsistent-return-statements

        if msg_type not in registered_message_types:
            logger.info('Message error: invalid type %d', msg_type)
            return  # TODO: #52 pylint: disable=inconsistent-return-statements

        try:
            instance = registered_message_types[msg_type](
                timestamp=msg_ts,
                encrypted=msg_enc,
                sig=sig,
                raw=msg,
                slots=slots,
                deserialized=True,
            )
        except Exception as exc:
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


class Disconnect(Message):
    TYPE = 2
    ENCRYPT = False

    __slots__ = ['reason'] + Message.__slots__

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

    ENUM_SLOTS = {
        'reason': REASON,
    }


class ChallengeSolution(Message):
    TYPE = 3

    __slots__ = ['solution'] + Message.__slots__


################
# P2P Messages #
################

P2P_MESSAGE_BASE = 1000


class Ping(Message):
    TYPE = P2P_MESSAGE_BASE + 1

    __slots__ = Message.__slots__


class Pong(Message):
    TYPE = P2P_MESSAGE_BASE + 2

    __slots__ = Message.__slots__


class GetPeers(Message):
    TYPE = P2P_MESSAGE_BASE + 3

    __slots__ = Message.__slots__


class Peers(Message):
    TYPE = P2P_MESSAGE_BASE + 4

    __slots__ = ['peers'] + Message.__slots__

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.peers = self.peers or []


class GetTasks(Message):
    TYPE = P2P_MESSAGE_BASE + 5

    __slots__ = Message.__slots__


class Tasks(Message):
    TYPE = P2P_MESSAGE_BASE + 6

    __slots__ = ['tasks'] + Message.__slots__

    def __init__(self, **kwargs):
        """
        Create message containing information about tasks
        :param list tasks: list of tasks information (subset of
                           taskserver.get_tasks_headers())
        """
        super().__init__(**kwargs)
        self.tasks = self.tasks or []


class RemoveTask(Message):
    TYPE = P2P_MESSAGE_BASE + 7

    __slots__ = ['task_id'] + Message.__slots__


class GetResourcePeers(Message):
    """Request for resource peers"""
    TYPE = P2P_MESSAGE_BASE + 8

    __slots__ = Message.__slots__


class ResourcePeers(Message):
    TYPE = P2P_MESSAGE_BASE + 9

    __slots__ = ['resource_peers'] + Message.__slots__

    def __init__(self, **kwargs):
        """
        Create message containing information about resource peers
        :param list resource_peers: list of peers information
        """
        super().__init__(**kwargs)
        self.resource_peers = self.resource_peers or []


class Degree(Message):
    TYPE = P2P_MESSAGE_BASE + 10

    __slots__ = ['degree'] + Message.__slots__


class Gossip(Message):
    TYPE = P2P_MESSAGE_BASE + 11

    __slots__ = ['gossip'] + Message.__slots__

    def __init__(self, **kwargs):
        """
        Create gossip message
        :param list gossip: gossip to be send
        """
        super().__init__(**kwargs)
        self.gossip = self.gossip or []


class StopGossip(Message):
    """Create stop gossip message"""
    TYPE = P2P_MESSAGE_BASE + 12

    __slots__ = Message.__slots__


class LocRank(Message):
    TYPE = P2P_MESSAGE_BASE + 13

    __slots__ = ['node_id', 'loc_rank'] + Message.__slots__


class FindNode(Message):
    TYPE = P2P_MESSAGE_BASE + 14

    __slots__ = ['node_key_id'] + Message.__slots__


class WantToStartTaskSession(Message):
    TYPE = P2P_MESSAGE_BASE + 15

    __slots__ = [
        'node_info',
        'conn_id',
        'super_node_info'
    ] + Message.__slots__


class SetTaskSession(Message):
    TYPE = P2P_MESSAGE_BASE + 16

    __slots__ = [
        'key_id',
        'node_info',
        'conn_id',
        'super_node_info',
    ] + Message.__slots__


TASK_MSG_BASE = 2000


class WantToComputeTask(Message):
    TYPE = TASK_MSG_BASE + 1

    __slots__ = [
        'node_name',
        'task_id',
        'perf_index',
        'max_resource_size',
        'max_memory_size',
        'num_cores',
        'price'
    ] + Message.__slots__


class TaskToCompute(Message):
    TYPE = TASK_MSG_BASE + 2

    __slots__ = ['compute_task_def'] + Message.__slots__

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        if key == 'compute_task_def':
            value = ComputeTaskDef(value)
        return value


class CannotAssignTask(Message):
    TYPE = TASK_MSG_BASE + 3

    __slots__ = [
        'reason',
        'task_id'
    ] + Message.__slots__

    class REASON(enum.Enum):
        NotMyTask = 'not_my_task'
        NoMoreSubtasks = 'no_more_subtasks'

    ENUM_SLOTS = {
        'reason': REASON,
    }


class ReportComputedTask(Message):
    # FIXME this message should be simpler
    TYPE = TASK_MSG_BASE + 4
    RESULT_TYPE = {
        'DATA': 0,
        'FILES': 1,
    }

    __slots__ = [
        'subtask_id',
        # TODO why do we need the type here?
        'result_type',
        'computation_time',
        'node_name',
        'address',
        'node_info',
        'port',
        'key_id',
        'extra_data',
        'eth_account',
        'task_to_compute',
    ] + Message.__slots__

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        return deserialize_task_to_compute(key, value)


class GetTaskResult(Message):
    """Request task result"""
    TYPE = TASK_MSG_BASE + 5

    __slots__ = ['subtask_id'] + Message.__slots__


class TaskResultHash(Message):
    TYPE = TASK_MSG_BASE + 7

    __slots__ = [
        'subtask_id',
        'multihash',
        'secret',
        'options'
    ] + Message.__slots__


class GetResource(Message):
    """Request a resource for a given task"""
    TYPE = TASK_MSG_BASE + 8

    __slots__ = [
        'task_id',
        'resource_header'
    ] + Message.__slots__


class SubtaskResultAccepted(Message):
    TYPE = TASK_MSG_BASE + 10

    __slots__ = [
        'subtask_id',
        'payment_ts'
    ] + Message.__slots__


class SubtaskResultRejected(Message):
    TYPE = TASK_MSG_BASE + 11

    __slots__ = ['subtask_id'] + Message.__slots__


class DeltaParts(Message):
    """Message with resource description in form of "delta parts".

    :param task_id: resources are for task with this id
    :param TaskResourceHeader delta_header: resource header containing
                                            only parts that computing
                                            node doesn't have
    :param list parts: list of all files that are needed to create
                       resources
    :param str node_name: resource owner name
    :param Node node_info: information about resource owner
    :param address: resource owner address
    :param port: resource owner port
    """
    TYPE = TASK_MSG_BASE + 12

    __slots__ = [
        'task_id',
        'delta_header',
        'parts',
        'node_name',
        'address',
        'port',
        'node_info',
    ] + Message.__slots__


class TaskFailure(Message):
    TYPE = TASK_MSG_BASE + 15

    __slots__ = [
        'subtask_id',
        'err',
        'task_to_compute',
    ] + Message.__slots__

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        return deserialize_task_to_compute(key, value)


class StartSessionResponse(Message):
    TYPE = TASK_MSG_BASE + 16

    __slots__ = ['conn_id'] + Message.__slots__

    def __init__(self, conn_id=None, **kwargs):
        """Create message with information that this session was started as
           an answer for a request to start task session
        :param uuid conn_id: connection id for reference
        """
        self.conn_id = conn_id
        super().__init__(**kwargs)


class WaitingForResults(Message):
    TYPE = TASK_MSG_BASE + 25

    __slots__ = Message.__slots__


class CannotComputeTask(Message):
    TYPE = TASK_MSG_BASE + 26

    __slots__ = [
        'reason',
        'subtask_id',
        'task_to_compute',
    ] + Message.__slots__

    class REASON(enum.Enum):
        WrongCTD = 'wrong_ctd'
        WrongKey = 'wrong_key'
        WrongAddress = 'wrong_address'
        WrongEnvironment = 'wrong_environment'
        NoSourceCode = 'no_source_code'
        WrongDockerImages = 'wrong_docker_images'

    ENUM_SLOTS = {
        'reason': REASON,
    }

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        return deserialize_task_to_compute(key, value)


class SubtaskPayment(Message):
    """Informs about payment for a subtask.
    It succeeds SubtaskResultAccepted but could
    be sent after a delay. It is also sent in response to
    SubtaskPaymentRequest. If transaction_id is None it
    should be interpreted as PAYMENT PENDING status.

    :param str subtask_id: accepted subtask id
    :param float reward: payment for computations
    :param str transaction_id: eth transaction id
    :param int block_number: eth blockNumber
    :param dict dict_repr: dictionary representation of a message
    """

    TYPE = TASK_MSG_BASE + 27

    __slots__ = [
        'subtask_id',
        'reward',
        'transaction_id',
        'block_number'
    ] + Message.__slots__


class SubtaskPaymentRequest(Message):
    """Requests information about payment for a subtask.

    :param str subtask_id: accepted subtask id
    :param dict dict_repr: dictionary representation of a message
    """

    TYPE = TASK_MSG_BASE + 28

    __slots__ = ['subtask_id'] + Message.__slots__


RESOURCE_MSG_BASE = 3000


class AbstractResource(Message):
    """
    :param str resource: resource name
    """
    __slots__ = ['resource'] + Message.__slots__


class PushResource(AbstractResource):
    """Message with information that expected number of copies of
       given resource should be pushed to the network
    :param int copies: number of copies
    """

    TYPE = RESOURCE_MSG_BASE + 1

    __slots__ = [
        'copies'
    ] + AbstractResource.__slots__


class HasResource(AbstractResource):
    """Create message with information about having given resource"""
    TYPE = RESOURCE_MSG_BASE + 2

    __slots__ = AbstractResource.__slots__


class WantsResource(AbstractResource):
    """Send information that node wants to receive given resource"""
    TYPE = RESOURCE_MSG_BASE + 3

    __slots__ = AbstractResource.__slots__


class PullResource(AbstractResource):
    """Create message with information that given resource is needed"""
    TYPE = RESOURCE_MSG_BASE + 4

    __slots__ = AbstractResource.__slots__


class PullAnswer(Message):
    """Message with information whether current peer has given
       resource and may send it
    :param str resource: resource name
    :param bool has_resource: information if user has resource
    """

    TYPE = RESOURCE_MSG_BASE + 5

    __slots__ = [
        'resource',
        'has_resource'
    ] + Message.__slots__


class ResourceList(Message):
    """Message with resource request
    :param str resources: resource list
    """

    TYPE = RESOURCE_MSG_BASE + 7

    __slots__ = [
        'resources',
        'options'
    ] + Message.__slots__


class ResourceHandshakeStart(Message):
    TYPE = RESOURCE_MSG_BASE + 8

    __slots__ = [
        'resource',
        'options'
    ] + Message.__slots__


class ResourceHandshakeNonce(Message):
    TYPE = RESOURCE_MSG_BASE + 9

    __slots__ = [
        'nonce'
    ] + Message.__slots__


class ResourceHandshakeVerdict(Message):
    TYPE = RESOURCE_MSG_BASE + 10

    __slots__ = [
        'accepted',
        'nonce'
    ] + Message.__slots__


CONCENT_MSG_BASE = 4000


class ServiceRefused(Message):
    TYPE = CONCENT_MSG_BASE

    @enum.unique
    class Reason(enum.Enum):
        TOO_SMALL_COMMUNICATION_PAYMENT = 'TOO_SMALL_COMMUNICATION_PAYMENT'
        TOO_SMALL_REQUESTOR_DEPOSIT = 'TOO_SMALL_REQUESTOR_DEPOSIT'
        TOO_SMALL_PROVIDER_DEPOSIT = 'TOO_SMALL_PROVIDER_DEPOSIT'
        SYSTEM_OVERLOADED = 'SYSTEM_OVERLOADED'

    ENUM_SLOTS = {
        'reason': Reason,
    }

    __slots__ = [
        'subtask_id',
        'reason',
        'task_to_compute',
    ] + Message.__slots__

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        return deserialize_task_to_compute(key, value)


class ForceReportComputedTask(Message):
    TYPE = CONCENT_MSG_BASE + 1

    __slots__ = [
        'task_to_compute',
        'result_hash',
    ] + Message.__slots__

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        return deserialize_task_to_compute(key, value)


class AckReportComputedTask(Message):
    TYPE = CONCENT_MSG_BASE + 2

    __slots__ = [
        'subtask_id',
        'task_to_compute',
    ] + Message.__slots__

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        return deserialize_task_to_compute(key, value)


class RejectReportComputedTask(Message):
    TYPE = CONCENT_MSG_BASE + 3

    @enum.unique
    class Reason(enum.Enum):
        """
        since python 3.6 it's possible to do this:

        class StringEnum(str, enum.Enum):
            def _generate_next_value_(name: str, *_):
                return name

        @enum.unique
        class Reason(StringEnum):
            TASK_TIME_LIMIT_EXCEEDED = enum.auto()
            SUBTASK_TIME_LIMIT_EXCEEDED = enum.auto()
            GOT_MESSAGE_CANNOT_COMPUTE_TASK = enum.auto()
            GOT_MESSAGE_TASK_FAILURE = enum.auto()
        """
        TASK_TIME_LIMIT_EXCEEDED = 'TASK_TIME_LIMIT_EXCEEDED'
        SUBTASK_TIME_LIMIT_EXCEEDED = 'SUBTASK_TIME_LIMIT_EXCEEDED'
        GOT_MESSAGE_CANNOT_COMPUTE_TASK = 'GOT_MESSAGE_CANNOT_COMPUTE_TASK'
        GOT_MESSAGE_TASK_FAILURE = 'GOT_MESSAGE_TASK_FAILURE'

    ENUM_SLOTS = {
        'reason': Reason,
    }

    __slots__ = [
        'subtask_id',
        'reason',
        'task_to_compute',
        'task_failure',
        'cannot_compute_task',
    ] + Message.__slots__

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        value = deserialize_task_to_compute(key, value)
        value = deserialize_task_failure(key, value)
        value = deserialize_cannot_compute_task(key, value)
        return value


class VerdictReportComputedTask(Message):
    TYPE = CONCENT_MSG_BASE + 4

    __slots__ = [
        'force_report_computed_task',
        'ack_report_computed_task',
    ] + Message.__slots__

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        value = deserialize_force_report_computed_task(key, value)
        value = deserialize_ack_report_computed_task(key, value)
        return value


class FileTransferToken(Message):
    TYPE = CONCENT_MSG_BASE + 5

    __slots__ = [
        'token_expiration_deadline',
        'storage_cluster_address',
        'authorized_client_public_key',
        'operation',
        'files',
    ] + Message.__slots__

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        if key == 'files':
            value = [FileTransferToken.FileInfo(f) for f in value]
        return value

    class FileInfo(datastructures.FrozenDict):
        """Represents SUBTASK metadata."""
        ITEMS = {
            'path': '',
            'checksum': '',
            'size': 0,
        }


def deserialize_verify(key, value, verify_key, verify_class):
    if key == verify_key:
        verify_slot_type(value, verify_class)
    return value


deserialize_task_to_compute = functools.partial(
    deserialize_verify,
    verify_key='task_to_compute',
    verify_class=TaskToCompute,
)

deserialize_task_failure = functools.partial(
    deserialize_verify,
    verify_key='task_failure',
    verify_class=TaskFailure,
)

deserialize_cannot_compute_task = functools.partial(
    deserialize_verify,
    verify_key='cannot_compute_task',
    verify_class=CannotComputeTask,
)

deserialize_force_report_computed_task = functools.partial(
    deserialize_verify,
    verify_key='force_report_computed_task',
    verify_class=ForceReportComputedTask,
)

deserialize_ack_report_computed_task = functools.partial(
    deserialize_verify,
    verify_key='ack_report_computed_task',
    verify_class=AckReportComputedTask,
)


def init_messages():
    """Add supported messages to register messages list"""
    if registered_message_types:
        return
    for message_class in (
            # Basic messages
            Hello,
            RandVal,
            Disconnect,
            ChallengeSolution,

            # P2P messages
            Ping,
            Pong,
            GetPeers,
            GetTasks,
            Peers,
            Tasks,
            RemoveTask,
            FindNode,
            GetResourcePeers,
            ResourcePeers,
            WantToStartTaskSession,
            SetTaskSession,
            # Ranking messages
            Degree,
            Gossip,
            StopGossip,
            LocRank,

            # Task messages
            CannotAssignTask,
            CannotComputeTask,
            TaskToCompute,
            WantToComputeTask,
            ReportComputedTask,
            TaskResultHash,
            TaskFailure,
            GetTaskResult,
            StartSessionResponse,

            WaitingForResults,
            SubtaskResultAccepted,
            SubtaskResultRejected,
            DeltaParts,

            # Resource messages
            GetResource,
            PushResource,
            HasResource,
            WantsResource,
            PullResource,
            PullAnswer,
            ResourceList,

            ResourceHandshakeStart,
            ResourceHandshakeNonce,
            ResourceHandshakeVerdict,

            SubtaskPayment,
            SubtaskPaymentRequest,

            # Concent messages
            ServiceRefused,
            ForceReportComputedTask,
            AckReportComputedTask,
            RejectReportComputedTask,
            VerdictReportComputedTask,
            FileTransferToken, ):
        if message_class.TYPE in registered_message_types:
            raise RuntimeError(
                "Duplicated message {}.TYPE: {}"
                .format(message_class.__name__, message_class.TYPE)
            )
        registered_message_types[message_class.TYPE] = message_class


init_messages()
