import datetime
import enum
import hashlib
import logging
import struct
import time
from typing import Optional

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
    except (TypeError, OSError, OverflowError):
        raise exceptions.TimestampError()
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


def _fake_sign(s):
    return b'\0' * Message.SIG_LEN


def deserialize_task_to_compute(key, value):
    if key == 'task_to_compute':
        if not isinstance(value, (TaskToCompute, type(None))):
            raise TypeError(
                "Invalid nested message type {} should be {}".format(
                    type(value),
                    TaskToCompute
                )
            )
    return value


# Message types that are allowed to be sent in the network
registered_message_types = {}


class Message():
    """ Communication message that is sent in all networks """

    __slots__ = ['timestamp', 'encrypted', 'sig', '_payload', '_raw']

    TS_SCALE = 10 ** 6
    HDR_LEN = 11
    SIG_LEN = 65

    TYPE = None
    ENCRYPT = True
    ENUM_SLOTS = {}

    def __init__(self, timestamp=None, encrypted=False, sig=None,
                 payload=None, raw=None, slots=None):

        """Create a new message
        :param timestamp: message timestamp
        :param encrypted: whether message was encrypted
        :param payload: payload bytes
        :param sig: signed message hash
        :param raw: original message bytes
        """
        # Child message slots
        self.load_slots(slots)

        # Header
        self.timestamp = timestamp or round(time.time(), 6)
        self.encrypted = encrypted
        self.sig = sig

        # Encoded data
        self._payload = payload  # child's payload only (may be encrypted)
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

    def get_short_hash(self):
        """Return short message representation for signature
        :return bytes: sha1(TYPE, timestamp, encrypted, payload)
        """
        sha = hashlib.sha1()
        sha.update(self.serialize_header())
        sha.update(self._payload or b'')
        return sha.digest()

    def serialize(self, sign_func=None, encrypt_func=None):
        """ Return serialized message
        :return str: serialized message """

        if sign_func is None:
            sign_func = _fake_sign

        try:
            self.encrypted = self.ENCRYPT and encrypt_func
            payload = serializer.dumps(self.slots())

            if self.encrypted:
                self._payload = encrypt_func(payload)
            else:
                self._payload = payload

            # When nesting one message inside another it's important
            # not to overwrite original signature.
            if self.sig is None:
                self.sig = sign_func(self.get_short_hash())

            return (
                self.serialize_header() +
                self.sig +
                self._payload
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
                           int(self.timestamp * self.TS_SCALE),
                           self.encrypted)

    def serialize_slot(self, key, value):
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
    def deserialize(cls, msg, decrypt_func, check_time=True):
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
            return

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
            return

        msg_ts /= cls.TS_SCALE

        if check_time:
            try:
                verify_time(msg_ts)
            except exceptions.TimestampError:
                logger.info("Message error: invalid timestamp: %r", msg_ts)
                return

        if msg_type not in registered_message_types:
            logger.info('Message error: invalid type %d', msg_type)
            return

        try:
            instance = registered_message_types[msg_type](
                timestamp=msg_ts,
                encrypted=msg_enc,
                sig=sig,
                payload=payload,
                raw=msg,
                slots=slots
            )
        except Exception as exc:
            logger.info("Message error: invalid data: %r", exc)
            return
        return instance

    def __repr__(self):
        return "{}(timestamp={}, encrypted={}, sig={}, slots={})".format(
            self.__class__.__name__,
            self.timestamp,
            self.encrypted,
            self.sig,
            self.slots(),
        )

    def load_slots(self, slots):
        if not isinstance(slots, (tuple, list)):
            return

        for entry in slots:
            try:
                slot, value = entry
            except (TypeError, ValueError):
                logger.debug("Message error: invalid slot: %r", entry)
                continue

            if not self.valid_slot(slot):
                continue

            value = self.deserialize_slot(slot, value)
            setattr(self, slot, value)

    def slots(self):
        """Returns a list representation of any subclass message"""
        processed_slots = []
        for key in self.__slots__:
            if not self.valid_slot(key):
                continue
            value = getattr(self, key)
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

    def __init__(
            self,
            port=0,
            node_name=None,
            client_key_id=None,
            node_info=None,
            rand_val=0,
            metadata=None,
            solve_challenge=False,
            challenge=None,
            difficulty=0,
            proto_id=0,
            client_ver=0,
            **kwargs):
        """
        Create new introduction message
        :param int port: listening port
        :param str node_name: uid
        :param str client_key_id: public key
        :param NodeInfo node_info: information about node
        :param float rand_val: random value that should be signed by other site
        :param metadata dict_repr: metadata
        :param boolean solve_challenge: should other client solve given
                                        challenge
        :param str challenge: challenge to solve
        :param int difficulty: difficulty of a challenge
        :param int proto_id: protocol id
        :param str client_ver: application version
        """

        self.proto_id = proto_id
        self.client_ver = client_ver
        self.port = port
        self.node_name = node_name
        self.client_key_id = client_key_id
        self.rand_val = rand_val
        self.node_info = node_info
        self.solve_challenge = solve_challenge
        self.challenge = challenge
        self.difficulty = difficulty
        self.metadata = metadata
        super().__init__(**kwargs)


class RandVal(Message):
    TYPE = 1

    __slots__ = ['rand_val'] + Message.__slots__

    def __init__(self, rand_val=0, **kwargs):
        """
        Create a message with signed random value.
        :param float rand_val: random value received from other side
        """
        self.rand_val = rand_val
        super().__init__(**kwargs)


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

    ENUM_SLOTS = {
        'reason': REASON,
    }

    def __init__(self, reason=-1, **kwargs):
        """
        Create a disconnect message
        :param int reason: disconnection reason
        """
        self.reason = reason
        super().__init__(**kwargs)


class ChallengeSolution(Message):
    TYPE = 3

    __slots__ = ['solution'] + Message.__slots__

    def __init__(self, solution="", **kwargs):
        """
        Create a message with signed cryptographic challenge solution
        :param str solution: challenge solution
        """
        self.solution = solution
        super().__init__(**kwargs)


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

    def __init__(self, peers=None, **kwargs):
        """
        Create message containing information about peers
        :param list peers: list of peers information
        """
        self.peers = peers or []
        super().__init__(**kwargs)


class GetTasks(Message):
    TYPE = P2P_MESSAGE_BASE + 5

    __slots__ = Message.__slots__


class Tasks(Message):
    TYPE = P2P_MESSAGE_BASE + 6

    __slots__ = ['tasks'] + Message.__slots__

    def __init__(self, tasks=None, **kwargs):
        """
        Create message containing information about tasks
        :param list tasks: list of tasks information (subset of
                           taskserver.get_tasks_headers())
        """
        self.tasks = tasks or []
        super().__init__(**kwargs)


class RemoveTask(Message):
    TYPE = P2P_MESSAGE_BASE + 7

    __slots__ = ['task_id'] + Message.__slots__

    def __init__(self, task_id=None, **kwargs):
        """
        Create message with request to remove given task
        :param str task_id: task to be removed
        """
        self.task_id = task_id
        super().__init__(**kwargs)


class GetResourcePeers(Message):
    """Request for resource peers"""
    TYPE = P2P_MESSAGE_BASE + 8

    __slots__ = Message.__slots__


class ResourcePeers(Message):
    TYPE = P2P_MESSAGE_BASE + 9

    __slots__ = ['resource_peers'] + Message.__slots__

    def __init__(self, resource_peers=None, **kwargs):
        """
        Create message containing information about resource peers
        :param list resource_peers: list of peers information
        """
        self.resource_peers = resource_peers or []
        super().__init__(**kwargs)


class Degree(Message):
    TYPE = P2P_MESSAGE_BASE + 10

    __slots__ = ['degree'] + Message.__slots__

    def __init__(self, degree=None, **kwargs):
        """
        Create message with information about node degree
        :param int degree: node degree in golem network
        """
        self.degree = degree
        super().__init__(**kwargs)


class Gossip(Message):
    TYPE = P2P_MESSAGE_BASE + 11

    __slots__ = ['gossip'] + Message.__slots__

    def __init__(self, gossip=None, **kwargs):
        """
        Create gossip message
        :param list gossip: gossip to be send
        """
        self.gossip = gossip or []
        super().__init__(**kwargs)


class StopGossip(Message):
    """Create stop gossip message"""
    TYPE = P2P_MESSAGE_BASE + 12

    __slots__ = Message.__slots__


class LocRank(Message):
    TYPE = P2P_MESSAGE_BASE + 13

    __slots__ = ['node_id', 'loc_rank'] + Message.__slots__

    def __init__(self, node_id='', loc_rank='', **kwargs):
        """
        Create message with local opinion about given node
        :param uuid node_id: message contain opinion about node with this id
        :param LocalRank loc_rank: opinion about node
        """
        self.node_id = node_id
        self.loc_rank = loc_rank
        super().__init__(**kwargs)


class FindNode(Message):
    TYPE = P2P_MESSAGE_BASE + 14

    __slots__ = ['node_key_id'] + Message.__slots__

    def __init__(self, node_key_id='', **kwargs):
        """
        Create find node message
        :param str node_key_id: key of a node to be find
        """
        self.node_key_id = node_key_id
        super().__init__(**kwargs)


class WantToStartTaskSession(Message):
    TYPE = P2P_MESSAGE_BASE + 15

    __slots__ = [
        'node_info',
        'conn_id',
        'super_node_info'
    ] + Message.__slots__

    def __init__(
            self,
            node_info=None,
            conn_id=None,
            super_node_info=None,
            **kwargs):
        """
        Create request for starting task session with given node
        :param Node node_info: information about this node
        :param uuid conn_id: connection id for reference
        :param Node|None super_node_info: information about known supernode
        """
        self.node_info = node_info
        self.conn_id = conn_id
        self.super_node_info = super_node_info
        super().__init__(**kwargs)


class SetTaskSession(Message):
    TYPE = P2P_MESSAGE_BASE + 16

    __slots__ = [
        'key_id',
        'node_info',
        'conn_id',
        'super_node_info',
    ] + Message.__slots__

    def __init__(
            self,
            key_id=None,
            node_info=None,
            conn_id=None,
            super_node_info=None,
            **kwargs):
        """Create message with information that node from node_info wants
           to start task session with key_id node
        :param key_id: target node key
        :param Node node_info: information about requestor
        :param uuid conn_id: connection id for reference
        :param Node|None super_node_info: information about known supernode
        """
        self.key_id = key_id
        self.node_info = node_info
        self.conn_id = conn_id
        self.super_node_info = super_node_info
        super().__init__(**kwargs)


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

    def __init__(
            self,
            node_name=0,
            task_id=0,
            perf_index=0,
            price=0,
            max_resource_size=0,
            max_memory_size=0,
            num_cores=0,
            **kwargs):
        """
        Create message with information that node wants to compute given task
        :param str node_name: id of that node
        :param uuid task_id: if of a task that node wants to compute
        :param float perf_index: benchmark result for this task type
        :param int max_resource_size: how much disk space can this node offer
        :param int max_memory_size: how much ram can this node offer
        :param int num_cores: how many cpu cores this node can offer
        """
        self.node_name = node_name
        self.task_id = task_id
        self.perf_index = perf_index
        self.max_resource_size = max_resource_size
        self.max_memory_size = max_memory_size
        self.num_cores = num_cores
        self.price = price
        super().__init__(**kwargs)


class TaskToCompute(Message):
    TYPE = TASK_MSG_BASE + 2

    __slots__ = ['compute_task_def'] + Message.__slots__

    def __init__(self, compute_task_def=None, **kwargs):
        """
        Create message with information about subtask to compute
        :param ComputeTaskDef compute_task_def: definition of a subtask that
                                                should be computed
        """
        self.compute_task_def = compute_task_def
        super().__init__(**kwargs)


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

    def __init__(self, task_id=0, reason="", **kwargs):
        """
        Create message with information that node can't get task to compute
        :param task_id: task that cannot be assigned
        :param str reason: reason why task cannot be assigned to asking node
        """
        self.task_id = task_id
        self.reason = reason
        super().__init__(**kwargs)


class ReportComputedTask(Message):
    # FIXME this message should be simpler
    TYPE = TASK_MSG_BASE + 4
    RESULT_TYPE = {
        'DATA': 0,
        'FILES': 1,
    }

    __slots__ = [
        'subtask_id',
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

    def __init__(
            self,
            subtask_id=0,
            result_type=RESULT_TYPE['DATA'],
            computation_time='',
            node_name='',
            address='',
            port='',
            key_id='',
            node_info=None,
            eth_account='',
            extra_data=None,
            **kwargs):
        """
        Create message with information about finished computation
        :param str subtask_id: finished subtask id
        :param int result_type: type of a result
        :param float computation_time: how long does it take to  compute this
                                       subtask
        :param node_name: task result owner name
        :param str address: task result owner address
        :param int port: task result owner port
        :param key_id: task result owner key
        :param Node node_info: information about this node
        :param str eth_account: ethereum address (bytes20) of task result owner
        :param extra_data: additional information, eg. list of files
        """
        self.subtask_id = subtask_id
        # TODO why do we need the type here?
        self.result_type = result_type
        self.extra_data = extra_data
        self.computation_time = computation_time
        self.node_name = node_name
        self.address = address
        self.port = port
        self.key_id = key_id
        self.eth_account = eth_account
        self.node_info = node_info
        super().__init__(**kwargs)

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        return deserialize_task_to_compute(key, value)


class GetTaskResult(Message):
    TYPE = TASK_MSG_BASE + 5

    __slots__ = ['subtask_id'] + Message.__slots__

    def __init__(self, subtask_id="", **kwargs):
        """
        Create request for task result
        :param str subtask_id: finished subtask id
        """
        self.subtask_id = subtask_id
        super().__init__(**kwargs)


class TaskResultHash(Message):
    TYPE = TASK_MSG_BASE + 7

    __slots__ = [
        'subtask_id',
        'multihash',
        'secret',
        'options'
    ] + Message.__slots__

    def __init__(
            self,
            subtask_id=0,
            multihash="",
            secret="",
            options=None,
            **kwargs):
        self.subtask_id = subtask_id
        self.multihash = multihash
        self.secret = secret
        self.options = options
        super().__init__(**kwargs)


class GetResource(Message):
    TYPE = TASK_MSG_BASE + 8

    __slots__ = [
        'task_id',
        'resource_header'
    ] + Message.__slots__

    def __init__(self, task_id="", resource_header=None, **kwargs):
        """
        Send request for resource to given task
        :param uuid task_id: given task id
        :param ResourceHeader resource_header: description of resources that
                                               current node has
        """
        self.task_id = task_id
        self.resource_header = resource_header
        super().__init__(**kwargs)


class SubtaskResultAccepted(Message):
    TYPE = TASK_MSG_BASE + 10

    __slots__ = [
        'subtask_id',
        'reward'
    ] + Message.__slots__

    def __init__(self, subtask_id=0, reward=0, **kwargs):
        """
        Create message with information that subtask result was accepted
        :param str subtask_id: accepted subtask id
        :param float reward: payment for computations
        """
        self.subtask_id = subtask_id
        self.reward = reward
        super().__init__(**kwargs)


class SubtaskResultRejected(Message):
    TYPE = TASK_MSG_BASE + 11

    __slots__ = ['subtask_id'] + Message.__slots__

    def __init__(self, subtask_id=0, **kwargs):
        """
        Create message with information that subtask result was rejected
        :param str subtask_id: id of rejected subtask
        """
        self.subtask_id = subtask_id
        super().__init__(**kwargs)


class DeltaParts(Message):
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

    def __init__(self, task_id=0, delta_header=None, parts=None, node_name='',
                 node_info=None, address='', port='', **kwargs):
        """
        Create message with resource description in form of "delta parts".
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
        self.task_id = task_id
        self.delta_header = delta_header
        self.parts = parts
        self.node_name = node_name
        self.address = address
        self.port = port
        self.node_info = node_info
        super().__init__(**kwargs)


class TaskFailure(Message):
    TYPE = TASK_MSG_BASE + 15

    __slots__ = [
        'subtask_id',
        'err',
        'task_to_compute',
    ] + Message.__slots__

    def __init__(self, subtask_id="", err="", **kwargs):
        """
        Create message with information about task computation failure
        :param str subtask_id: id of a failed subtask
        :param str err: error message that occur during computations
        """
        self.subtask_id = subtask_id
        self.err = err
        super().__init__(**kwargs)

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

    def __init__(self, subtask_id=None, reason=None, **kwargs):
        """
        Message informs that the node is waiting for results
        """
        self.reason = reason
        self.subtask_id = subtask_id
        super().__init__(**kwargs)

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        return deserialize_task_to_compute(key, value)


class SubtaskPayment(Message):
    TYPE = TASK_MSG_BASE + 27

    __slots__ = [
        'subtask_id',
        'reward',
        'transaction_id',
        'block_number'
    ] + Message.__slots__

    def __init__(self, subtask_id=None, reward=None, transaction_id=None,
                 block_number=None, **kwargs):
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

        Additional params are described in Message().
        """

        self.subtask_id = subtask_id
        self.reward = reward
        self.transaction_id = transaction_id
        self.block_number = block_number
        super().__init__(**kwargs)


class SubtaskPaymentRequest(Message):
    TYPE = TASK_MSG_BASE + 28

    __slots__ = ['subtask_id'] + Message.__slots__

    def __init__(self, subtask_id=None, **kwargs):
        """Requests information about payment for a subtask.

        :param str subtask_id: accepted subtask id
        :param dict dict_repr: dictionary representation of a message

        Additional params are described in Message().
        """

        self.subtask_id = subtask_id
        super().__init__(**kwargs)


RESOURCE_MSG_BASE = 3000


class AbstractResource(Message):
    __slots__ = ['resource'] + Message.__slots__

    def __init__(self, resource=None, **kwargs):
        """
        :param str resource: resource name
        """
        self.resource = resource
        super(AbstractResource, self).__init__(**kwargs)


class PushResource(AbstractResource):
    TYPE = RESOURCE_MSG_BASE + 1

    __slots__ = [
        'copies'
    ] + AbstractResource.__slots__

    def __init__(self, copies=0, **kwargs):
        """Create message with information that expected number of copies of
           given resource should be pushed to the network
        :param int copies: number of copies
        """
        self.copies = copies
        super().__init__(**kwargs)


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
    TYPE = RESOURCE_MSG_BASE + 5

    __slots__ = [
        'resource',
        'has_resource'
    ] + Message.__slots__

    def __init__(self, resource=None, has_resource=False, **kwargs):
        """Create message with information whether current peer has given
           resource and may send it
        :param str resource: resource name
        :param bool has_resource: information if user has resource
        """
        self.resource = resource
        self.has_resource = has_resource
        super().__init__(**kwargs)


class ResourceList(Message):
    TYPE = RESOURCE_MSG_BASE + 7

    __slots__ = [
        'resources',
        'options'
    ] + Message.__slots__

    def __init__(self, resources=None, options=None, **kwargs):
        """
        Create message with resource request
        :param str resources: resource list
        """
        self.resources = resources
        self.options = options
        super().__init__(**kwargs)


class ResourceHandshakeStart(Message):
    TYPE = RESOURCE_MSG_BASE + 8

    __slots__ = [
        'resource'
    ] + Message.__slots__

    def __init__(self,
                 resource: Optional[str]=None,
                 **kwargs):

        self.resource = resource
        super().__init__(**kwargs)


class ResourceHandshakeNonce(Message):
    TYPE = RESOURCE_MSG_BASE + 9

    __slots__ = [
        'nonce'
    ] + Message.__slots__

    def __init__(self,
                 nonce: Optional[str]=None,
                 **kwargs):

        self.nonce = nonce
        super().__init__(**kwargs)


class ResourceHandshakeVerdict(Message):
    TYPE = RESOURCE_MSG_BASE + 10

    __slots__ = [
        'accepted',
        'nonce'
    ] + Message.__slots__

    def __init__(self,
                 nonce: Optional[str]=None,
                 accepted: Optional[bool] = False,
                 **kwargs):

        self.nonce = nonce
        self.accepted = accepted
        super().__init__(**kwargs)


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

    def __init__(self,
                 subtask_id=None,
                 reason: Optional[Reason] = None,
                 **kwargs):
        self.subtask_id = subtask_id
        self.reason = reason
        super().__init__(**kwargs)

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        return deserialize_task_to_compute(key, value)


class ForceReportComputedTask(Message):
    TYPE = CONCENT_MSG_BASE + 1

    __slots__ = [
        'subtask_id',
        'task_to_compute',
    ] + Message.__slots__

    def __init__(self, subtask_id=None, **kwargs):
        self.subtask_id = subtask_id
        super().__init__(**kwargs)

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        return deserialize_task_to_compute(key, value)


class AckReportComputedTask(Message):
    TYPE = CONCENT_MSG_BASE + 2

    __slots__ = [
        'subtask_id',
        'task_to_compute',
    ] + Message.__slots__

    def __init__(self, subtask_id=None, **kwargs):
        self.subtask_id = subtask_id
        super().__init__(**kwargs)

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
    ] + Message.__slots__

    def __init__(
            self,
            subtask_id=None,
            reason: Reason = None,
            **kwargs):
        self.subtask_id = subtask_id
        self.reason = reason
        super().__init__(**kwargs)

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        return deserialize_task_to_compute(key, value)


class VerdictReportComputedTask(Message):
    TYPE = CONCENT_MSG_BASE + 4

    __slots__ = [
        'subtask_id',
        'task_to_compute',
    ] + Message.__slots__

    def __init__(self, subtask_id=None, **kwargs):
        self.subtask_id = subtask_id
        super().__init__(**kwargs)

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        return deserialize_task_to_compute(key, value)


def init_messages():
    """Add supported messages to register messages list"""
    if registered_message_types:
        return
    for message_class in \
            (
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
            ):
        if message_class.TYPE in registered_message_types:
            raise RuntimeError(
                "Duplicated message {}.TYPE: {}"
                .format(message_class.__name__, message_class.TYPE)
            )
        registered_message_types[message_class.TYPE] = message_class


init_messages()
