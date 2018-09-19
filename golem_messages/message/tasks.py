import enum
import functools
import struct
import typing

from eth_utils import to_checksum_address
from ethereum.utils import sha3

from golem_messages import datastructures
from golem_messages import exceptions
from golem_messages import idgenerator
from golem_messages import validators
from golem_messages.register import library
from golem_messages.utils import decode_hex

from . import base

TASK_MSG_BASE = 2000


class ComputeTaskDef(datastructures.ValidatingDict, datastructures.FrozenDict):
    """Represents SUBTASK metadata."""
    ITEMS = {
        'task_id': '',
        'subtask_id': '',
        # deadline represents subtask timeout in UTC timestamp (float or int)
        # If you're looking for whole TASK deadline SEE: task_header.deadline
        # Task headers are received in MessageTasks.tasks.
        'deadline': 0,
        'src_code': '',
        'extra_data': {},  # safe because of copy in parent.__missing__()
        'short_description': '',
        'working_directory': '',
        'performance': 0,
        'docker_images': None,
    }

    validate_task_id = functools.partial(
        validators.validate_varchar,
        field_name='task_id',
        max_length=128,
    )

    validate_subtask_id = functools.partial(
        validators.validate_varchar,
        field_name='subtask_id',
        max_length=128,
    )


class TaskMessage(base.Message):
    __slots__ = []
    TASK_ID_PROVIDERS = ()

    @enum.unique
    class OWNER_CHOICES(datastructures.StringEnum):
        provider = enum.auto()
        requestor = enum.auto()
        concent = enum.auto()

    EXPECTED_OWNERS = ()

    def _get_task_value(self, attr_name):
        msgs = [getattr(self, slot)
                for slot in self.TASK_ID_PROVIDERS
                if hasattr(self, slot)]

        for msg in msgs:
            val = getattr(msg, attr_name, None)
            if val:
                return val
        return None

    @property
    def task_id(self):
        """
        :return: the `task_id` related to this message chain
        """
        return self._get_task_value('task_id')

    @property
    def subtask_id(self):
        """
        :return: the `subtask_id` related to this message chain
        """
        return self._get_task_value('subtask_id')

    @property
    def task_to_compute(self):
        """
        :return: the `TaskToCompute` related to this message chain
        """
        return self._get_task_value('task_to_compute')

    @property
    def provider_id(self):
        """
        :return: the provider's `node_id` related to this message chain
        """
        return self._get_task_value('provider_id')

    @property
    def requestor_id(self):
        """
        :return: the requestor's `node_id` related to this message chain
        """
        return self._get_task_value('requestor_id')

    def validate_ownership(self, concent_public_key=None):
        """
        validates that the message is signed by one of the expected parties

        requires `concent_public_key` if the Concent is one of the possible
        owners
        """
        owner_map = {
            TaskMessage.OWNER_CHOICES.provider:
                decode_hex(self.task_to_compute.provider_public_key),
            TaskMessage.OWNER_CHOICES.requestor:
                decode_hex(self.task_to_compute.requestor_public_key),
            TaskMessage.OWNER_CHOICES.concent:
                concent_public_key,
        }

        for owner in self.EXPECTED_OWNERS:
            try:
                if self.verify_signature(public_key=owner_map.get(owner)):
                    return True
            except exceptions.InvalidSignature:
                pass

        exc = exceptions.InvalidSignature('%s is not signed by the %s' % (
            self.__class__.__name__,
            ' or '.join([
                '%s: %s' % (
                    o.value, owner_map.get(o)
                ) for o in self.EXPECTED_OWNERS
            ])
        ))
        exc.message = self
        raise exc

    def validate_ownership_chain(self, concent_public_key=None):
        """
        validates that the whole chain consists of messages that are signed by
        their respective expected parties

        requires `concent_public_key` if the Concent is a possible owner of
        any message within the chain
        """
        self.validate_ownership(concent_public_key=concent_public_key)

        for msg in [slot for slot in
                    [getattr(self, slot_name) for slot_name in self.__slots__]
                    if isinstance(slot, TaskMessage)]:
            msg.validate_ownership_chain(concent_public_key=concent_public_key)

        return True

    def verify_owners(self,
                      provider_public_key=None,
                      requestor_public_key=None,
                      concent_public_key=None):
        """
        verifies both that the whole message chain is consistent with respect
        to the expected message ownership and that the roles in the message
        chain match the expected provider/requestor keys

        if provided, `provider_public_key` / `requestor_public_key` will be
        verified against the roles extracted from the included message chain.

        :param provider_public_key:
        :param requestor_public_key:
        :param concent_public_key: must be provided if any of the child
                                   messages is expected to be signed
                                   by the Concent
        :return:
        """

        def assert_role(role, expected, actual):
            if expected != actual:
                raise exceptions.OwnershipMismatch(
                    "%s: Task %s mismatch - expected: %s, actual: %s" % (
                        self.__class__.__name__, role, expected, actual
                    )
                )

        if provider_public_key:
            assert_role('provider',
                        provider_public_key,
                        decode_hex(self.task_to_compute.provider_public_key))

        if requestor_public_key:
            assert_role('requestor',
                        requestor_public_key,
                        decode_hex(self.task_to_compute.requestor_public_key))

        self.validate_ownership_chain(concent_public_key=concent_public_key)
        return True

    def is_valid(self):  # noqa pylint:disable=no-self-use
        """
        checks whether the message is semantically valid with respect to
        golem logic requirements regarding the specific task-related messages

        it should _not_ verify the cryptographic signatures and/or
        ownership of the message or any messages contained within, as these
        are performed by the `verify_owners` et al

        Should raise `exceptions.ValidationError` in case
        of a failed validation check.

        :raises: `exceptions.ValidationError`
        :return: bool
        """
        return True


class ConcentEnabled:  # noqa pylint:disable=too-few-public-methods
    __slots__ = []

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.concent_enabled = bool(self.concent_enabled)  # noqa pylint:disable=assigning-non-slot


@library.register(TASK_MSG_BASE + 1)
class WantToComputeTask(ConcentEnabled, base.Message):
    __slots__ = [
        'node_name',
        'task_id',
        'perf_index',
        'max_resource_size',
        'max_memory_size',
        'num_cores',
        'price',
        'concent_enabled',  # Provider notifies requestor
                            # about his concent status
    ] + base.Message.__slots__


@library.register(TASK_MSG_BASE + 2)
class TaskToCompute(ConcentEnabled, TaskMessage):
    EXPECTED_OWNERS = (TaskMessage.OWNER_CHOICES.requestor, )
    ETHSIG_FORMAT = '66p'
    ETHSIG_LENGTH = struct.calcsize(ETHSIG_FORMAT)

    __slots__ = [
        'requestor_id',  # a.k.a. node id
        'requestor_public_key',  # key used for msg signing and encryption
        'requestor_ethereum_public_key',  # used for transactions on blockchain
        'provider_id',  # a.k.a. node id
        'provider_public_key',  # key used for msg signing and encryption
        'provider_ethereum_public_key',  # used for transactions on blockchain
        'compute_task_def',
        'package_hash',  # the hash of the package (resources) zip file
        'size',  # the size of the resources zip file
        'concent_enabled',
        'price',  # total subtask price computed as `price * subtask_timeout`

        '_ethsig'  # must be last
    ] + base.Message.__slots__

    @property
    def requestor_ethereum_address(self):
        return to_checksum_address(
            sha3(decode_hex(self.requestor_ethereum_public_key))[12:].hex()
        )

    @property
    def provider_ethereum_address(self):
        return to_checksum_address(
            sha3(decode_hex(self.provider_ethereum_public_key))[12:].hex(),
        )

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        if key == 'compute_task_def':
            value = ComputeTaskDef(value)
        if key in ('price', 'size'):
            validators.validate_integer(
                field_name=key,
                value=value,
            )
        return value

    @property
    def task_id(self):
        if self.compute_task_def:
            return self.compute_task_def.get('task_id')
        return None

    @property
    def subtask_id(self):
        if self.compute_task_def:
            return self.compute_task_def.get('subtask_id')
        return None

    @property
    def task_to_compute(self):
        return self

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if not hasattr(self, '_ethsig'):
            self._ethsig = None

    def serialize(self, *args, **kwargs):  # pylint: disable=arguments-differ
        serialized = super().serialize(*args, **kwargs)
        sig_length = self.ETHSIG_LENGTH - 1
        if self._ethsig and len(self._ethsig) != sig_length:
            raise ValueError(
                "'_ethsig' must be exactly %s bytes long (or None)"
                % sig_length)
        ethsig = struct.pack(
            self.ETHSIG_FORMAT,
            self._ethsig or b''
        )
        return serialized + ethsig

    @classmethod
    def deserialize_with_header(cls, header, data, *args, **kwargs):  # noqa pylint: disable=arguments-differ
        ethsig_data, data = data[-cls.ETHSIG_LENGTH:], data[:-cls.ETHSIG_LENGTH]
        instance: TaskToCompute = super().deserialize_with_header(
            header, data, *args, **kwargs
        )
        (ethsig, ) = struct.unpack(
            cls.ETHSIG_FORMAT, ethsig_data)
        instance._ethsig = ethsig or None  # noqa pylint: disable=protected-access,assigning-non-slot
        try:
            instance.verify_ethsig()
        except exceptions.InvalidSignature:
            raise exceptions.InvalidSignature(
                "ethereum address signature verification failed for `%s`"
                % instance.requestor_ethereum_public_key
            )
        instance.validate_taskid()
        return instance

    def generate_ethsig(
            self, private_key: bytes, msg_hash: typing.Optional[bytes] = None
    ) -> None:
        """
        Calculate and set message's ethereum signature
        using the provided ethereum private key.

        :param private_key: ethereum private key
        :param msg_hash: may be optionally provided to skip generation
                         of the message hash while signing
        """

        if not self.requestor_ethereum_public_key:
            raise exceptions.FieldError(
                "It doesn't really make sense to"
                " generate the ethereum signature"
                " with no `requestor_ethereum_public_key` in place...",
                field='requestor_ethereum_public_key',
                value=self.requestor_ethereum_public_key,
            )

        self._ethsig = self._get_signature(private_key, msg_hash)

    def verify_ethsig(
            self, msg_hash: typing.Optional[bytes] = None
    ) -> bool:
        """
        Verify the message's ethereum signature using the provided public key.
        Ensures that the requestor has control over the ethereum address
        associated with `requestor_ethereum_public_key`

        :param msg_hash: maybe optionally provided to skip generation
                         of the message hash during the verification
        :return: `True` if the signature is correct.
        :raises: `exceptions.InvalidSignature` if the signature is corrupted
        """
        return self._verify_signature(
            self._ethsig, decode_hex(self.requestor_ethereum_public_key), msg_hash
        )

    def validate_taskid(self) -> None:
        for key in ('task_id', 'subtask_id'):
            value = self.compute_task_def[key]
            if not idgenerator.check_id_hex_seed(value, self.requestor_id):
                raise exceptions.FieldError(
                    "Should be generated with node == ({node:x})".format(
                        node=idgenerator.hex_seed_to_node(self.requestor_id),
                    ),
                    field=key,
                    value=value,
                )


@library.register(TASK_MSG_BASE + 3)
class CannotAssignTask(base.AbstractReasonMessage):
    __slots__ = [
        'task_id'
    ] + base.AbstractReasonMessage.__slots__

    class REASON(datastructures.StringEnum):
        NotMyTask = enum.auto()
        NoMoreSubtasks = enum.auto()
        ConcentDisabled = enum.auto()


@library.register(TASK_MSG_BASE + 4)
class ReportComputedTask(TaskMessage):
    """
    Message sent from a Provider to a Requestor, announcing completion
    of the assigned subtask (attached as `task_to_compute`)
    """
    # FIXME this message should be simpler
    RESULT_TYPE = {
        'DATA': 0,
        'FILES': 1,
    }

    TASK_ID_PROVIDERS = ('task_to_compute', )
    EXPECTED_OWNERS = (TaskMessage.OWNER_CHOICES.provider, )

    __slots__ = [
        # TODO why do we need the type here?
        'result_type',
        'node_name',
        'address',
        'node_info',
        'port',
        'key_id',
        'extra_data',
        'eth_account',
        'task_to_compute',
        'size',
        'package_hash',  # sha1 hash of the package file (the zip file)
        'multihash',     # hyperg record used when transferring
                         # the result directly between the nodes
        'secret',
        'options',
    ] + base.Message.__slots__

    @base.verify_slot('task_to_compute', TaskToCompute)
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)


@library.register(TASK_MSG_BASE + 8)
class GetResource(base.Message):
    """Request a resource for a given task"""
    __slots__ = [
        'task_id',
        'resource_header'
    ] + base.Message.__slots__


@library.register(TASK_MSG_BASE + 10)
class SubtaskResultsAccepted(TaskMessage):
    """
    Sent from the Requestor to the Provider, accepting the provider's
    completed task results.

    Having received this message, the Provider expects payment to follow.
    """
    TASK_ID_PROVIDERS = ('task_to_compute', )
    EXPECTED_OWNERS = (TaskMessage.OWNER_CHOICES.requestor, )

    __slots__ = [
        'payment_ts',
        'task_to_compute',
    ] + base.Message.__slots__

    @base.verify_slot('task_to_compute', TaskToCompute)
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)


@library.register(TASK_MSG_BASE + 11)
class SubtaskResultsRejected(TaskMessage, base.AbstractReasonMessage):
    """
    Sent from the Requestor to the Provider, rejecting the provider's
    completed task results

    Alternatively, sent from the Concent to the Provider in case of
    additional verification (when the verdict of the verification is negative)
    or in case of forced results verdict (when the verdict is negative -
    either because the work itself was deemed invalid by the requestor or
    because it had been previously determined authoritatively that the
    results could not have been retrieved.)
    """
    TASK_ID_PROVIDERS = ('report_computed_task', )
    EXPECTED_OWNERS = (TaskMessage.OWNER_CHOICES.requestor,
                       TaskMessage.OWNER_CHOICES.concent)

    __slots__ = [
        'report_computed_task',
    ] + base.AbstractReasonMessage.__slots__

    @enum.unique
    class REASON(enum.Enum):
        VerificationNegative = 'Results verification negative'
        ConcentResourcesFailure = \
            'Concent could not retrieve resources to verify'
        ConcentVerificationNegative = 'Concent results verification negative'
        ForcedResourcesFailure = \
            'Concent reported failure to retrieve the resources to verify'
        ResourcesFailure = \
            'Could not retrieve resources'

    @base.verify_slot('report_computed_task', ReportComputedTask)
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)


@library.register(TASK_MSG_BASE + 15)
class TaskFailure(TaskMessage):
    TASK_ID_PROVIDERS = ('task_to_compute', )
    EXPECTED_OWNERS = (TaskMessage.OWNER_CHOICES.provider, )

    __slots__ = [
        'task_to_compute',
        'err',
    ] + base.Message.__slots__

    @base.verify_slot('task_to_compute', TaskToCompute)
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)


@library.register(TASK_MSG_BASE + 16)
class StartSessionResponse(base.Message):
    __slots__ = ['conn_id'] + base.Message.__slots__

    def __init__(self, conn_id=None, **kwargs):
        """Create message with information that this session was started as
           an answer for a request to start task session
        :param uuid conn_id: connection id for reference
        """
        self.conn_id = conn_id
        super().__init__(**kwargs)


@library.register(TASK_MSG_BASE + 25)
class WaitingForResults(base.Message):
    __slots__ = base.Message.__slots__


@library.register(TASK_MSG_BASE + 26)
class CannotComputeTask(TaskMessage, base.AbstractReasonMessage):
    TASK_ID_PROVIDERS = ('task_to_compute', )
    EXPECTED_OWNERS = (TaskMessage.OWNER_CHOICES.provider, )

    __slots__ = [
        'task_to_compute',
    ] + base.AbstractReasonMessage.__slots__

    class REASON(datastructures.StringEnum):
        WrongCTD = enum.auto()
        WrongKey = enum.auto()
        WrongAddress = enum.auto()
        WrongEnvironment = enum.auto()
        NoSourceCode = enum.auto()
        WrongDockerImages = enum.auto()
        ConcentRequired = enum.auto()
        ConcentDisabled = enum.auto()
        InsufficientBalance = enum.auto()
        InsufficientDeposit = enum.auto()  # GNTB deposit too low
        TooShortDeposit = enum.auto()  # GNTB deposit has too short lock

    @base.verify_slot('task_to_compute', TaskToCompute)
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)


@library.register(TASK_MSG_BASE + 27)
class SubtaskPayment(base.Message):
    """Informs about payment for a subtask.
    It succeeds SubtaskResultsAccepted but could
    be sent after a delay. It is also sent in response to
    SubtaskPaymentRequest. If transaction_id is None it
    should be interpreted as PAYMENT PENDING status.

    :param str subtask_id: accepted subtask id
    :param float reward: payment for computations
    :param str transaction_id: eth transaction id
    :param int block_number: eth blockNumber
    :param dict dict_repr: dictionary representation of a message
    """
    __slots__ = [
        'subtask_id',
        'reward',
        'transaction_id',
        'block_number'
    ] + base.Message.__slots__


@library.register(TASK_MSG_BASE + 28)
class SubtaskPaymentRequest(base.Message):
    """Requests information about payment for a subtask.

    :param str subtask_id: accepted subtask id
    :param dict dict_repr: dictionary representation of a message
    """
    __slots__ = ['subtask_id'] + base.Message.__slots__


@library.register(TASK_MSG_BASE + 29)
class AckReportComputedTask(TaskMessage):
    """
    Sent from Requestor to the Provider, acknowledging reception of the
    `ReportComputedTask` message.

    If the requestor fails to respond to the `ReportComputedTask` message
    before the timeout and Provider then uses Concent to acquire the
    acknowledgement, this message will be sent from the Concent to the Provider
    and has the same effect as the regular Requestor's acknowledgement.
    """
    TASK_ID_PROVIDERS = ('report_computed_task', )
    EXPECTED_OWNERS = (TaskMessage.OWNER_CHOICES.requestor,
                       TaskMessage.OWNER_CHOICES.concent)

    __slots__ = [
        'report_computed_task',
    ] + base.Message.__slots__

    @base.verify_slot('report_computed_task', ReportComputedTask)
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)


@library.register(TASK_MSG_BASE + 30)
class RejectReportComputedTask(TaskMessage, base.AbstractReasonMessage):
    # because other inner messages can also include `TaskToCompute`
    # we need to differentiate between the universal `task_to_compute` accessor
    # and the `TaskToCompute` attached directly into `RejectReportComputedTask`
    # hence `attached_task_to_compute` which includes the directly attached TTC
    #
    TASK_ID_PROVIDERS = ('attached_task_to_compute',
                         'task_failure',
                         'cannot_compute_task', )
    EXPECTED_OWNERS = (TaskMessage.OWNER_CHOICES.requestor,
                       TaskMessage.OWNER_CHOICES.concent)

    @enum.unique
    class REASON(datastructures.StringEnum):
        SubtaskTimeLimitExceeded = enum.auto()
        GotMessageCannotComputeTask = enum.auto()
        GotMessageTaskFailure = enum.auto()

    __slots__ = [
        'attached_task_to_compute',
        'task_failure',
        'cannot_compute_task',
    ] + base.AbstractReasonMessage.__slots__

    @base.verify_slot(
        'attached_task_to_compute',
        TaskToCompute,
        allow_none=True,
    )
    @base.verify_slot(
        'task_failure',
        TaskFailure,
        allow_none=True
    )
    @base.verify_slot(
        'cannot_compute_task',
        CannotComputeTask,
        allow_none=True
    )
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)
