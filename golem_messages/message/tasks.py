import enum
import functools

from ethereum.utils import sha3

from golem_messages import datastructures
from golem_messages import exceptions
from golem_messages import validators

from . import base

TASK_MSG_BASE = 2000


class ComputeTaskDef(datastructures.FrozenDict):
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

    def __setitem__(self, key, value):
        validator = getattr(self, 'validate_{}'.format(key), None)
        if validator is not None:
            validator(value=value)  # pylint: disable=not-callable
        super().__setitem__(key, value)

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
                self.task_to_compute.provider_public_key,
            TaskMessage.OWNER_CHOICES.requestor:
                self.task_to_compute.requestor_public_key,
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
                        self.task_to_compute.provider_public_key)

        if requestor_public_key:
            assert_role('requestor',
                        requestor_public_key,
                        self.task_to_compute.requestor_public_key)

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


class WantToComputeTask(base.Message):
    TYPE = TASK_MSG_BASE + 1

    __slots__ = [
        'node_name',
        'task_id',
        'perf_index',
        'max_resource_size',
        'max_memory_size',
        'num_cores',
        'price'
    ] + base.Message.__slots__


class TaskToCompute(TaskMessage):
    TYPE = TASK_MSG_BASE + 2
    EXPECTED_OWNERS = (TaskMessage.OWNER_CHOICES.requestor, )

    __slots__ = [
        'requestor_id',  # a.k.a. node id
        'requestor_public_key',  # key used for msg signing and encryption
        'requestor_ethereum_public_key',  # used for transactions on blockchain
        'provider_id',  # a.k.a. node id
        'provider_public_key',  # key used for msg signing and encryption
        'provider_ethereum_public_key',  # used for transactions on blockchain
        'compute_task_def',
        'package_hash',
        'concent_enabled',
        'price', # total subtask price computed as `price * subtask_timeout`
    ] + base.Message.__slots__

    def __init__(self, header: datastructures.MessageHeader = None,
                 sig=None, slots=None, deserialized=False, **kwargs):
        super().__init__(header=header, sig=sig, slots=slots,
                         deserialized=deserialized, **kwargs)

        # defaults to `True` if not specified explicitly as `False`
        if self.concent_enabled is None:
            self.concent_enabled = True

    @property
    def requestor_ethereum_address(self):
        return '0x{}'.format(
            sha3(self.requestor_ethereum_public_key)[12:].hex(),
        )

    @property
    def provider_ethereum_address(self):
        return '0x{}'.format(
            sha3(self.provider_ethereum_public_key)[12:].hex(),
        )

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        if key == 'compute_task_def':
            value = ComputeTaskDef(value)
        if key == 'price':
            validators.validate_integer(
                field_name='price',
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


class CannotAssignTask(base.AbstractReasonMessage):
    TYPE = TASK_MSG_BASE + 3

    __slots__ = [
        'task_id'
    ] + base.AbstractReasonMessage.__slots__

    class REASON(enum.Enum):
        NotMyTask = 'not_my_task'
        NoMoreSubtasks = 'no_more_subtasks'


class ReportComputedTask(TaskMessage):
    """
    Message sent from a Provider to a Requestor, announcing completion
    of the assigned subtask (attached as `task_to_compute`)
    """
    # FIXME this message should be simpler
    TYPE = TASK_MSG_BASE + 4
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


class GetResource(base.Message):
    """Request a resource for a given task"""
    TYPE = TASK_MSG_BASE + 8

    __slots__ = [
        'task_id',
        'resource_header'
    ] + base.Message.__slots__


class SubtaskResultsAccepted(TaskMessage):
    """
    Sent from the Requestor to the Provider, accepting the provider's
    completed task results.

    Having received this message, the Provider expects payment to follow.
    """
    TYPE = TASK_MSG_BASE + 10
    TASK_ID_PROVIDERS = ('task_to_compute', )
    EXPECTED_OWNERS = (TaskMessage.OWNER_CHOICES.requestor, )

    __slots__ = [
        'payment_ts',
        'task_to_compute',
    ] + base.Message.__slots__

    @base.verify_slot('task_to_compute', TaskToCompute)
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)


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
    TYPE = TASK_MSG_BASE + 11
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


class TaskFailure(TaskMessage):
    TYPE = TASK_MSG_BASE + 15
    TASK_ID_PROVIDERS = ('task_to_compute', )
    EXPECTED_OWNERS = (TaskMessage.OWNER_CHOICES.provider, )

    __slots__ = [
        'task_to_compute',
        'err',
    ] + base.Message.__slots__

    @base.verify_slot('task_to_compute', TaskToCompute)
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)


class StartSessionResponse(base.Message):
    TYPE = TASK_MSG_BASE + 16

    __slots__ = ['conn_id'] + base.Message.__slots__

    def __init__(self, conn_id=None, **kwargs):
        """Create message with information that this session was started as
           an answer for a request to start task session
        :param uuid conn_id: connection id for reference
        """
        self.conn_id = conn_id
        super().__init__(**kwargs)


class WaitingForResults(base.Message):
    TYPE = TASK_MSG_BASE + 25

    __slots__ = base.Message.__slots__


class CannotComputeTask(TaskMessage, base.AbstractReasonMessage):
    TYPE = TASK_MSG_BASE + 26
    TASK_ID_PROVIDERS = ('task_to_compute', )
    EXPECTED_OWNERS = (TaskMessage.OWNER_CHOICES.provider, )

    __slots__ = [
        'task_to_compute',
    ] + base.AbstractReasonMessage.__slots__

    class REASON(enum.Enum):
        WrongCTD = 'wrong_ctd'
        WrongKey = 'wrong_key'
        WrongAddress = 'wrong_address'
        WrongEnvironment = 'wrong_environment'
        NoSourceCode = 'no_source_code'
        WrongDockerImages = 'wrong_docker_images'

    @base.verify_slot('task_to_compute', TaskToCompute)
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)


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

    TYPE = TASK_MSG_BASE + 27

    __slots__ = [
        'subtask_id',
        'reward',
        'transaction_id',
        'block_number'
    ] + base.Message.__slots__


class SubtaskPaymentRequest(base.Message):
    """Requests information about payment for a subtask.

    :param str subtask_id: accepted subtask id
    :param dict dict_repr: dictionary representation of a message
    """

    TYPE = TASK_MSG_BASE + 28

    __slots__ = ['subtask_id'] + base.Message.__slots__


class AckReportComputedTask(TaskMessage):
    """
    Sent from Requestor to the Provider, acknowledging reception of the
    `ReportComputedTask` message.

    If the requestor fails to respond to the `ReportComputedTask` message
    before the timeout and Provider then uses Concent to acquire the
    acknowledgement, this message will be sent from the Concent to the Provider
    and has the same effect as the regular Requestor's acknowledgement.
    """

    TYPE = TASK_MSG_BASE + 29
    TASK_ID_PROVIDERS = ('report_computed_task', )
    EXPECTED_OWNERS = (TaskMessage.OWNER_CHOICES.requestor, )

    __slots__ = [
        'report_computed_task',
    ] + base.Message.__slots__

    @base.verify_slot('report_computed_task', ReportComputedTask)
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)


class RejectReportComputedTask(TaskMessage, base.AbstractReasonMessage):
    TYPE = TASK_MSG_BASE + 30

    #
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

    @base.verify_slot('attached_task_to_compute_', TaskToCompute)
    @base.verify_slot('task_failure', TaskFailure)
    @base.verify_slot('cannot_compute_task', CannotComputeTask)
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)
