import enum
import functools

from ethereum.utils import sha3

from golem_messages import datastructures
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

class TaskMessageMixin():
    __slots__ = []
    TASK_ID_PROVIDERS = ()

    def _get_task_value(self, attr_name):
        msgs = [getattr(self, slot)
                for slot in self.TASK_ID_PROVIDERS
                if hasattr(self, slot)]

        for msg in msgs:
            if hasattr(msg, attr_name):
                return getattr(msg, attr_name)
        return None

    @property
    def task_id(self):
        return self._get_task_value('task_id')

    @property
    def subtask_id(self):
        return self._get_task_value('subtask_id')


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


class TaskToCompute(TaskMessageMixin, base.Message):
    TYPE = TASK_MSG_BASE + 2

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


class CannotAssignTask(base.AbstractReasonMessage):
    TYPE = TASK_MSG_BASE + 3

    __slots__ = [
        'task_id'
    ] + base.AbstractReasonMessage.__slots__

    class REASON(enum.Enum):
        NotMyTask = 'not_my_task'
        NoMoreSubtasks = 'no_more_subtasks'


class ReportComputedTask(TaskMessageMixin, base.Message):
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

    __slots__ = [
        # @todo I'd remove the `subtask_id` from here as it's
        # present within `task_to_compute` anyway...
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


class SubtaskResultsAccepted(TaskMessageMixin, base.Message):
    """
    Sent from the Requestor to the Provider, accepting the provider's
    completed task results.

    Having received this message, the Provider expects payment to follow.
    """
    TYPE = TASK_MSG_BASE + 10
    TASK_ID_PROVIDERS = ('task_to_compute', )

    __slots__ = [
        'payment_ts',
        'task_to_compute',
    ] + base.Message.__slots__

    @base.verify_slot('task_to_compute', TaskToCompute)
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)


class SubtaskResultsRejected(TaskMessageMixin, base.AbstractReasonMessage):
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


class TaskFailure(TaskMessageMixin, base.Message):
    TYPE = TASK_MSG_BASE + 15
    TASK_ID_PROVIDERS = ('task_to_compute', )

    __slots__ = [
        'subtask_id',
        'err',
        'task_to_compute',
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


class CannotComputeTask(base.AbstractReasonMessage):
    TYPE = TASK_MSG_BASE + 26
    TASK_ID_PROVIDERS = ('task_to_compute', )

    __slots__ = [
        'subtask_id',
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
