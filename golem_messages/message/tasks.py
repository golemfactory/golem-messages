import enum
import functools

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
        'return_address': '',
        'return_port': 0,
        # task_owner is a dict from golem.network.p2p.node.Node.to_dict()
        # - requestor
        'task_owner': None,
        'key_id': 0,
        'working_directory': '',
        'performance': 0,
        'environment': '',
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


class TaskToCompute(base.Message):
    TYPE = TASK_MSG_BASE + 2

    __slots__ = [
        'requestor_id',
        'requestor_public_key',
        'provider_id',
        'provider_public_key',
        'compute_task_def',
    ] + base.Message.__slots__

    def load_slots(self, slots):
        super().load_slots(slots)
        self.validate_compute_task_def(self.compute_task_def)

    def validate_compute_task_def(self, value):
        try:
            node_key = value['task_owner']['key']
        except (TypeError, KeyError):
            return
        if node_key != self.requestor_id:
            errmsg = "requestor_id: {} != compute_task_def['task_owner']['key']"
            raise exceptions.FieldError(
                errmsg.format(self.requestor_id, node_key),
                field='compute_task_def',
                value=value,
            )

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        if key == 'compute_task_def':
            value = ComputeTaskDef(value)
        return value


class CannotAssignTask(base.AbstractReasonMessage):
    TYPE = TASK_MSG_BASE + 3

    __slots__ = [
        'task_id'
    ] + base.AbstractReasonMessage.__slots__

    class REASON(enum.Enum):
        NotMyTask = 'not_my_task'
        NoMoreSubtasks = 'no_more_subtasks'


class ReportComputedTask(base.Message):
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
        'size',
        'checksum',
    ] + base.Message.__slots__

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        return deserialize_task_to_compute(key, value)


class GetTaskResult(base.Message):
    """Request task result"""
    TYPE = TASK_MSG_BASE + 5

    __slots__ = ['subtask_id'] + base.Message.__slots__


class TaskResultHash(base.Message):
    TYPE = TASK_MSG_BASE + 7

    __slots__ = [
        'subtask_id',
        'multihash',
        'secret',
        'options'
    ] + base.Message.__slots__


class GetResource(base.Message):
    """Request a resource for a given task"""
    TYPE = TASK_MSG_BASE + 8

    __slots__ = [
        'task_id',
        'resource_header'
    ] + base.Message.__slots__


class SubtaskResultsAccepted(base.Message):
    TYPE = TASK_MSG_BASE + 10

    __slots__ = [
        'subtask_id',
        'payment_ts'
    ] + base.Message.__slots__


class SubtaskResultsRejected(base.Message):
    TYPE = TASK_MSG_BASE + 11

    __slots__ = ['subtask_id'] + base.Message.__slots__


class DeltaParts(base.Message):
    """base.Message with resource description in form of "delta parts".

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
    ] + base.Message.__slots__


class TaskFailure(base.Message):
    TYPE = TASK_MSG_BASE + 15

    __slots__ = [
        'subtask_id',
        'err',
        'task_to_compute',
    ] + base.Message.__slots__

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        return deserialize_task_to_compute(key, value)


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

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        return deserialize_task_to_compute(key, value)


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


deserialize_task_to_compute = functools.partial(
    base.deserialize_verify,
    verify_key='task_to_compute',
    verify_class=TaskToCompute,
)

deserialize_report_computed_task = functools.partial(
    base.deserialize_verify,
    verify_key='report_computed_task',
    verify_class=ReportComputedTask,
)
