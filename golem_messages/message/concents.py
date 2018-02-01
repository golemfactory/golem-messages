import enum
import functools

from golem_messages import datastructures

from . import base
from . import tasks


CONCENT_MSG_BASE = 4000


class ServiceRefused(base.AbstractReasonMessage):
    TYPE = CONCENT_MSG_BASE

    @enum.unique
    class REASON(enum.Enum):
        TooSmallCommunicationPayment = 'TOO_SMALL_COMMUNICATION_PAYMENT'
        TooSmallRequestorDeposit = 'TOO_SMALL_REQUESTOR_DEPOSIT'
        TooSmallProviderDeposit = 'TOO_SMALL_PROVIDER_DEPOSIT'
        SystemOverloaded = 'SYSTEM_OVERLOADED'

    __slots__ = [
        'subtask_id',
        'task_to_compute',
    ] + base.AbstractReasonMessage.__slots__

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        return tasks.deserialize_task_to_compute(key, value)


class ForceReportComputedTask(base.Message):
    """
    Message sent from a Provider to the Concent, requesting an forced
    acknowledgment of the reception of the `ReportComputedTask` message
    from the Requestor.

    The same, rewritten message is then sent from the Concent to the Requestor.
    """
    TYPE = CONCENT_MSG_BASE + 1

    __slots__ = [
        'task_to_compute',
        'result_hash',
    ] + base.Message.__slots__

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        return tasks.deserialize_task_to_compute(key, value)


class AckReportComputedTask(base.Message):
    TYPE = CONCENT_MSG_BASE + 2

    __slots__ = [
        'subtask_id',
        'task_to_compute',
    ] + base.Message.__slots__

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        return tasks.deserialize_task_to_compute(key, value)


class RejectReportComputedTask(base.AbstractReasonMessage):
    TYPE = CONCENT_MSG_BASE + 3

    @enum.unique
    class REASON(enum.Enum):
        """
        since python 3.6 it's possible to do this:

        class StringEnum(str, enum.Enum):
            def _generate_next_value_(name: str, *_):
                return name

        @enum.unique
        class REASON(StringEnum):
            TASK_TIME_LIMIT_EXCEEDED = enum.auto()
            SUBTASK_TIME_LIMIT_EXCEEDED = enum.auto()
            GOT_MESSAGE_CANNOT_COMPUTE_TASK = enum.auto()
            GOT_MESSAGE_TASK_FAILURE = enum.auto()
        """
        TaskTimeLimitExceeded = 'TASK_TIME_LIMIT_EXCEEDED'
        SubtaskTimeLimitExceeded = 'SUBTASK_TIME_LIMIT_EXCEEDED'
        GotMessageCannotComputeTask = 'GOT_MESSAGE_CANNOT_COMPUTE_TASK'
        GotMessageTaskFailure = 'GOT_MESSAGE_TASK_FAILURE'

    __slots__ = [
        'subtask_id',
        'task_to_compute',
        'task_failure',
        'cannot_compute_task',
    ] + base.AbstractReasonMessage.__slots__

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        value = tasks.deserialize_task_to_compute(key, value)
        value = deserialize_task_failure(key, value)
        value = deserialize_cannot_compute_task(key, value)
        return value


class VerdictReportComputedTask(base.Message):
    TYPE = CONCENT_MSG_BASE + 4

    __slots__ = [
        'force_report_computed_task',
        'ack_report_computed_task',
    ] + base.Message.__slots__

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        value = deserialize_force_report_computed_task(key, value)
        value = deserialize_ack_report_computed_task(key, value)
        return value


class FileTransferToken(base.Message):
    TYPE = CONCENT_MSG_BASE + 5

    __slots__ = [
        'subtask_id',
        'token_expiration_deadline',
        'storage_cluster_address',
        'authorized_client_public_key',
        'operation',
        'files',
    ] + base.Message.__slots__

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


class SubtaskResultsVerify(base.Message):
    """
    Message sent from a Provider to the Concent, requesting additional
    verification in case the result had been rejected by the Requestor

    :param (slot)SubtaskResultsRejected subtask_result_rejected:
           the original reject message

    """
    TYPE = CONCENT_MSG_BASE + 6

    __slots__ = [
        'subtask_result_rejected',
    ] + base.Message.__slots__

    def deserialize_slot(self, key, value):
        return base.deserialize_verify(
            key,
            super().deserialize_slot(key, value),
            verify_key='subtask_result_rejected',
            verify_class=tasks.SubtaskResultsRejected
        )


class AckSubtaskResultsVerify(base.Message):
    """
    Message sent from the Concent to the Provider to acknowledge reception
    of the `SubtaskResultsVerify` message
    """
    TYPE = CONCENT_MSG_BASE + 7

    __slots__ = [
        'subtask_result_verify',
    ] + base.Message.__slots__

    def deserialize_slot(self, key, value):
        return base.deserialize_verify(
            key,
            super().deserialize_slot(key, value),
            verify_key='subtask_result_verify',
            verify_class=SubtaskResultsVerify
        )


class SubtaskResultsSettled(base.Message):
    """
    Message sent from the Concent to both the Provider and the Requestor
    informing of positive acceptance of the results by the Concent and the
    fact that the payment has been force-sent to the Provider

    :param (slot)str origin: the origin of the `SubtaskResultsVerify` message
                             that triggered the Concent action

    :param (slot)TaskToCompute task_to_compute: TTF containing the task
                                                that the settlement
                                                pertains to

    """

    TYPE = CONCENT_MSG_BASE + 8

    @enum.unique
    class Origin(enum.Enum):
        ResultsAcceptedTimeout = 'results_accepted_timeout'
        ResultsRejected = 'results_rejected'

    ENUM_SLOTS = {
        'origin': Origin,
    }

    __slots__ = [
        'origin',
        'task_to_compute',
    ] + base.Message.__slots__

    def deserialize_slot(self, key, value):
        return base.deserialize_verify(
            key,
            super().deserialize_slot(key, value),
            verify_key='task_to_compute',
            verify_class=tasks.TaskToCompute,
        )


class ForceGetTaskResult(base.Message):
    TYPE = CONCENT_MSG_BASE + 9

    __slots__ = [
        'report_computed_task',
        'force_report_computed_task',
    ] + base.Message.__slots__

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        value = tasks.deserialize_report_computed_task(key, value)
        value = deserialize_force_report_computed_task(key, value)
        return value


class ForceGetTaskResultAck(base.Message):
    TYPE = CONCENT_MSG_BASE + 10

    __slots__ = [
        'force_get_task_result',
    ] + base.Message.__slots__

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        return deserialize_force_get_task_result(key, value)


class ForceGetTaskResultFailed(base.Message):
    TYPE = CONCENT_MSG_BASE + 11

    __slots__ = [
        'task_to_compute',
    ] + base.Message.__slots__

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        return tasks.deserialize_task_to_compute(key, value)


class ForceGetTaskResultRejected(base.AbstractReasonMessage):
    TYPE = CONCENT_MSG_BASE + 12

    __slots__ = [
        'force_get_task_result',
    ] + base.AbstractReasonMessage.__slots__

    class REASON(enum.Enum):
        OperationAlreadyInitiated = 'operation_already_initiated'
        AcceptanceTimeLimitExceeded = 'acceptance_time_limit_exceeded'

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        return deserialize_force_get_task_result(key, value)


class ForceGetTaskResultUpload(base.Message):
    TYPE = CONCENT_MSG_BASE + 13

    __slots__ = [
        'force_get_task_result',
        'file_transfer_token',
    ] + base.Message.__slots__

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        value = deserialize_force_get_task_result(key, value)
        value = deserialize_file_transfer_token(key, value)
        return value


class ForceGetTaskResultDownload(base.Message):
    TYPE = CONCENT_MSG_BASE + 14

    __slots__ = [
        'force_get_task_result',
        'file_transfer_token',
    ] + base.Message.__slots__

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        value = deserialize_force_get_task_result(key, value)
        value = deserialize_file_transfer_token(key, value)
        return value


deserialize_task_failure = functools.partial(
    base.deserialize_verify,
    verify_key='task_failure',
    verify_class=tasks.TaskFailure,
)

deserialize_cannot_compute_task = functools.partial(
    base.deserialize_verify,
    verify_key='cannot_compute_task',
    verify_class=tasks.CannotComputeTask,
)

deserialize_force_report_computed_task = functools.partial(
    base.deserialize_verify,
    verify_key='force_report_computed_task',
    verify_class=ForceReportComputedTask,
)

deserialize_ack_report_computed_task = functools.partial(
    base.deserialize_verify,
    verify_key='ack_report_computed_task',
    verify_class=AckReportComputedTask,
)

deserialize_force_get_task_result = functools.partial(
    base.deserialize_verify,
    verify_key='force_get_task_result',
    verify_class=ForceGetTaskResult,
)

deserialize_file_transfer_token = functools.partial(
    base.deserialize_verify,
    verify_key='file_transfer_token',
    verify_class=FileTransferToken,
)

deserialize_force_get_task_result_failed = functools.partial(
    base.deserialize_verify,
    verify_key='force_get_task_result_failed',
    verify_class=ForceGetTaskResultFailed,
)
