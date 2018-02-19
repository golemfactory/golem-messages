import enum
import functools

from golem_messages import datastructures

from . import base
from . import tasks


CONCENT_MSG_BASE = 4000


class ServiceRefused(base.AbstractReasonMessage):
    """
    Sent (synchronously) as a response from the Concent to the calling party
    (either a Provider or a Requestor), informing them that the Concent refuses
    to execute the requested action because either the message (request) itself
    is corrupted or some of the prerequisites (like e.g. the deposit) are not
    satisfied.

    :param REASON reason: the reason for the refusal
    """
    TYPE = CONCENT_MSG_BASE

    @enum.unique
    class REASON(enum.Enum):
        TooSmallCommunicationPayment = 'TOO_SMALL_COMMUNICATION_PAYMENT'
        TooSmallRequestorDeposit = 'TOO_SMALL_REQUESTOR_DEPOSIT'
        TooSmallProviderDeposit = 'TOO_SMALL_PROVIDER_DEPOSIT'
        SystemOverloaded = 'SYSTEM_OVERLOADED'
        DuplicateRequest = 'DUPLICATE_REQUEST'
        InvalidRequest = 'REQUEST_FORMAT_OR_CONTENT_INVALID'
        ConcentDisabled = 'CONCENT_SERVICE_IS_NOT_ENABLED_FOR_THIS_SUBTASK'

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
        'report_computed_task',
        'result_hash',
    ] + base.Message.__slots__

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        value = tasks.deserialize_report_computed_task(key, value)
        return value


class AckReportComputedTask(base.Message):
    """
    Sent from Requestor to the Provider, acknowledging reception of the
    `ReportComputedTask` message.

    If the requestor fails to respond to the `ReportComputedTask` message
    before the timeout and Provider then uses Concent to acquire the
    acknowledgement, this message will be sent from the Concent to the Provider
    and has the same effect as the regular Requestor's acknowledgement.
    """

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
    """
    Informational message sent from from the Concent to the affected
    Requestor, informing them that the `ReportComputedTask` has been implicitly
    acknowledged by the Concent on behalf of the Requestor.
    (Provider has received the `AckReportComputedTask` from the Concent)

    The state of the Provider/Requestor interaction is assumed to be the same
    as if the Requestor sent the `AckReportComputedTask` on their own.
    """
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

    :param SubtaskResultsRejected subtask_result_rejected:
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

    :param str origin: the origin of the `SubtaskResultsVerify` message
                             that triggered the Concent action

    :param TaskToCompute task_to_compute: TTF containing the task
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
    ] + base.Message.__slots__

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        value = tasks.deserialize_report_computed_task(key, value)
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


class ForceSubtaskResults(base.Message):
    """
    Sent from the Provider to the Concent, in an effort to force the
    `SubtaskResultsAccepted/Rejected` message from the Requestor

    :param AckReportComputedTask ack_report_computed_task: the previously
                                                           delivered
                                                           acknowledgement
                                                           of the reception
                                                           of the RCT message
    """
    TYPE = CONCENT_MSG_BASE + 15

    __slots__ = [
        'ack_report_computed_task',
    ] + base.Message.__slots__

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        value = deserialize_ack_report_computed_task(key, value)
        return value


class ForceSubtaskResultsResponse(base.Message):
    """
    Sent from the Concent to the Provider to communicate the final resolution
    of the forced results verdict.

    Contains one of the following:

    :param SubtaskResultsAccepted subtask_results_accepted:
    :param SubtaskResultsRejected subtask_results_rejected:
    """
    TYPE = CONCENT_MSG_BASE + 16

    __slots__ = [
        'subtask_results_accepted',
        'subtask_results_rejected',
    ] + base.Message.__slots__

    @base.verify_slot('subtask_results_accepted', tasks.SubtaskResultsAccepted)
    @base.verify_slot('subtask_results_rejected', tasks.SubtaskResultsRejected)
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)


class ForceSubtaskResultsRejected(base.AbstractReasonMessage):
    """
    Possible response from the Concent to the Provider to the
    `ForceSubtaskResults` request, when the request is not valid at the time
    it's made.
    """

    TYPE = CONCENT_MSG_BASE + 17

    __slots__ = base.AbstractReasonMessage.__slots__

    class REASON(enum.Enum):
        RequestPremature = 'premature: still within the verification timeout'
        RequestTooLate = 'too late: past the forced communication timeout'


class ForcePayment(base.Message):
    """
    Sent from the Provider to the Concent to force payment for which the
    payment timeout has already passed using Requestor's deposit.

    :param list subtask_results_accepted_list: the list of
        `SubtaskResultsAccepted` messages
    """
    TYPE = CONCENT_MSG_BASE + 18

    __slots__ = [
        'subtask_results_accepted_list'
    ] + base.Message.__slots__

    @base.verify_slot_list('subtask_results_accepted_list',
                           tasks.SubtaskResultsAccepted)
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)


class ForcePaymentCommitted(base.Message):
    """
    Sent from the Concent to the Provider to acknowledge that Provider
    has been paid from the Requestor's deposit - or - to acknowledge that
    the payment is due but the deposit is not enough to cover it.

    Message of the same content is also sent as an information to the Requestor
    whose deposit is affected by the operation.
    """
    TYPE = CONCENT_MSG_BASE + 19

    __slots__ = [
        # the closure time for the Concent's payment,
        # iow, the amount paid should satisfy all pending payments
        # up until this point in time
        'payment_ts',
        # the requestor's golem node address
        'task_owner_key',
        # provider's ethereum address
        'provider_eth_account',
        # the amount paid to the requestor
        'amount_paid',
        # the message recipient's role in the transaction
        'recipient_type',
        # the amount that could not have been satisfied from the deposit
        'amount_pending',
    ]

    class Actor(enum.Enum):
        Requestor = "requestor"
        Provider = "provider"

    ENUM_SLOTS = {
        'recipient_type': Actor,
    }


class ForcePaymentRejected(base.AbstractReasonMessage):
    """
    Sent from the Concent to the Provider to inform them that Concent was
    unable to find the tasks that need to be paid for - because either they
    have indeed been paid for already or because they are not overdue yet.

    (the latter means that most likely, the Provider's clock is out of sync)
    """
    TYPE = CONCENT_MSG_BASE + 20

    @enum.unique
    class REASON(enum.Enum):
        NoUnsettledTasksFound = 'no unsettled tasks found'
        TimestampError = 'timestamp error - subtasks are not overdue yet'

    __slots__ = [
        'force_payment'
    ] + base.AbstractReasonMessage.__slots__

    @base.verify_slot('force_payment', ForcePayment)
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)


class ForceReportComputedTaskResponse(base.AbstractReasonMessage):
    """Sent from Concent to Provider as a response to ForceReportComputedTask.
    """
    TYPE = CONCENT_MSG_BASE + 21

    @enum.unique
    class REASON(enum.Enum):
        # Ack received from requestor attached as ack_report_computed_task
        AckFromRequestor = 'ack_from_requestor'
        # Reject received from requestor attached as reject_report_computed_task
        RejectFromRequestor = 'reject_from_requestor'
        # Concent refused service because of subtask timeout
        SubtaskTimeout = 'subtask_timeout'
        # Ack generated and signed by Concent attached
        # as ack_report_computed_task
        ConcentAck = 'concent_ack'

    __slots__ = base.AbstractReasonMessage.__slots__ + [
        # AckReportComputedTask sent from Requestor to Concent
        # OR generated and signed by Concent
        'ack_report_computed_task',
        # RejectReportComputedTask sent from Requestor to Concent
        'reject_report_computed_task',
    ]

    @base.verify_slot(
        'ack_report_computed_task',
        AckReportComputedTask,
    )
    @base.verify_slot(
        'reject_report_computed_task',
        RejectReportComputedTask,
    )
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)


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
