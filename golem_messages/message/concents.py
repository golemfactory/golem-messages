import enum

from golem_messages import datastructures
from golem_messages import exceptions
from golem_messages.register import library

from . import base
from . import tasks


CONCENT_MSG_BASE = 4000


@library.register(CONCENT_MSG_BASE)
class ServiceRefused(tasks.TaskMessage, base.AbstractReasonMessage):
    """
    Sent (synchronously) as a response from the Concent to the calling party
    (either a Provider or a Requestor), informing them that the Concent refuses
    to execute the requested action because either the message (request) itself
    is corrupted or some of the prerequisites (like e.g. the deposit) are not
    satisfied.

    :param REASON reason: the reason for the refusal
    """
    TASK_ID_PROVIDERS = ('task_to_compute', )
    EXPECTED_OWNERS = (tasks.TaskMessage.OWNER_CHOICES.concent, )
    MSG_SLOTS = {
        'task_to_compute': tasks.TaskToCompute,
    }

    @enum.unique
    class REASON(enum.Enum):
        TooSmallCommunicationPayment = 'TOO_SMALL_COMMUNICATION_PAYMENT'
        TooSmallRequestorDeposit = 'TOO_SMALL_REQUESTOR_DEPOSIT'
        TooSmallProviderDeposit = 'TOO_SMALL_PROVIDER_DEPOSIT'
        SystemOverloaded = 'SYSTEM_OVERLOADED'
        DuplicateRequest = 'DUPLICATE_REQUEST'
        InvalidRequest = 'REQUEST_FORMAT_OR_CONTENT_INVALID'
        ConcentDisabled = 'CONCENT_SERVICE_IS_NOT_ENABLED_FOR_THIS_SUBTASK'
        UnsupportedProtocolVersion = 'UNSUPPORTED_PROTOCOL_VERSION'
        PriceNotPositive = 'PRICE_NOT_POSITIVE'

    __slots__ = [
        'task_to_compute',
    ] + base.AbstractReasonMessage.__slots__


@library.register(CONCENT_MSG_BASE + 1)
class ForceReportComputedTask(tasks.TaskMessage):
    """
    Message sent from a Provider to the Concent, requesting an forced
    acknowledgment of the reception of the `ReportComputedTask` message
    from the Requestor.

    The same, rewritten message is then sent from the Concent to the Requestor.
    """
    TASK_ID_PROVIDERS = ('report_computed_task', )
    EXPECTED_OWNERS = (tasks.TaskMessage.OWNER_CHOICES.provider,
                       tasks.TaskMessage.OWNER_CHOICES.concent)
    MSG_SLOTS = {
        'report_computed_task': tasks.ReportComputedTask,
    }

    __slots__ = [
        'report_computed_task',
        'result_hash',
    ] + base.Message.__slots__


@library.register(CONCENT_MSG_BASE + 4)
class VerdictReportComputedTask(tasks.TaskMessage):
    """
    Informational message sent from from the Concent to the affected
    Requestor, informing them that the `ReportComputedTask` has been implicitly
    acknowledged by the Concent on behalf of the Requestor.
    (Provider has received the `AckReportComputedTask` from the Concent)

    The state of the Provider/Requestor interaction is assumed to be the same
    as if the Requestor sent the `AckReportComputedTask` on their own.
    """
    TASK_ID_PROVIDERS = ('force_report_computed_task',
                         'ack_report_computed_task', )
    EXPECTED_OWNERS = (tasks.TaskMessage.OWNER_CHOICES.concent, )
    MSG_SLOTS = {
        'force_report_computed_task': ForceReportComputedTask,
        'ack_report_computed_task': tasks.AckReportComputedTask,
    }

    __slots__ = [
        'force_report_computed_task',
        'ack_report_computed_task',
    ] + base.Message.__slots__

    def is_valid(self):
        ttcs_tuple = (
            self.ack_report_computed_task.
            report_computed_task.task_to_compute,
            self.force_report_computed_task.
            report_computed_task.task_to_compute,
        )

        if not ttcs_tuple.count(ttcs_tuple[0]) == len(ttcs_tuple):
            raise exceptions.ValidationError(
                'Multiple, differing TaskToCompute messages in %s' % self)

        return True


@library.register(CONCENT_MSG_BASE + 5)
class FileTransferToken(base.Message):
    """
    Sent from the Concent (usually, as an attachment in another message) to
    enable upload/download of files pertaining to the subtask at hand.
    """
    @enum.unique
    class Operation(datastructures.StringEnum):
        upload = enum.auto()
        download = enum.auto()

    ENUM_SLOTS = {
        'operation': Operation,
    }

    __slots__ = [
        'subtask_id',
        'token_expiration_deadline',
        'storage_cluster_address',
        'authorized_client_public_key',
        'operation',
        'files',
    ] + base.Message.__slots__

    def deserialize_slot(self, key, value):
        def deserialize_fileinfo(f):
            try:
                f['category'] = FileTransferToken.FileInfo.Category(
                    f.get('category')
                )
            except ValueError:
                pass
            return FileTransferToken.FileInfo(f)

        value = super().deserialize_slot(key, value)
        if key == 'files':
            value = [deserialize_fileinfo(f) for f in value]
        return value

    class FileInfo(datastructures.ValidatingDict, datastructures.FrozenDict):
        """Represents the subtask file metadata."""

        @enum.unique
        class Category(datastructures.StringEnum):
            results = enum.auto()  # the results package of a computed task
            resources = enum.auto()   # the task's resources from the requestor

        ITEMS = {
            'path': '',
            'checksum': '',
            'size': 0,
            'category': Category.results  # for now (backwards-compatibility)
        }

        def validate_category(self, value):
            if value not in self.Category:
                raise exceptions.FieldError(
                    "`category` must be one of %s, got: " % [
                        c for c in self.Category],
                    field='category',
                    value=value,
                )

    @property
    def is_upload(self):
        return self.operation == self.Operation.upload

    @property
    def is_download(self):
        return self.operation == self.Operation.download

    def get_file_info(self, category: FileInfo.Category):
        """
        retrieves the `FileInfo` object of the given category from the
        token's `files` list

        as, it doesn't make sense for the `files` list to contain multiple
        files of the same category, we're just returning the first found file
        """

        for fi in self.files:
            if fi.get('category') == category:
                return fi

        return None


@library.register(CONCENT_MSG_BASE + 6)
class SubtaskResultsVerify(tasks.TaskMessage):
    """
    Message sent from a Provider to the Concent, requesting additional
    verification in case the result had been rejected by the Requestor

    :param SubtaskResultsRejected subtask_results_rejected:
           the original reject message

    """
    TASK_ID_PROVIDERS = ('subtask_results_rejected', )
    EXPECTED_OWNERS = (tasks.TaskMessage.OWNER_CHOICES.provider, )
    MSG_SLOTS = {
        'subtask_results_rejected': tasks.SubtaskResultsRejected,
    }

    __slots__ = [
        'subtask_results_rejected',
    ] + base.Message.__slots__


@library.register(CONCENT_MSG_BASE + 7)
class AckSubtaskResultsVerify(tasks.TaskMessage):
    """
    Message sent from the Concent to the Provider to acknowledge reception
    of the `SubtaskResultsVerify` message and more importantly, to pass the
    required `FileTransferToken` message to the Provider which must use it
    to upload files to the Concent service.
    """
    TASK_ID_PROVIDERS = ('subtask_results_verify', )
    EXPECTED_OWNERS = (tasks.TaskMessage.OWNER_CHOICES.concent, )
    MSG_SLOTS = {
        'subtask_results_verify': SubtaskResultsVerify,
        'file_transfer_token': FileTransferToken,
    }

    __slots__ = [
        'subtask_results_verify',
        'file_transfer_token',
    ] + base.Message.__slots__


@library.register(CONCENT_MSG_BASE + 8)
class SubtaskResultsSettled(tasks.TaskMessage):
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
    TASK_ID_PROVIDERS = ('task_to_compute', )
    EXPECTED_OWNERS = (tasks.TaskMessage.OWNER_CHOICES.concent, )

    @enum.unique
    class Origin(enum.Enum):
        ResultsAcceptedTimeout = 'results_accepted_timeout'
        ResultsRejected = 'results_rejected'

    ENUM_SLOTS = {
        'origin': Origin,
    }
    MSG_SLOTS = {
        'task_to_compute': tasks.TaskToCompute,
    }

    __slots__ = [
        'origin',
        'task_to_compute',
    ] + base.Message.__slots__


@library.register(CONCENT_MSG_BASE + 9)
class ForceGetTaskResult(tasks.TaskMessage):
    """
    Sent from the Requestor to the Concent, requesting assistance in
    downloading the results from the Provider.
    """
    TASK_ID_PROVIDERS = ('report_computed_task', )
    EXPECTED_OWNERS = (tasks.TaskMessage.OWNER_CHOICES.requestor, )

    __slots__ = [
        'report_computed_task',
    ] + base.Message.__slots__

    MSG_SLOTS = {
        'report_computed_task': tasks.ReportComputedTask,
    }


@library.register(CONCENT_MSG_BASE + 10)
class AckForceGetTaskResult(tasks.TaskMessage):
    """
    Sent from the Concent to the Requestor to acknowledge reception of the
    `ForceGetTaskResult` message
    """
    TASK_ID_PROVIDERS = ('force_get_task_result', )
    EXPECTED_OWNERS = (tasks.TaskMessage.OWNER_CHOICES.concent, )

    __slots__ = [
        'force_get_task_result',
    ] + base.Message.__slots__

    MSG_SLOTS = {
        'force_get_task_result': ForceGetTaskResult,
    }


@library.register(CONCENT_MSG_BASE + 11)
class ForceGetTaskResultFailed(tasks.TaskMessage):
    """
    Sent from the Concent to the Requestor to announce a failure to retrieve
    the results from the Provider.

    Having received this message, the Requestor can use it later on
    to reject any attempt at forced acceptance by proving the result
    could not have been downloaded in the first place.
    """
    TASK_ID_PROVIDERS = ('task_to_compute', )
    EXPECTED_OWNERS = (tasks.TaskMessage.OWNER_CHOICES.concent, )

    __slots__ = [
        'task_to_compute',
    ] + base.Message.__slots__

    MSG_SLOTS = {
        'task_to_compute': tasks.TaskToCompute,
    }


@library.register(CONCENT_MSG_BASE + 12)
class ForceGetTaskResultRejected(tasks.TaskMessage,
                                 base.AbstractReasonMessage):
    """
    Sent from the Concent to the Requestor to notify them that the
    `ForceGetTaskResult` message was not allowed at this time
    """
    TASK_ID_PROVIDERS = ('force_get_task_result', )
    EXPECTED_OWNERS = (tasks.TaskMessage.OWNER_CHOICES.concent, )
    MSG_SLOTS = {
        'force_get_task_result': ForceGetTaskResult,
    }

    __slots__ = [
        'force_get_task_result',
    ] + base.AbstractReasonMessage.__slots__

    class REASON(enum.Enum):
        AcceptanceTimeLimitExceeded = 'acceptance_time_limit_exceeded'


@library.register(CONCENT_MSG_BASE + 13)
class ForceGetTaskResultUpload(tasks.TaskMessage):
    """
    Sent from the Concent to the Provider to notify them they can (and need to)
    upload the results to them
    """
    TASK_ID_PROVIDERS = ('force_get_task_result', )
    EXPECTED_OWNERS = (tasks.TaskMessage.OWNER_CHOICES.concent, )
    MSG_SLOTS = {
        'force_get_task_result': ForceGetTaskResult,
        'file_transfer_token': FileTransferToken,
    }

    __slots__ = [
        'force_get_task_result',
        'file_transfer_token',
    ] + base.Message.__slots__


@library.register(CONCENT_MSG_BASE + 14)
class ForceGetTaskResultDownload(tasks.TaskMessage):
    """
    Sent from the Concent to the Requestor to notify them that the results
    are available for download.
    """
    TASK_ID_PROVIDERS = ('force_get_task_result', )
    EXPECTED_OWNERS = (tasks.TaskMessage.OWNER_CHOICES.concent, )
    MSG_SLOTS = {
        'force_get_task_result': ForceGetTaskResult,
        'file_transfer_token': FileTransferToken,
    }

    __slots__ = [
        'force_get_task_result',
        'file_transfer_token',
    ] + base.Message.__slots__


@library.register(CONCENT_MSG_BASE + 15)
class ForceSubtaskResults(tasks.TaskMessage):
    """
    Sent from the Provider to the Concent, in an effort to force the
    `SubtaskResultsAccepted/Rejected` message from the Requestor

    :param AckReportComputedTask ack_report_computed_task: the previously
                                                           delivered
                                                           acknowledgement
                                                           of the reception
                                                           of the RCT message
    """
    TASK_ID_PROVIDERS = ('ack_report_computed_task', )
    EXPECTED_OWNERS = (
        tasks.TaskMessage.OWNER_CHOICES.provider,
        tasks.TaskMessage.OWNER_CHOICES.concent,
    )
    MSG_SLOTS = {
        'ack_report_computed_task': tasks.AckReportComputedTask,
    }

    __slots__ = [
        'ack_report_computed_task',
    ] + base.Message.__slots__


@library.register(CONCENT_MSG_BASE + 16)
class ForceSubtaskResultsResponse(tasks.TaskMessage):
    """
    Sent from the Concent to the Provider to communicate the final resolution
    of the forced results verdict.

    Contains one of the following:

    :param SubtaskResultsAccepted subtask_results_accepted:
    :param SubtaskResultsRejected subtask_results_rejected:
    """
    TASK_ID_PROVIDERS = ('subtask_results_accepted',
                         'subtask_results_rejected', )
    EXPECTED_OWNERS = (tasks.TaskMessage.OWNER_CHOICES.concent, )
    MSG_SLOTS = {
        'subtask_results_accepted': tasks.SubtaskResultsAccepted,
        'subtask_results_rejected': tasks.SubtaskResultsRejected,
    }

    __slots__ = [
        'subtask_results_accepted',
        'subtask_results_rejected',
    ] + base.Message.__slots__


@library.register(CONCENT_MSG_BASE + 17)
class ForceSubtaskResultsRejected(tasks.TaskMessage,
                                  base.AbstractReasonMessage):
    """
    Possible response from the Concent to the Provider to the
    `ForceSubtaskResults` request, when the request is not valid at the time
    it's made.
    """

    TASK_ID_PROVIDERS = ('force_subtask_results', )
    EXPECTED_OWNERS = (tasks.TaskMessage.OWNER_CHOICES.concent, )
    MSG_SLOTS = {
        'force_subtask_results': ForceSubtaskResults,
    }

    __slots__ = [
        'force_subtask_results'
    ] + base.AbstractReasonMessage.__slots__

    class REASON(enum.Enum):
        RequestPremature = 'premature: still within the verification timeout'
        RequestTooLate = 'too late: past the forced communication timeout'


@library.register(CONCENT_MSG_BASE + 18)
class ForcePayment(base.Message):
    """
    Sent from the Provider to the Concent to force payment for which the
    payment timeout has already passed using Requestor's deposit.

    :param list subtask_results_accepted_list: the list of
        `SubtaskResultsAccepted` messages
    """
    __slots__ = [
        'subtask_results_accepted_list'
    ] + base.Message.__slots__
    MSG_SLOTS = {
        'subtask_results_accepted_list': [tasks.SubtaskResultsAccepted]
    }


@library.register(CONCENT_MSG_BASE + 19)
class ForcePaymentCommitted(base.Message):
    """
    Sent from the Concent to the Provider to acknowledge that Provider
    has been paid from the Requestor's deposit - or - to acknowledge that
    the payment is due but the deposit is not enough to cover it.

    Message of the same content is also sent as an information to the Requestor
    whose deposit is affected by the operation.
    """
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


@library.register(CONCENT_MSG_BASE + 20)
class ForcePaymentRejected(base.AbstractReasonMessage):
    """
    Sent from the Concent to the Provider to inform them that Concent was
    unable to find the tasks that need to be paid for - because either they
    have indeed been paid for already or because they are not overdue yet.

    (the latter means that most likely, the Provider's clock is out of sync)
    """
    @enum.unique
    class REASON(enum.Enum):
        NoUnsettledTasksFound = 'no unsettled tasks found'
        TimestampError = 'timestamp error - subtasks are not overdue yet'

    __slots__ = [
        'force_payment'
    ] + base.AbstractReasonMessage.__slots__
    MSG_SLOTS = {
        'force_payment': ForcePayment,
    }


@library.register(CONCENT_MSG_BASE + 21)
class ForceReportComputedTaskResponse(tasks.TaskMessage,
                                      base.AbstractReasonMessage):
    """Sent from Concent to Provider as a response to ForceReportComputedTask.
    """
    TASK_ID_PROVIDERS = ('ack_report_computed_task',
                         'reject_report_computed_task', )
    EXPECTED_OWNERS = (tasks.TaskMessage.OWNER_CHOICES.concent, )

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
    MSG_SLOTS = {
        'ack_report_computed_task': tasks.AckReportComputedTask,
        'reject_report_computed_task': tasks.RejectReportComputedTask,
    }


@library.register(CONCENT_MSG_BASE + 22)
class ClientAuthorization(base.Message):
    """
    Message sent from a Provider or Requestor to the Concent,
    used to identify and authenticate him in communication process.

    This message must be signed with the key it contains.
    This the proof that the client indeed has the private part of that key.
    """
    __slots__ = [
        'client_public_key',
    ] + base.Message.__slots__
