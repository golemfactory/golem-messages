import enum

from golem_messages import datastructures
from golem_messages import exceptions
from golem_messages import validators

from . import base
from . import tasks


CONCENT_MSG_BASE = 4000


class ServiceRefused(tasks.TaskMessage, base.AbstractReasonMessage):
    """
    Sent (synchronously) as a response from the Concent to the calling party
    (either a Provider or a Requestor), informing them that the Concent refuses
    to execute the requested action because either the message (request) itself
    is corrupted or some of the prerequisites (like e.g. the deposit) are not
    satisfied.

    :param REASON reason: the reason for the refusal
    """
    TYPE = CONCENT_MSG_BASE
    TASK_ID_PROVIDERS = ('task_to_compute', )
    EXPECTED_OWNERS = (tasks.TaskMessage.OWNER_CHOICES.concent, )

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
        'task_to_compute',
    ] + base.AbstractReasonMessage.__slots__

    @base.verify_slot('task_to_compute', tasks.TaskToCompute)
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)


class ForceReportComputedTask(tasks.TaskMessage):
    """
    Message sent from a Provider to the Concent, requesting an forced
    acknowledgment of the reception of the `ReportComputedTask` message
    from the Requestor.

    The same, rewritten message is then sent from the Concent to the Requestor.
    """
    TYPE = CONCENT_MSG_BASE + 1
    TASK_ID_PROVIDERS = ('report_computed_task', )
    EXPECTED_OWNERS = (tasks.TaskMessage.OWNER_CHOICES.provider,
                       tasks.TaskMessage.OWNER_CHOICES.concent)

    __slots__ = [
        'report_computed_task',
        'result_hash',
    ] + base.Message.__slots__

    @base.verify_slot('report_computed_task', tasks.ReportComputedTask)
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)


class VerdictReportComputedTask(tasks.TaskMessage):
    """
    Informational message sent from from the Concent to the affected
    Requestor, informing them that the `ReportComputedTask` has been implicitly
    acknowledged by the Concent on behalf of the Requestor.
    (Provider has received the `AckReportComputedTask` from the Concent)

    The state of the Provider/Requestor interaction is assumed to be the same
    as if the Requestor sent the `AckReportComputedTask` on their own.
    """
    TYPE = CONCENT_MSG_BASE + 4
    TASK_ID_PROVIDERS = ('force_report_computed_task',
                         'ack_report_computed_task', )
    EXPECTED_OWNERS = (tasks.TaskMessage.OWNER_CHOICES.concent, )

    __slots__ = [
        'force_report_computed_task',
        'ack_report_computed_task',
    ] + base.Message.__slots__

    @base.verify_slot('force_report_computed_task', ForceReportComputedTask)
    @base.verify_slot('ack_report_computed_task', tasks.AckReportComputedTask)
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)

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


class FileTransferToken(base.Message):
    """
    Sent from the Concent (usually, as an attachment in another message) to
    enable upload/download of files pertaining to the subtask at hand.
    """
    TYPE = CONCENT_MSG_BASE + 5

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


class SubtaskResultsVerify(tasks.TaskMessage):
    """
    Message sent from a Provider to the Concent, requesting additional
    verification in case the result had been rejected by the Requestor

    :param SubtaskResultsRejected subtask_results_rejected:
           the original reject message

    """
    TYPE = CONCENT_MSG_BASE + 6
    TASK_ID_PROVIDERS = ('subtask_results_rejected', )
    EXPECTED_OWNERS = (tasks.TaskMessage.OWNER_CHOICES.provider, )

    __slots__ = [
        'subtask_results_rejected',
    ] + base.Message.__slots__

    @base.verify_slot('subtask_results_rejected', tasks.SubtaskResultsRejected)
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)


class AckSubtaskResultsVerify(tasks.TaskMessage):
    """
    Message sent from the Concent to the Provider to acknowledge reception
    of the `SubtaskResultsVerify` message and more importantly, to pass the
    required `FileTransferToken` message to the Provider which must use it
    to upload files to the Concent service.
    """
    TYPE = CONCENT_MSG_BASE + 7
    TASK_ID_PROVIDERS = ('subtask_results_verify', )
    EXPECTED_OWNERS = (tasks.TaskMessage.OWNER_CHOICES.concent, )

    __slots__ = [
        'subtask_results_verify',
        'file_transfer_token',
    ] + base.Message.__slots__

    @base.verify_slot('subtask_results_verify', SubtaskResultsVerify)
    @base.verify_slot('file_transfer_token', FileTransferToken)
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)


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

    TYPE = CONCENT_MSG_BASE + 8
    TASK_ID_PROVIDERS = ('task_to_compute', )
    EXPECTED_OWNERS = (tasks.TaskMessage.OWNER_CHOICES.concent, )

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

    @base.verify_slot('task_to_compute', tasks.TaskToCompute)
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)


class ForceGetTaskResult(tasks.TaskMessage):
    """
    Sent from the Requestor to the Concent, requesting assistance in
    downloading the results from the Provider.
    """
    TYPE = CONCENT_MSG_BASE + 9
    TASK_ID_PROVIDERS = ('report_computed_task', )
    EXPECTED_OWNERS = (tasks.TaskMessage.OWNER_CHOICES.requestor, )

    __slots__ = [
        'report_computed_task',
    ] + base.Message.__slots__

    @base.verify_slot('report_computed_task', tasks.ReportComputedTask)
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)


class AckForceGetTaskResult(tasks.TaskMessage):
    """
    Sent from the Concent to the Requestor to acknowledge reception of the
    `ForceGetTaskResult` message
    """
    TYPE = CONCENT_MSG_BASE + 10
    TASK_ID_PROVIDERS = ('force_get_task_result', )
    EXPECTED_OWNERS = (tasks.TaskMessage.OWNER_CHOICES.concent, )

    __slots__ = [
        'force_get_task_result',
    ] + base.Message.__slots__

    @base.verify_slot('force_get_task_result', ForceGetTaskResult)
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)


class ForceGetTaskResultFailed(tasks.TaskMessage):
    """
    Sent from the Concent to the Requestor to announce a failure to retrieve
    the results from the Provider.

    Having received this message, the Requestor can use it later on
    to reject any attempt at forced acceptance by proving the result
    could not have been downloaded in the first place.
    """
    TYPE = CONCENT_MSG_BASE + 11
    TASK_ID_PROVIDERS = ('task_to_compute', )
    EXPECTED_OWNERS = (tasks.TaskMessage.OWNER_CHOICES.concent, )

    __slots__ = [
        'task_to_compute',
    ] + base.Message.__slots__

    @base.verify_slot('task_to_compute', tasks.TaskToCompute)
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)


class ForceGetTaskResultRejected(tasks.TaskMessage,
                                 base.AbstractReasonMessage):
    """
    Sent from the Concent to the Requestor to notify them that the
    `ForceGetTaskResult` message was not allowed at this time
    """
    TYPE = CONCENT_MSG_BASE + 12
    TASK_ID_PROVIDERS = ('force_get_task_result', )
    EXPECTED_OWNERS = (tasks.TaskMessage.OWNER_CHOICES.concent, )

    __slots__ = [
        'force_get_task_result',
    ] + base.AbstractReasonMessage.__slots__

    class REASON(enum.Enum):
        AcceptanceTimeLimitExceeded = 'acceptance_time_limit_exceeded'

    @base.verify_slot('force_get_task_result', ForceGetTaskResult)
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)


class ForceGetTaskResultUpload(tasks.TaskMessage):
    """
    Sent from the Concent to the Provider to notify them they can (and need to)
    upload the results to them
    """
    TYPE = CONCENT_MSG_BASE + 13
    TASK_ID_PROVIDERS = ('force_get_task_result', )
    EXPECTED_OWNERS = (tasks.TaskMessage.OWNER_CHOICES.concent, )

    __slots__ = [
        'force_get_task_result',
        'file_transfer_token',
    ] + base.Message.__slots__

    @base.verify_slot('force_get_task_result', ForceGetTaskResult)
    @base.verify_slot('file_transfer_token', FileTransferToken)
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)


class ForceGetTaskResultDownload(tasks.TaskMessage):
    """
    Sent from the Concent to the Requestor to notify them that the results
    are available for download.
    """
    TYPE = CONCENT_MSG_BASE + 14
    TASK_ID_PROVIDERS = ('force_get_task_result', )
    EXPECTED_OWNERS = (tasks.TaskMessage.OWNER_CHOICES.concent, )

    __slots__ = [
        'force_get_task_result',
        'file_transfer_token',
    ] + base.Message.__slots__

    @base.verify_slot('force_get_task_result', ForceGetTaskResult)
    @base.verify_slot('file_transfer_token', FileTransferToken)
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)


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
    TYPE = CONCENT_MSG_BASE + 15
    TASK_ID_PROVIDERS = ('ack_report_computed_task', )
    EXPECTED_OWNERS = (
        tasks.TaskMessage.OWNER_CHOICES.provider,
        tasks.TaskMessage.OWNER_CHOICES.concent,
    )

    __slots__ = [
        'ack_report_computed_task',
    ] + base.Message.__slots__

    @base.verify_slot('ack_report_computed_task', tasks.AckReportComputedTask)
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)


class ForceSubtaskResultsResponse(tasks.TaskMessage):
    """
    Sent from the Concent to the Provider to communicate the final resolution
    of the forced results verdict.

    Contains one of the following:

    :param SubtaskResultsAccepted subtask_results_accepted:
    :param SubtaskResultsRejected subtask_results_rejected:
    """
    TYPE = CONCENT_MSG_BASE + 16
    TASK_ID_PROVIDERS = ('subtask_results_accepted',
                         'subtask_results_rejected', )
    EXPECTED_OWNERS = (tasks.TaskMessage.OWNER_CHOICES.concent, )

    __slots__ = [
        'subtask_results_accepted',
        'subtask_results_rejected',
    ] + base.Message.__slots__

    @base.verify_slot('subtask_results_accepted', tasks.SubtaskResultsAccepted)
    @base.verify_slot('subtask_results_rejected', tasks.SubtaskResultsRejected)
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)


class ForceSubtaskResultsRejected(tasks.TaskMessage,
                                  base.AbstractReasonMessage):
    """
    Possible response from the Concent to the Provider to the
    `ForceSubtaskResults` request, when the request is not valid at the time
    it's made.
    """

    TYPE = CONCENT_MSG_BASE + 17
    TASK_ID_PROVIDERS = ('force_subtask_results', )
    EXPECTED_OWNERS = (tasks.TaskMessage.OWNER_CHOICES.concent, )

    __slots__ = [
        'force_subtask_results'
    ] + base.AbstractReasonMessage.__slots__

    class REASON(enum.Enum):
        RequestPremature = 'premature: still within the verification timeout'
        RequestTooLate = 'too late: past the forced communication timeout'

    @base.verify_slot('force_subtask_results', ForceSubtaskResults)
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)


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


class ForceReportComputedTaskResponse(tasks.TaskMessage,
                                      base.AbstractReasonMessage):
    """Sent from Concent to Provider as a response to ForceReportComputedTask.
    """
    TYPE = CONCENT_MSG_BASE + 21
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

    @base.verify_slot(
        'ack_report_computed_task',
        tasks.AckReportComputedTask,
    )
    @base.verify_slot(
        'reject_report_computed_task',
        tasks.RejectReportComputedTask,
    )
    def deserialize_slot(self, key, value):
        return super().deserialize_slot(key, value)


class ClientAuthorization(base.Message):
    """
    Message sent from a Provider or Requestor to the Concent,
    used to identify and authenticate him in communication process.

    This message must be signed with the key it contains.
    This the proof that the client indeed has the private part of that key.
    """
    TYPE = CONCENT_MSG_BASE + 22

    __slots__ = [
        'client_public_key',
    ] + base.Message.__slots__


class NonceAbstractMessage(base.Message):
    """
    Abstract message containing `nonce` field and its validation.
    """

    __slots__ = [
        'nonce',
    ] + base.Message.__slots__

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        if key == 'nonce':
            validators.validate_integer(field_name=key, value=value)
        return value


class TransactionAbstractMessage(NonceAbstractMessage):
    """
    Abstract message containing transaction data and its validation.
    """
    __slots__ = [
        'gasprice',
        'startgas',
        'to',
        'value',
        'data',
    ] + NonceAbstractMessage.__slots__

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        if key == 'to':
            validators.validate_varchar(
                field_name=key,
                value=value,
                max_length=20,
            )
        if key == 'data':
            validators.validate_bytes(
                field_name=key,
                value=value,
            )
        if key in ('gasprice', 'startgas', 'value'):
            validators.validate_integer(field_name=key, value=value)
        return value


class TransactionSigningRequest(TransactionAbstractMessage):
    """
    Message sent from SCI transaction signing callback to a Concent,
    containing data about transaction which client wants to sign using SigningService.
    """

    TYPE = CONCENT_MSG_BASE + 23

    __slots__ = [
        'from',
    ] + TransactionAbstractMessage.__slots__

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        if key == 'from':
            validators.validate_varchar(
                field_name=key,
                value=value,
                max_length=20,
            )
        return value


class SignedTransaction(TransactionAbstractMessage):
    """
    Message sent from SigningService to the Concent,
    if transaction was successfully signed,
    containing data about transaction and its signature.

    Concent should copy the signature data to the transaction object passed
    to the callback by SCI.
    """

    TYPE = CONCENT_MSG_BASE + 24

    __slots__ = [
        'v',
        'r',
        's',
    ] + TransactionAbstractMessage.__slots__

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key, value)
        if key in ('v', 'r', 's'):
            validators.validate_integer(field_name=key, value=value)
        return value


class TransactionRejected(NonceAbstractMessage):
    """
    Message sent from SigningService to the Concent,
    if transaction cannot be signed from any of various reasons.
    """

    TYPE = CONCENT_MSG_BASE + 25

    @enum.unique
    class REASON(enum.Enum):
        # The message itself is valid but does not describe a valid Ethereum
        # transaction. Use this if it passes our validations but the Ethereum
        # library still rejects it for any reason.
        InvalidTransaction = 'invalid_transaction'
        # The service is not authorized to transfer funds from the account
        # specified in the transaction.
        UnauthorizedAccount = 'unauthorized_account'

    ENUM_SLOTS = {
        'reason': REASON,
    }

    __slots__ = [
        'reason',
    ] + NonceAbstractMessage.__slots__
