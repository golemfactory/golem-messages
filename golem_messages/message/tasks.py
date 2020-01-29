import enum
import functools
import typing

from golem_messages import datastructures
from golem_messages import exceptions
from golem_messages import idgenerator
from golem_messages import settings
from golem_messages import validators
from golem_messages.datastructures import promissory
from golem_messages.datastructures.promissory import PromissoryNote
from golem_messages.datastructures.stats import ProviderStats
from golem_messages.datastructures.tasks import TaskHeader
from golem_messages.register import library
from golem_messages.utils import decode_hex, pubkey_to_address

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
        'extra_data': {},  # safe because of copy in parent.__missing__()
        'performance': 0,
        'docker_images': None,
        'resources': [],
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

    @classmethod
    def deserialize_with_header(cls, header, data, *args, **kwargs):  # noqa pylint: disable=arguments-differ
        instance: TaskMessage = super().deserialize_with_header(
            header, data, *args, **kwargs
        )
        instance.is_valid()
        return instance

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
    """
    A computation Offer.

    A Provider sends it directly to a Requestor as a response to the Requestor's
    Demand (Task) in order to get work (SubTask ie. TaskToCompute) to do.

    """
    __slots__ = [
        'perf_index',         # Provider's performance; a benchmark result
        'cpu_usage',          # Provider's cpu usage; a benchmark result
        'max_resource_size',  # P's storage size available for computation
        'max_memory_size',    # P's RAM
        'price',              # Offered price per hour in GNT WEI (10e-18)
        'num_subtasks',       # How many subtasks Provider wants to work on
                              # (simultaneously); 1 by default
        'concent_enabled',    # Provider's Concent status
        'extra_data',         # additional required information about the
                              # Provider's environment. `golem-messages` should
                              # be intentionally agnostic with regards to the
                              # contents of this field.

        'provider_public_key',  # for signing and encryption
        'provider_ethereum_address',  # for transactions on ETH blockchain
        'task_header',        # Demand; signed by a Requestor
    ] + base.Message.__slots__

    DEFAULT_NUM_SUBTASKS = 1

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.num_subtasks is None:
            self.num_subtasks = self.DEFAULT_NUM_SUBTASKS

    @property
    def task_id(self):
        return self.task_header.task_id

    def serialize_slot(self, key, value):
        if key == 'task_header' and isinstance(value, TaskHeader):
            return value.to_dict()

        return super().serialize_slot(key, value)

    def deserialize_slot(self, key, value):
        if key == 'task_header' and value is not None:
            return TaskHeader(**value)

        if key == 'cpu_usage' and value is not None:
            validators.validate_integer(key, value)
            if value < 0:
                raise exceptions.FieldError(
                    "Should be equal or greater than zero",
                    field=key,
                    value=value,
                )

        value = super().deserialize_slot(key, value)

        if key == 'num_subtasks':
            validators.validate_positive_integer(key, value)

        return value


@library.register(TASK_MSG_BASE + 2)
class TaskToCompute(
        ConcentEnabled,
        TaskMessage,
        promissory.PromissorySlotMixin,
):
    EXPECTED_OWNERS = (TaskMessage.OWNER_CHOICES.requestor, )

    MSG_SLOTS = {
        'want_to_compute_task': base.MessageSlotDefinition(WantToComputeTask),
    }

    __slots__ = [
        'requestor_id',  # a.k.a. node id
        'requestor_public_key',  # key used for msg signing and encryption
        'requestor_ethereum_public_key',  # used for transactions on blockchain
        'provider_id',  # a.k.a. node id
        'compute_task_def',
        'want_to_compute_task',
        'package_hash',  # the hash of the package (resources) zip file
        'size',  # the size of the resources zip file
        'concent_enabled',
        'price',  # total subtask price in GNT WEI (10e-18)
        'resources_options',
        'ethsig',
        'promissory_note_sig',  # the signature of the PromissoryNote
                                # for the provider, signed by the requestor
        'concent_promissory_note_sig',  # the signature of the PromissoryNote
                                        # for the Concent Service,
                                        # signed by the requestor
    ] + base.Message.__slots__

    @property
    def requestor_ethereum_address(self):
        return pubkey_to_address(self.requestor_ethereum_public_key)

    @property
    def provider_public_key(self):
        return self.want_to_compute_task.provider_public_key

    @property
    def provider_ethereum_address(self):
        return self.want_to_compute_task.provider_ethereum_address

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

    @classmethod
    def deserialize_with_header(cls, header, data, *args, **kwargs):  # noqa pylint: disable=arguments-differ
        instance: TaskToCompute = super().deserialize_with_header(
            header, data, *args, **kwargs
        )
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
        using the provided ethereum private key by signing nested
        WantToComputeTask message.

        :param private_key: ethereum private key
        :param msg_hash: may be optionally provided to skip generation
                         of the message hash while signing. If not provided,
                         the hash is generated from nested WantToComputeTask.
        """

        if not self.requestor_ethereum_public_key:
            raise exceptions.FieldError(
                "It doesn't really make sense to"
                " generate the ethereum signature"
                " with no `requestor_ethereum_public_key` in place...",
                field='requestor_ethereum_public_key',
                value=self.requestor_ethereum_public_key,
            )

        self.ethsig = self.want_to_compute_task._get_signature(private_key, msg_hash)  # noqa pylint: disable=attribute-defined-outside-init,protected-access

    def verify_ethsig(
            self, msg_hash: typing.Optional[bytes] = None
    ) -> bool:
        """
        Verify the message's ethereum signature using the provided public key.
        Ensures that the requestor has control over the ethereum address
        associated with `requestor_ethereum_public_key`

        :param msg_hash: maybe optionally provided to skip generation
                         of the message hash during the verification.
        :return: `True` if the signature is correct.
        :raises: `exceptions.InvalidSignature` if the signature is corrupted
        """
        return self.want_to_compute_task._verify_signature(  # noqa pylint: disable=protected-access
            self.ethsig,
            decode_hex(self.requestor_ethereum_public_key),
            msg_hash
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

    def validate_ownership(self, concent_public_key=None):
        self.want_to_compute_task.task_header.verify(
            decode_hex(self.requestor_public_key)
        )
        return super().validate_ownership(concent_public_key)

    def _get_promissory_note(
            self, deposit_contract_address: str) -> PromissoryNote:
        return promissory.PromissoryNote(
            address_from=self.requestor_ethereum_address,
            address_to=self.provider_ethereum_address,
            amount=self.price,
            subtask_id=self.subtask_id,
            contract_address=deposit_contract_address,
        )

    def _get_concent_promissory_note(
            self, deposit_contract_address: str) -> PromissoryNote:
        return promissory.PromissoryNote(
            address_from=self.requestor_ethereum_address,
            address_to=deposit_contract_address,
            amount=self.price,
            subtask_id=self.subtask_id,
            contract_address=deposit_contract_address,
        )

    def sign_promissory_note(
            self,
            deposit_contract_address: str,
            private_key: bytes
    ) -> None:
        self.promissory_note_sig = self._get_promissory_note(  # noqa pylint: disable=attribute-defined-outside-init
            deposit_contract_address=deposit_contract_address
        ).sign(
            privkey=private_key
        )

    def verify_promissory_note(self, deposit_contract_address: str) -> bool:
        return self._get_promissory_note(
            deposit_contract_address=deposit_contract_address
        ).sig_valid(self.promissory_note_sig)

    def sign_all_promissory_notes(
            self,
            deposit_contract_address: str,
            private_key: bytes
    ) -> None:
        self.sign_concent_promissory_note(
            deposit_contract_address=deposit_contract_address,
            private_key=private_key,
        )
        self.sign_promissory_note(
            deposit_contract_address=deposit_contract_address,
            private_key=private_key,
        )

    def verify_all_promissory_notes(
            self, deposit_contract_address: str) -> bool:
        return self.verify_concent_promissory_note(
            deposit_contract_address=deposit_contract_address,
        ) and self.verify_promissory_note(
            deposit_contract_address=deposit_contract_address
        )


@library.register(TASK_MSG_BASE + 3)
class CannotAssignTask(base.AbstractReasonMessage):
    __slots__ = [
        'task_id'
    ] + base.AbstractReasonMessage.__slots__

    class REASON(datastructures.StringEnum):
        NotMyTask = enum.auto()
        NoMoreSubtasks = enum.auto()  # No more subtasks but you can ask later
        # All subtasks are computed and verified. Task finished.
        TaskFinished = enum.auto()
        ConcentDisabled = enum.auto()


@library.register(TASK_MSG_BASE + 4)
class ReportComputedTask(TaskMessage):
    """
    Message sent from a Provider to a Requestor, announcing completion
    of the assigned subtask (attached as `task_to_compute`)
    """
    # FIXME this message should be simpler

    TASK_ID_PROVIDERS = ('task_to_compute', )
    EXPECTED_OWNERS = (TaskMessage.OWNER_CHOICES.provider, )
    MSG_SLOTS = {
        'task_to_compute': base.MessageSlotDefinition(TaskToCompute),
    }

    __slots__ = [
        'address',
        'node_info',
        'port',
        'key_id',
        'extra_data',
        'task_to_compute',
        'size',
        'package_hash',  # sha1 hash of the package file (the zip file)
        'multihash',     # hyperg record used when transferring
                         # the result directly between the nodes
        'secret',
        'options',
        'stats',
    ] + base.Message.__slots__

    def serialize_slot(self, key, value):
        if key == 'stats' and isinstance(value, ProviderStats):
            return value.to_dict()

        return super().serialize_slot(key, value)

    def deserialize_slot(self, key, value):
        if key == 'stats' and value is not None:
            return ProviderStats(**value)

        return super().deserialize_slot(key, value)


@library.register(TASK_MSG_BASE + 10)
class SubtaskResultsAccepted(TaskMessage):
    """
    Sent from the Requestor to the Provider, accepting the provider's
    completed task results.

    Having received this message, the Provider expects payment to follow.
    """
    TASK_ID_PROVIDERS = ('report_computed_task', )
    EXPECTED_OWNERS = (TaskMessage.OWNER_CHOICES.requestor, )

    __slots__ = [
        'payment_ts',
        'report_computed_task',
    ] + base.Message.__slots__
    MSG_SLOTS = {
        'report_computed_task': base.MessageSlotDefinition(ReportComputedTask),
    }

    def is_valid(self) -> bool:
        if self.payment_ts > self.header.timestamp:
            raise exceptions.ValidationError(
                "Payment timestamp cannot be from the future!"
            )
        if self.payment_ts + \
                settings.PAYMENT_TIMESTAMP_TOLERANCE.total_seconds() < \
                self.header.timestamp:
            raise exceptions.ValidationError(
                "Payment timestamp is too far in the past."
            )
        return True


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
        'force_get_task_result_failed',
    ] + base.AbstractReasonMessage.__slots__
    MSG_SLOTS = {
        'report_computed_task': base.MessageSlotDefinition(ReportComputedTask),
        'force_get_task_result_failed': base.MessageSlotDefinition(
            'golem_messages.message.concents.ForceGetTaskResultFailed',
            allow_none=True,
        )
    }

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

    REQUESTOR_REASONS_ALLOWED = {
        'concent': (
            REASON.VerificationNegative,
            REASON.ForcedResourcesFailure,
        ),
        'no_concent': (
            REASON.VerificationNegative,
            REASON.ResourcesFailure,
        )
    }

    def is_valid(self):
        if not self.reason:
            raise exceptions.ValidationError("Undefined reason.")

        fgtrf = self.force_get_task_result_failed
        if fgtrf:
            if (
                    self.task_id != fgtrf.task_id or
                    self.subtask_id != fgtrf.subtask_id
            ):
                raise exceptions.ValidationError(
                    "The ForceGetTaskResultFailed message must pertain to the "
                    "same task/subtask."
                )
        if self.reason == self.REASON.ForcedResourcesFailure and not fgtrf:
            raise exceptions.ValidationError(
                "ForcedResourcesFailure requires providing a "
                "Concent-signed ForceGetTaskResultFailed"
            )

        return True

    def is_valid_for_requestor(self):
        """
        validates if the message is correct if coming from a requestor

        :raises: `exceptions.ValidationError`
        :return: bool
        """
        concent = self.report_computed_task.task_to_compute.concent_enabled
        allowed_reasons = self.REQUESTOR_REASONS_ALLOWED[
            'concent' if concent else 'no_concent'
        ]

        if self.reason not in allowed_reasons:
            raise exceptions.ValidationError(
                f"{self.reason.value} is not allowed for a Requestor "
                f"when concent_enabled={concent}."
            )

        return self.is_valid()


@library.register(TASK_MSG_BASE + 15)
class TaskFailure(TaskMessage, base.AbstractReasonMessage):
    TASK_ID_PROVIDERS = ('task_to_compute', )
    EXPECTED_OWNERS = (TaskMessage.OWNER_CHOICES.provider, )
    MSG_SLOTS = {
        'task_to_compute': base.MessageSlotDefinition(TaskToCompute),
    }

    __slots__ = [
        'task_to_compute',
        'err',
    ] + base.AbstractReasonMessage.__slots__

    class REASON(datastructures.StringEnum):
        ComputationError = enum.auto()
        BudgetExceeded = enum.auto()
        TimeExceeded = enum.auto()

    DEFAULT_REASON = REASON.ComputationError

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.reason is None:
            self.reason = self.DEFAULT_REASON


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


@library.register(TASK_MSG_BASE + 26)
class CannotComputeTask(TaskMessage, base.AbstractReasonMessage):
    TASK_ID_PROVIDERS = ('task_to_compute', )
    EXPECTED_OWNERS = (TaskMessage.OWNER_CHOICES.provider, )
    MSG_SLOTS = {
        'task_to_compute': base.MessageSlotDefinition(TaskToCompute),
    }

    __slots__ = [
        'task_to_compute',
    ] + base.AbstractReasonMessage.__slots__

    class REASON(datastructures.StringEnum):
        CannotTakeWork = enum.auto()
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
        PromissoryNoteMissing = enum.auto()  # deposit unusable
        OfferCancelled = enum.auto()
        ResourcesTooBig = enum.auto()


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
    MSG_SLOTS = {
        'report_computed_task': base.MessageSlotDefinition(ReportComputedTask),
    }


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
    MSG_SLOTS = {
        'attached_task_to_compute': base.MessageSlotDefinition(
            TaskToCompute,
            allow_none=True,
        ),
        'task_failure': base.MessageSlotDefinition(
            TaskFailure,
            allow_none=True,
        ),
        'cannot_compute_task':
            base.MessageSlotDefinition(CannotComputeTask, allow_none=True),
    }

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
