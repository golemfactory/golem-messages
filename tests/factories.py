import time
import uuid
import random

import factory
import faker

from ethereum.utils import denoms

from golem_messages.message import concents
from golem_messages.message import tasks

# pylint: disable=too-few-public-methods,unnecessary-lambda


class SlotsFactory(factory.Factory):
    """
    Generic factory that produces a tuple representing the slots dictionary
    which can be fed directly to the appropriate message constructor

    The slot keys are defined through regular attributes on the specific
    factory class and thus, they can also be passed to the subfactory when the
    message factory is invoked, e.g.:

    :Example:

    SubtaskResultsVerifyFactory(slots__subtask_id='some-id')

    """

    class Meta:
        model = tuple

    @classmethod
    def _create(cls, *args, **kwargs):  # noqa pylint:disable=unused-argument
        return kwargs.items()


class TaskOwnerFactory(factory.DictFactory):
    key = factory.Faker('binary', length=64)
    node_name = factory.Faker('name')


class ComputeTaskDefFactory(factory.DictFactory):
    class Meta:
        model = tasks.ComputeTaskDef

    task_owner = factory.SubFactory(TaskOwnerFactory)
    task_id = factory.Faker('uuid4')
    subtask_id = factory.Faker('uuid4')


class TaskToComputeFactory(factory.Factory):
    class Meta:
        model = tasks.TaskToCompute

    requestor_id = factory.Sequence(lambda n: 'requestor {}'.format(n))
    requestor_public_key = factory.Sequence(
        lambda n: 'requestor pubkey {}'.format(n)
    )
    provider_id = factory.Sequence(lambda n: 'provider {}'.format(n))
    provider_public_key = factory.Sequence(
        lambda n: 'provider pubkey {}'.format(n)
    )

    compute_task_def = factory.SubFactory(ComputeTaskDefFactory)

    @classmethod
    def _create(cls, *args, **kwargs):
        # ensure the `requestor_id` is the same as `task_owner['key']`
        # unless they're explicitly set
        if 'requestor_id' in kwargs and 'compute_task_def' not in kwargs:
            kwargs['compute_task_def'] = ComputeTaskDefFactory(
                task_owner__key=kwargs['requestor_id']
            )
        else:
            task_def = kwargs.setdefault('compute_task_def',
                                         ComputeTaskDefFactory())
            kwargs['requestor_id'] = task_def.get('task_owner').get('key')

        return super()._create(*args, **kwargs)


class SubtaskResultsAcceptedFactory(factory.Factory):
    class Meta:
        model = tasks.SubtaskResultsAccepted

    task_to_compute = factory.SubFactory(
        'tests.factories.TaskToComputeFactory')


class SubtaskResultsRejectedFactory(factory.Factory):
    """
    Produces a regular `SubtaskResultsRejected` message, containing the earlier
    `ReportComputedTask` message
    """
    class Meta:
        model = tasks.SubtaskResultsRejected

    report_computed_task = factory.SubFactory(
        'tests.factories.ReportComputedTaskFactory')


class SubtaskResultsRejectedFGTRFFactory(factory.Factory):
    """
    Produces the alternate version of the `SubtaskResultsRejected` message,
    containing the `ForceGetTaskResultFailed` message - resulting from an
    earlier, failed, forced communication procedure
    """
    class Meta:
        model = tasks.SubtaskResultsRejected

    force_get_task_result_failed = factory.SubFactory(
        'tests.factories.ForceGetTaskResultFailedFactory')


class ReportComputedTaskSlotsFactory(SlotsFactory):
    class Meta:
        model = tuple

    task_to_compute = factory.SubFactory(TaskToComputeFactory)


class ReportComputedTaskFactory(factory.Factory):
    class Meta:
        model = tasks.ReportComputedTask

    slots = factory.SubFactory(ReportComputedTaskSlotsFactory)


class ForceReportComputedTaskSlotsFactory(SlotsFactory):
    class Meta:
        model = tuple

    task_to_compute = factory.SubFactory(TaskToComputeFactory)


class ForceReportComputedTaskFactory(factory.Factory):
    class Meta:
        model = concents.ForceReportComputedTask

    slots = factory.SubFactory(ForceReportComputedTaskSlotsFactory)


class SubtaskResultsVerifySlotsFactory(SlotsFactory):
    class Meta:
        model = tuple

    subtask_result_rejected = factory.SubFactory(SubtaskResultsRejectedFactory)


class SubtaskResultsVerifyFactory(factory.Factory):
    class Meta:
        model = concents.SubtaskResultsVerify

    slots = factory.SubFactory(SubtaskResultsVerifySlotsFactory)


class AckSubtaskResultsVerifySlotsFactory(SlotsFactory):
    class Meta:
        model = tuple

    subtask_result_verify = factory.SubFactory(SubtaskResultsVerifyFactory)


class AckSubtaskResultsVerifyFactory(factory.Factory):
    class Meta:
        model = concents.AckSubtaskResultsVerify

    slots = factory.SubFactory(AckSubtaskResultsVerifySlotsFactory)


class SubtaskResultsSettledFactory(factory.Factory):
    class Meta:
        model = concents.SubtaskResultsSettled

    origin = concents.SubtaskResultsSettled.Origin.ResultsAcceptedTimeout
    task_to_compute = factory.SubFactory(TaskToComputeFactory)

    @classmethod
    def origin_acceptance_timeout(cls, *args, **kwargs):
        kwargs['origin'] = \
                concents.SubtaskResultsSettled.Origin.ResultsAcceptedTimeout
        return cls(*args, **kwargs)

    @classmethod
    def origin_results_rejected(cls, *args, **kwargs):
        kwargs['origin'] = \
                concents.SubtaskResultsSettled.Origin.ResultsRejected
        return cls(*args, **kwargs)


class ForceGetTaskResultSlotsFactory(SlotsFactory):
    class Meta:
        model = tuple

    report_computed_task = factory.SubFactory(ReportComputedTaskFactory)
    force_report_computed_task = factory.SubFactory(
        ForceReportComputedTaskFactory)


class ForceGetTaskResultFactory(factory.Factory):
    class Meta:
        model = concents.ForceGetTaskResult

    slots = factory.SubFactory(ForceGetTaskResultSlotsFactory)


class ForceGetTaskResultAckSlotsFactory(SlotsFactory):
    class Meta:
        model = tuple

    force_get_task_result = factory.SubFactory(ForceGetTaskResultFactory)


class ForceGetTaskResultAckFactory(factory.Factory):
    class Meta:
        model = concents.ForceGetTaskResultAck

    slots = factory.SubFactory(ForceGetTaskResultAckSlotsFactory)


class ForceGetTaskResultFailedSlotsFactory(SlotsFactory):
    class Meta:
        model = tuple

    task_to_compute = factory.SubFactory(TaskToComputeFactory)


class ForceGetTaskResultFailedFactory(factory.Factory):
    class Meta:
        model = concents.ForceGetTaskResultFailed

    slots = factory.SubFactory(ForceGetTaskResultFailedSlotsFactory)


class ForceGetTaskResultRejectedSlotsFactory(SlotsFactory):
    class Meta:
        model = tuple

    force_get_task_result = factory.SubFactory(ForceGetTaskResultFactory)


class ForceGetTaskResultRejectedFactory(factory.Factory):
    class Meta:
        model = concents.ForceGetTaskResultRejected

    slots = factory.SubFactory(ForceGetTaskResultRejectedSlotsFactory)


class FileTransferTokenFactory(factory.Factory):
    class Meta:
        model = concents.FileTransferToken

    slots = factory.SubFactory(SlotsFactory,
                               subtask_id='test-si-{}'.format(uuid.uuid4()))


class ForceGetTaskResultUploadSlotsFactory(SlotsFactory):
    class Meta:
        model = tuple

    force_get_task_result = factory.SubFactory(ForceGetTaskResultFactory)
    file_transfer_token = factory.SubFactory(FileTransferTokenFactory)


class ForceGetTaskResultUploadFactory(factory.Factory):
    class Meta:
        model = concents.ForceGetTaskResultUpload

    slots = factory.SubFactory(ForceGetTaskResultUploadSlotsFactory)


class ForceGetTaskResultDownloadFactory(ForceGetTaskResultUploadFactory):
    pass


class ForceSubtaskResultsResponseFactory(factory.Factory):
    class Meta:
        model = concents.ForceSubtaskResultsResponse

    @classmethod
    def with_accepted(cls, *args, **kwargs):
        if 'subtask_results_accepted' not in kwargs:
            kwargs['subtask_results_accepted__generate'] = True
        return cls(*args, **kwargs)

    @classmethod
    def with_rejected(cls, *args, **kwargs):
        if 'subtask_results_rejected' not in kwargs:
            kwargs['subtask_results_rejected__generate'] = True
        return cls(*args, **kwargs)

    # pylint: disable=no-self-argument
    # the first argument of a `post_generation` hook _doesn't_
    # reference the factory class but rather the generated model object

    @factory.post_generation
    def subtask_results_accepted(obj, create, extracted, **kwargs):
        if not create:
            return

        msg = extracted
        if not msg and kwargs and kwargs.pop('generate'):
            msg = SubtaskResultsAcceptedFactory(**kwargs)

        if msg:
            setattr(obj, 'subtask_results_accepted', msg)

    @factory.post_generation
    def subtask_results_rejected(obj, create, extracted, **kwargs):
        if not create:
            return

        msg = extracted
        if not msg and kwargs and kwargs.pop('generate'):
            msg = SubtaskResultsRejectedFactory(**kwargs)

        if msg:
            setattr(obj, 'subtask_results_rejected', msg)

    # pylint: enable=no-self-argument


class AckReportComputedTaskFactory(factory.Factory):
    class Meta:
        model = concents.AckReportComputedTask

    task_to_compute = factory.SubFactory(TaskToComputeFactory)


class ForceSubtaskResultsFactory(factory.Factory):
    class Meta:
        model = concents.ForceSubtaskResults

    ack_report_computed_task = factory.SubFactory(AckReportComputedTaskFactory)


class ForceSubtaskResultsRejectedFactory(factory.Factory):
    class Meta:
        model = concents.ForceSubtaskResultsRejected

    reason = concents.ForceSubtaskResultsRejected.REASON.RequestPremature

    @classmethod
    def premature(cls, *args, **kwargs):
        kwargs['reason'] = \
            concents.ForceSubtaskResultsRejected.REASON.RequestPremature
        return cls(*args, **kwargs)

    @classmethod
    def too_late(cls, *args, **kwargs):
        kwargs['reason'] = \
            concents.ForceSubtaskResultsRejected.REASON.RequestTooLate
        return cls(*args, **kwargs)


class ForcePaymentFactory(factory.Factory):
    class Meta:
        model = concents.ForcePayment

    @classmethod
    def with_accepted_tasks(cls, *args, **kwargs):
        kwargs['subtask_results_accepted_list__generate'] = 1
        return cls(*args, **kwargs)

    # pylint: disable=no-self-argument

    @factory.post_generation
    def subtask_results_accepted_list(obj, create, extracted, **kwargs):
        if not create:
            return

        msgs = extracted
        if not msgs and kwargs and kwargs.get('generate'):
            msgs = []
            num_msgs = kwargs.pop('generate')
            for _ in range(num_msgs):
                msgs.append(SubtaskResultsAcceptedFactory(**kwargs))

        if msgs:
            setattr(obj, 'subtask_results_accepted_list', msgs)

    # pylint: enable=no-self-argument


class ForcePaymentCommittedFactory(factory.Factory):
    class Meta:
        model = concents.ForcePaymentCommitted

    payment_ts = factory.LazyFunction(lambda: int(time.time()))
    task_owner_key = factory.Faker('binary', length=64)
    provider_eth_account = factory.LazyFunction(
        lambda: '0x' + faker.Faker().sha1())
    amount_paid = factory.LazyFunction(
        lambda: random.randint(0, denoms.ether)
    )
    recipient_type = concents.ForcePaymentCommitted.Actor.Provider

    @classmethod
    def to_provider(cls, *args, **kwargs):
        kwargs['recipient_type'] = \
            concents.ForcePaymentCommitted.Actor.Provider
        return cls(*args, **kwargs)

    @classmethod
    def to_requestor(cls, *args, **kwargs):
        kwargs['recipient_type'] = \
            concents.ForcePaymentCommitted.Actor.Requestor
        return cls(*args, **kwargs)


class ForcePaymentRejectedFactory(factory.Factory):
    class Meta:
        model = concents.ForcePaymentRejected

    reason = concents.ForcePaymentRejected.REASON.NoUnsettledTasksFound
