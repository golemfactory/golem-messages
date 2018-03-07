import time
import uuid
import random

from ethereum.utils import denoms
import factory
import faker

from golem_messages.message import concents
from golem_messages.message import tasks

# pylint: disable=too-few-public-methods,unnecessary-lambda


class TaskOwnerFactory(factory.DictFactory):
    key = factory.Faker('binary', length=64)
    node_name = factory.Faker('name')


class ComputeTaskDefFactory(factory.DictFactory):
    class Meta:
        model = tasks.ComputeTaskDef

    task_id = factory.Faker('uuid4')
    subtask_id = factory.Faker('uuid4')


class TaskToComputeFactory(factory.Factory):
    class Meta:
        model = tasks.TaskToCompute

    requestor_id = factory.Sequence(lambda n: 'requestor {}'.format(n))
    requestor_public_key = factory.Sequence(
        lambda n: 'requestor pubkey {}'.format(n)
    )
    requestor_ethereum_public_key = factory.Faker('binary', length=64)
    provider_id = factory.Sequence(lambda n: 'provider {}'.format(n))
    provider_public_key = factory.Sequence(
        lambda n: 'provider pubkey {}'.format(n)
    )
    provider_ethereum_public_key = factory.Faker('binary', length=64)

    compute_task_def = factory.SubFactory(ComputeTaskDefFactory)


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


class ReportComputedTaskFactory(factory.Factory):
    class Meta:
        model = tasks.ReportComputedTask

    task_to_compute = factory.SubFactory(TaskToComputeFactory)


class ForceReportComputedTaskFactory(factory.Factory):
    class Meta:
        model = concents.ForceReportComputedTask

    report_computed_task = factory.SubFactory(ReportComputedTaskFactory)


class SubtaskResultsVerifyFactory(factory.Factory):
    class Meta:
        model = concents.SubtaskResultsVerify

    subtask_results_rejected = factory.SubFactory(SubtaskResultsRejectedFactory)


class AckSubtaskResultsVerifyFactory(factory.Factory):
    class Meta:
        model = concents.AckSubtaskResultsVerify

    subtask_results_verify = factory.SubFactory(SubtaskResultsVerifyFactory)


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


class ForceGetTaskResultFactory(factory.Factory):
    class Meta:
        model = concents.ForceGetTaskResult

    report_computed_task = factory.SubFactory(ReportComputedTaskFactory)


class AckForceGetTaskResultFactory(factory.Factory):
    class Meta:
        model = concents.AckForceGetTaskResult

    force_get_task_result = factory.SubFactory(ForceGetTaskResultFactory)


class ForceGetTaskResultFailedFactory(factory.Factory):
    class Meta:
        model = concents.ForceGetTaskResultFailed

    task_to_compute = factory.SubFactory(TaskToComputeFactory)


class ForceGetTaskResultRejectedFactory(factory.Factory):
    class Meta:
        model = concents.ForceGetTaskResultRejected

    force_get_task_result = factory.SubFactory(ForceGetTaskResultFactory)


class FileTransferTokenFactory(factory.Factory):
    class Meta:
        model = concents.FileTransferToken

    subtask_id = factory.LazyFunction(
        lambda: 'test-si-{}'.format(uuid.uuid4()))


class ForceGetTaskResultUploadFactory(factory.Factory):
    class Meta:
        model = concents.ForceGetTaskResultUpload

    force_get_task_result = factory.SubFactory(ForceGetTaskResultFactory)
    file_transfer_token = factory.SubFactory(FileTransferTokenFactory)


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


class RejectReportComputedTaskFactory(factory.Factory):
    class Meta:
        model = concents.RejectReportComputedTask

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

    force_payment = factory.SubFactory(ForcePaymentFactory)
    reason = concents.ForcePaymentRejected.REASON.NoUnsettledTasksFound


class ForceReportComputedTaskResponseFactory(factory.Factory):
    class Meta:
        model = concents.ForceReportComputedTaskResponse

    ack_report_computed_task = factory.SubFactory(AckReportComputedTaskFactory)
    reject_report_computed_task = factory.SubFactory(
        RejectReportComputedTaskFactory
    )


class ClientAuthorizationFactory(factory.Factory):
    class Meta:
        model = concents.ClientAuthorization

    client_public_key = factory.Faker('binary', length=64)
