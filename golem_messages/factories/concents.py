# pylint: disable=too-few-public-methods,unnecessary-lambda
import random
import time

from ethereum.utils import denoms
import factory.fuzzy
import faker

from golem_messages.factories import tasks as tasks_factories
from golem_messages.message import concents
from . import helpers
from .tasks import (
    SubtaskResultsAcceptedFactory, SubtaskResultsRejectedFactory
)


class FileInfoFactory(factory.DictFactory):
    class Meta:
        model = concents.FileTransferToken.FileInfo

    path = factory.LazyFunction(lambda: faker.Faker().file_path()[1:])
    checksum = factory.LazyFunction(lambda: 'sha1:' + faker.Faker().sha1())
    size = factory.Faker('random_int', min=1 << 20, max=10 << 20)


class ForceReportComputedTaskFactory(helpers.MessageFactory):
    class Meta:
        model = concents.ForceReportComputedTask

    result_hash = factory.Faker('text')
    report_computed_task = factory.SubFactory(
        'golem_messages.factories.tasks.ReportComputedTaskFactory')


class SubtaskResultsVerifyFactory(helpers.MessageFactory):
    class Meta:
        model = concents.SubtaskResultsVerify

    subtask_results_rejected = factory.SubFactory(
        'golem_messages.factories.tasks.SubtaskResultsRejectedFactory')


class AckSubtaskResultsVerifyFactory(helpers.MessageFactory):
    class Meta:
        model = concents.AckSubtaskResultsVerify

    subtask_results_verify = factory.SubFactory(SubtaskResultsVerifyFactory)


class SubtaskResultsSettledFactory(helpers.MessageFactory):
    class Meta:
        model = concents.SubtaskResultsSettled

    origin = concents.SubtaskResultsSettled.Origin.ResultsAcceptedTimeout
    task_to_compute = factory.SubFactory(
        'golem_messages.factories.tasks.TaskToComputeFactory')

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


class ForceGetTaskResultFactory(helpers.MessageFactory):
    class Meta:
        model = concents.ForceGetTaskResult

    report_computed_task = factory.SubFactory(
        'golem_messages.factories.tasks.ReportComputedTaskFactory')


class AckForceGetTaskResultFactory(helpers.MessageFactory):
    class Meta:
        model = concents.AckForceGetTaskResult

    force_get_task_result = factory.SubFactory(ForceGetTaskResultFactory)


class ForceGetTaskResultFailedFactory(helpers.MessageFactory):
    class Meta:
        model = concents.ForceGetTaskResultFailed

    task_to_compute = factory.SubFactory(
        'golem_messages.factories.tasks.TaskToComputeFactory')


class ForceGetTaskResultRejectedFactory(helpers.MessageFactory):
    class Meta:
        model = concents.ForceGetTaskResultRejected

    force_get_task_result = factory.SubFactory(ForceGetTaskResultFactory)


class FileTransferTokenFactory(helpers.MessageFactory):
    class Meta:
        model = concents.FileTransferToken

    subtask_id = factory.Faker('uuid4')
    token_expiration_deadline = 1800
    storage_cluster_address = factory.Faker('url')
    authorized_client_public_key = factory.Faker('binary', length=64)
    operation = concents.FileTransferToken.Operation.upload
    files = factory.List([
        factory.SubFactory(FileInfoFactory)
    ])

    # pylint: disable=no-self-argument

    @factory.post_generation
    def upload(obj, create, extracted, **_):
        if not create:
            return

        if extracted:
            obj.operation = concents.FileTransferToken.Operation.upload

    @factory.post_generation
    def download(obj, create, extracted, **_):
        if not create:
            return

        if extracted:
            obj.operation = concents.FileTransferToken.Operation.download

    # pylint: enable=no-self-argument


class ForceGetTaskResultUploadFactory(helpers.MessageFactory):
    class Meta:
        model = concents.ForceGetTaskResultUpload

    force_get_task_result = factory.SubFactory(ForceGetTaskResultFactory)
    file_transfer_token = factory.SubFactory(
        FileTransferTokenFactory, upload=True)


class ForceGetTaskResultDownloadFactory(helpers.MessageFactory):
    class Meta:
        model = concents.ForceGetTaskResultDownload

    force_get_task_result = factory.SubFactory(ForceGetTaskResultFactory)
    file_transfer_token = factory.SubFactory(
        FileTransferTokenFactory, download=True)


class ForceSubtaskResultsResponseFactory(helpers.MessageFactory):
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


class ForceSubtaskResultsFactory(helpers.MessageFactory):
    class Meta:
        model = concents.ForceSubtaskResults

    ack_report_computed_task = factory.SubFactory(
        'golem_messages.factories.tasks.AckReportComputedTaskFactory')


class ForceSubtaskResultsRejectedFactory(helpers.MessageFactory):
    class Meta:
        model = concents.ForceSubtaskResultsRejected

    force_subtask_results = factory.SubFactory(ForceSubtaskResultsFactory)
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


class ForcePaymentFactory(helpers.MessageFactory):
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


class ForcePaymentCommittedFactory(helpers.MessageFactory):
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


class ForcePaymentRejectedFactory(helpers.MessageFactory):
    class Meta:
        model = concents.ForcePaymentRejected

    force_payment = factory.SubFactory(ForcePaymentFactory)
    reason = concents.ForcePaymentRejected.REASON.NoUnsettledTasksFound


class ForceReportComputedTaskResponseFactory(helpers.MessageFactory):
    class Meta:
        model = concents.ForceReportComputedTaskResponse

    reason = factory.fuzzy.FuzzyChoice(
        concents.ForceReportComputedTaskResponse.REASON
    )
    ack_report_computed_task = helpers.optional_subfactory(
        'ack_report_computed_task',
        tasks_factories.AckReportComputedTaskFactory
    )
    reject_report_computed_task = helpers.optional_subfactory(
        'reject_report_computed_task',
        tasks_factories.RejectReportComputedTaskFactory
    )

    @classmethod
    def with_ack_report_computed_task(cls, *args, **kwargs):
        if 'reason' not in kwargs:
            kwargs.update({
                'reason': cls._meta.model.REASON.AckFromRequestor
            })
        return cls(*args, **kwargs,
                   ack_report_computed_task___generate=True)

    @classmethod
    def with_reject_report_computed_task(cls, *args, **kwargs):
        if 'reason' in kwargs:
            kwargs.update({
                'reason': cls._meta.model.REASON.RejectFromRequestor
            })
        return cls(
            *args, **kwargs,
            reject_report_computed_task___generate=True,
            reject_report_computed_task__attached_task_to_compute___generate=\
                True,
        )


class VerdictReportComputedTaskFactory(helpers.MessageFactory):
    class Meta:
        model = concents.VerdictReportComputedTask

    force_report_computed_task = factory.SubFactory(
        ForceReportComputedTaskFactory)
    ack_report_computed_task = factory.SubFactory(
        'golem_messages.factories.tasks.AckReportComputedTaskFactory',
    )

    # pylint: disable=no-self-argument

    @factory.post_generation
    def arct_report_computed_task(msg, _create, _extracted, **kwargs):
        rct = helpers.clone_message(
            msg.force_report_computed_task.report_computed_task
        )

        for k, v in kwargs.items():
            setattr(rct, k, v)

        msg.ack_report_computed_task.report_computed_task = rct

    # pylint: enable=no-self-argument


class ClientAuthorizationFactory(helpers.MessageFactory):
    class Meta:
        model = concents.ClientAuthorization

    client_public_key = factory.Faker('binary', length=64)


class ServiceRefusedFactory(helpers.MessageFactory):
    class Meta:
        model = concents.ServiceRefused

    reason = factory.fuzzy.FuzzyChoice(concents.ServiceRefused.REASON)
    task_to_compute = factory.SubFactory(
        'golem_messages.factories.tasks.TaskToComputeFactory')
