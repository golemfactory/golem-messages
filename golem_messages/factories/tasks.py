# pylint: disable=too-few-public-methods,unnecessary-lambda
import calendar
import datetime
import os
import time

from eth_utils import encode_hex
import factory.fuzzy
import faker

from golem_messages import cryptography
from golem_messages.message import tasks

from . import helpers


class TaskOwnerFactory(factory.DictFactory):
    key = factory.Faker('binary', length=64)
    node_name = factory.Faker('name')


class ComputeTaskDefFactory(factory.DictFactory):
    class Meta:
        model = tasks.ComputeTaskDef

    task_id = factory.Faker('uuid4')
    subtask_id = factory.Faker('uuid4')
    deadline = factory.LazyFunction(
        lambda: calendar.timegm(time.gmtime()) +
        int(datetime.timedelta(days=1).total_seconds()))
    src_code = factory.Faker('text')


class TaskToComputeFactory(helpers.MessageFactory):
    class Meta:
        model = tasks.TaskToCompute

    requestor_id = factory.Faker('binary', length=64)
    provider_id = factory.Faker('binary', length=64)
    compute_task_def = factory.SubFactory(ComputeTaskDefFactory)
    provider_public_key = factory.LazyFunction(
        lambda: cryptography.ECCx(None).raw_pubkey)
    provider_ethereum_public_key = factory.SelfAttribute(
        'provider_public_key'
    )
    requestor_public_key = factory.LazyFunction(
        lambda: cryptography.ECCx(None).raw_pubkey)
    requestor_ethereum_public_key = factory.SelfAttribute(
        'requestor_public_key')

    compute_task_def = factory.SubFactory(ComputeTaskDefFactory)
    package_hash = factory.LazyFunction(lambda: 'sha1:' + faker.Faker().sha1())
    size = factory.Faker('random_int', min=1 << 20, max=10 << 20)
    price = factory.Faker('random_int', min=1 << 20, max=10 << 20)

    @classmethod
    def past_deadline(cls, *args, **kwargs):
        past_deadline = calendar.timegm(time.gmtime()) - \
                        int(datetime.timedelta(days=1).total_seconds())
        kwargs.update({
            'compute_task_def__deadline': past_deadline
        })
        return cls(*args, **kwargs)


class CannotComputeTaskFactory(helpers.MessageFactory):
    class Meta:
        model = tasks.CannotComputeTask

    task_to_compute = factory.SubFactory(TaskToComputeFactory)
    reason = factory.fuzzy.FuzzyChoice(tasks.CannotComputeTask.REASON)


class TaskFailureFactory(helpers.MessageFactory):
    class Meta:
        model = tasks.TaskFailure

    task_to_compute = factory.SubFactory(TaskToComputeFactory)
    err = factory.Faker('sentence')


class ReportComputedTaskFactory(helpers.MessageFactory):
    class Meta:
        model = tasks.ReportComputedTask

    result_type = 0
    node_name = factory.Faker('name')
    address = factory.Faker('ipv4')
    port = factory.Faker('pyint')
    eth_account = factory.LazyFunction(lambda: encode_hex(os.urandom(20)))
    key_id = factory.Faker('binary', length=64)
    task_to_compute = factory.SubFactory(TaskToComputeFactory)
    package_hash = factory.LazyFunction(lambda: 'sha1:' + faker.Faker().sha1())
    size = factory.Faker('random_int', min=1 << 20, max=10 << 20)
    multihash = factory.Faker('text')
    secret = factory.Faker('text')


class AckReportComputedTaskFactory(helpers.MessageFactory):
    class Meta:
        model = tasks.AckReportComputedTask

    report_computed_task = factory.SubFactory(ReportComputedTaskFactory)


class RejectReportComputedTaskFactory(helpers.MessageFactory):
    class Meta:
        model = tasks.RejectReportComputedTask

    reason = factory.fuzzy.FuzzyChoice(tasks.RejectReportComputedTask.REASON)
    attached_task_to_compute = helpers.optional_subfactory(
        'attached_task_to_compute', TaskToComputeFactory)
    task_failure = helpers.optional_subfactory(
        'task_failure', TaskFailureFactory)
    cannot_compute_task = helpers.optional_subfactory(
        'cannot_compute_task', CannotComputeTaskFactory
    )

    @classmethod
    def with_task_to_compute(cls, *args, **kwargs):
        if 'reason' not in kwargs:
            kwargs.update({
                'reason': cls._meta.model.REASON.SubtaskTimeLimitExceeded
            })
        return cls(*args, **kwargs, attached_task_to_compute___generate=True)

    @classmethod
    def with_task_failure(cls, *args, **kwargs):
        if 'reason' not in kwargs:
            kwargs.update({
                'reason': cls._meta.model.REASON.GotMessageTaskFailure
            })
        return cls(*args, **kwargs, task_failure___generate=True)

    @classmethod
    def with_cannot_compute_task(cls, *args, **kwargs):
        if 'reason' not in kwargs:
            kwargs.update({
                'reason': cls._meta.model.REASON.GotMessageCannotComputeTask
            })
        return cls(*args, **kwargs, cannot_compute_task___generate=True)


class SubtaskResultsAcceptedFactory(helpers.MessageFactory):
    class Meta:
        model = tasks.SubtaskResultsAccepted

    task_to_compute = factory.SubFactory(TaskToComputeFactory)
    payment_ts = factory.LazyFunction(lambda: int(time.time()))


class SubtaskResultsRejectedFactory(helpers.MessageFactory):
    """
    Produces a regular `SubtaskResultsRejected` message, containing the earlier
    `ReportComputedTask` message
    """
    class Meta:
        model = tasks.SubtaskResultsRejected

    report_computed_task = factory.SubFactory(ReportComputedTaskFactory)
