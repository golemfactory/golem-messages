# pylint: disable=too-few-public-methods,unnecessary-lambda
import calendar
import datetime
import os
import time

import factory.fuzzy
from eth_utils import encode_hex

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

    subtask_id = factory.Faker('uuid4')
    task_to_compute = factory.SubFactory(TaskToComputeFactory)


class TaskFailureFactory(helpers.MessageFactory):
    class Meta:
        model = tasks.TaskFailure

    subtask_id = factory.Faker('uuid4')
    err = factory.Faker('sentence')
    task_to_compute = factory.SubFactory(TaskToComputeFactory)


class ReportComputedTaskFactory(helpers.MessageFactory):
    class Meta:
        model = tasks.ReportComputedTask

    result_type = 0
    computation_time = factory.Faker('pyfloat')
    node_name = factory.Faker('name')
    address = factory.Faker('ipv4')
    port = factory.Faker('pyint')
    eth_account = factory.LazyFunction(lambda: encode_hex(os.urandom(20)))
    key_id = factory.Faker('binary', length=64)
    task_to_compute = factory.SubFactory(TaskToComputeFactory)
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
    task_to_compute = factory.SubFactory(TaskToComputeFactory)
    task_failure = factory.SubFactory(
        TaskFailureFactory,
        task_to_compute=factory.SelfAttribute(
            '..task_to_compute',
        )
    )
    cannot_compute_task = factory.SubFactory(
        CannotComputeTaskFactory,
        task_to_compute=factory.SelfAttribute(
            '..task_to_compute',
        )
    )


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
