# pylint: disable=too-few-public-methods,unnecessary-lambda
import calendar
import datetime
import time

import factory

from golem_messages.message import tasks


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

    price = factory.Faker('random_int', min=1 << 20, max=10 << 20)


class ReportComputedTaskFactory(factory.Factory):
    class Meta:
        model = tasks.ReportComputedTask

    task_to_compute = factory.SubFactory(TaskToComputeFactory)


class AckReportComputedTaskFactory(factory.Factory):
    class Meta:
        model = tasks.AckReportComputedTask

    report_computed_task = factory.SubFactory(ReportComputedTaskFactory)


class RejectReportComputedTaskFactory(factory.Factory):
    class Meta:
        model = tasks.RejectReportComputedTask

    task_to_compute = factory.SubFactory(TaskToComputeFactory)


class SubtaskResultsAcceptedFactory(factory.Factory):
    class Meta:
        model = tasks.SubtaskResultsAccepted

    task_to_compute = factory.SubFactory(TaskToComputeFactory)


class SubtaskResultsRejectedFactory(factory.Factory):
    """
    Produces a regular `SubtaskResultsRejected` message, containing the earlier
    `ReportComputedTask` message
    """
    class Meta:
        model = tasks.SubtaskResultsRejected

    report_computed_task = factory.SubFactory(ReportComputedTaskFactory)
