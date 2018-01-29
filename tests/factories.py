import uuid
import factory


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
    key = factory.Sequence(lambda n: 'node {}'.format(n))
    node_name = factory.Faker('name')


class ComputeTaskDefFactory(factory.DictFactory):
    class Meta:
        model = tasks.ComputeTaskDef

    task_owner = factory.SubFactory(TaskOwnerFactory)
    task_id = factory.Faker('uuid4')
    subtask_id = factory.Faker('uuid4')


class TaskToComputeSlotsFactory(SlotsFactory):
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


class TaskToComputeFactory(factory.Factory):
    class Meta:
        model = tasks.TaskToCompute

    slots = factory.SubFactory(TaskToComputeSlotsFactory)


class SubtaskResultsRejectedFactory(factory.Factory):
    class Meta:
        model = tasks.SubtaskResultsRejected

    slots = factory.SubFactory(SlotsFactory,
                               subtask_id='test-si-{}'.format(uuid.uuid4()))


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


class SubtaskResultsSettledSlotsFactory(SlotsFactory):
    class Meta:
        model = tuple

    origin = concents.SubtaskResultsSettled.Origin.ResultsAcceptedTimeout
    task_to_compute = factory.SubFactory(TaskToComputeFactory)


class SubtaskResultsSettledFactory(factory.Factory):
    class Meta:
        model = concents.SubtaskResultsSettled

    slots = factory.SubFactory(SubtaskResultsSettledSlotsFactory)

    @classmethod
    def origin_acceptance_timeout(cls, *args, **kwargs):
        kwargs['slots__origin'] = \
                concents.SubtaskResultsSettled.Origin.ResultsAcceptedTimeout
        return cls(*args, **kwargs)

    @classmethod
    def origin_results_rejected(cls, *args, **kwargs):
        kwargs['slots__origin'] = \
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
