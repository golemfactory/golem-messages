import uuid
import factory

from golem_messages.message.tasks import (
    ComputeTaskDef, TaskToCompute, SubtaskResultsRejected, ReportComputedTask,
)

from golem_messages.message.concents import (
    SubtaskResultsVerify, AckSubtaskResultsVerify, SubtaskResultsSettled,
    ForceGetTaskResult, ForceGetTaskResultAck, ForceGetTaskResultFailed,
    ForceGetTaskResultRejected, ForceGetTaskResultUpload,
    ForceReportComputedTask, FileTransferToken,
)

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


class ComputeTaskDefFactory(factory.DictFactory):
    class Meta:
        model = ComputeTaskDef

    task_owner = factory.SubFactory(TaskOwnerFactory)


class TaskToComputeSlotsFactory(SlotsFactory):
    requestor_id = factory.Sequence(lambda n: 'master {}'.format(n))
    provider_id = factory.Sequence(lambda n: 'servant {}'.format(n))

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
        model = TaskToCompute

    slots = factory.SubFactory(TaskToComputeSlotsFactory)


class SubtaskResultsRejectedFactory(factory.Factory):
    class Meta:
        model = SubtaskResultsRejected

    slots = factory.SubFactory(SlotsFactory,
                               subtask_id='test-si-{}'.format(uuid.uuid4()))


class ReportComputedTaskSlotsFactory(SlotsFactory):
    class Meta:
        model = tuple

    task_to_compute = factory.SubFactory(TaskToComputeFactory)


class ReportComputedTaskFactory(factory.Factory):
    class Meta:
        model = ReportComputedTask

    slots = factory.SubFactory(ReportComputedTaskSlotsFactory)


class ForceReportComputedTaskSlotsFactory(SlotsFactory):
    class Meta:
        model = tuple

    task_to_compute = factory.SubFactory(TaskToComputeFactory)


class ForceReportComputedTaskFactory(factory.Factory):
    class Meta:
        model = ForceReportComputedTask

    slots = factory.SubFactory(ForceReportComputedTaskSlotsFactory)


class SubtaskResultsVerifySlotsFactory(SlotsFactory):
    class Meta:
        model = tuple

    subtask_result_rejected = factory.SubFactory(SubtaskResultsRejectedFactory)


class SubtaskResultsVerifyFactory(factory.Factory):
    class Meta:
        model = SubtaskResultsVerify

    slots = factory.SubFactory(SubtaskResultsVerifySlotsFactory)


class AckSubtaskResultsVerifySlotsFactory(SlotsFactory):
    class Meta:
        model = tuple

    subtask_result_verify = factory.SubFactory(SubtaskResultsVerifyFactory)


class AckSubtaskResultsVerifyFactory(factory.Factory):
    class Meta:
        model = AckSubtaskResultsVerify

    slots = factory.SubFactory(AckSubtaskResultsVerifySlotsFactory)


class SubtaskResultsSettledSlotsFactory(SlotsFactory):
    class Meta:
        model = tuple

    origin = SubtaskResultsSettled.Origin.ResultsAcceptedTimeout
    task_to_compute = factory.SubFactory(TaskToComputeFactory)


class SubtaskResultsSettledFactory(factory.Factory):
    class Meta:
        model = SubtaskResultsSettled

    slots = factory.SubFactory(SubtaskResultsSettledSlotsFactory)

    @classmethod
    def origin_acceptance_timeout(cls, *args, **kwargs):
        kwargs.update({
            'slots__origin':
                SubtaskResultsSettled.Origin.ResultsAcceptedTimeout
        })
        return cls(*args, **kwargs)

    @classmethod
    def origin_results_rejected(cls, *args, **kwargs):
        kwargs.update({
            'slots__origin':
                SubtaskResultsSettled.Origin.ResultsRejected
        })
        return cls(*args, **kwargs)


class ForceGetTaskResultSlotsFactory(SlotsFactory):
    class Meta:
        model = tuple

    report_computed_task = factory.SubFactory(ReportComputedTaskFactory)
    force_report_computed_task = factory.SubFactory(
        ForceReportComputedTaskFactory)


class ForceGetTaskResultFactory(factory.Factory):
    class Meta:
        model = ForceGetTaskResult

    slots = factory.SubFactory(ForceGetTaskResultSlotsFactory)


class ForceGetTaskResultAckSlotsFactory(SlotsFactory):
    class Meta:
        model = tuple

    force_get_task_result = factory.SubFactory(ForceGetTaskResultFactory)


class ForceGetTaskResultAckFactory(factory.Factory):
    class Meta:
        model = ForceGetTaskResultAck

    slots = factory.SubFactory(ForceGetTaskResultAckSlotsFactory)


class ForceGetTaskResultFailedSlotsFactory(SlotsFactory):
    class Meta:
        model = tuple

    task_to_compute = factory.SubFactory(TaskToComputeFactory)


class ForceGetTaskResultFailedFactory(factory.Factory):
    class Meta:
        model = ForceGetTaskResultFailed

    slots = factory.SubFactory(ForceGetTaskResultFailedSlotsFactory)


class ForceGetTaskResultRejectedSlotsFactory(SlotsFactory):
    class Meta:
        model = tuple

    force_get_task_result = factory.SubFactory(ForceGetTaskResultFactory)


class ForceGetTaskResultRejectedFactory(factory.Factory):
    class Meta:
        model = ForceGetTaskResultRejected

    slots = factory.SubFactory(ForceGetTaskResultRejectedSlotsFactory)


class FileTransferTokenFactory(factory.Factory):
    class Meta:
        model = FileTransferToken

    slots = factory.SubFactory(SlotsFactory,
                               subtask_id='test-si-{}'.format(uuid.uuid4()))


class ForceGetTaskResultUploadSlotsFactory(SlotsFactory):
    class Meta:
        model = tuple

    force_get_task_result = factory.SubFactory(ForceGetTaskResultFactory)
    file_transfer_token = factory.SubFactory(FileTransferTokenFactory)


class ForceGetTaskResultUploadFactory(factory.Factory):
    class Meta:
        model = ForceGetTaskResultUpload

    slots = factory.SubFactory(ForceGetTaskResultUploadSlotsFactory)
