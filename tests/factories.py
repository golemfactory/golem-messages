import uuid
import factory

from golem_messages.message.tasks import (
    ComputeTaskDef, TaskToCompute, SubtaskResultRejected
)

from golem_messages.message.concents import (
    SubtaskResultVerify, AckSubtaskResultVerify, SubtaskResultSettled,
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

    SubtaskResultVerifyFactory(slots__subtask_id='some-id')

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


class SubtaskResultRejectedFactory(factory.Factory):
    class Meta:
        model = SubtaskResultRejected

    slots = factory.SubFactory(SlotsFactory,
                               subtask_id='test-si-{}'.format(uuid.uuid4()))


class SubtaskResultVerifySlotsFactory(SlotsFactory):
    class Meta:
        model = tuple

    subtask_result_rejected = factory.SubFactory(SubtaskResultRejectedFactory)


class SubtaskResultVerifyFactory(factory.Factory):
    class Meta:
        model = SubtaskResultVerify

    slots = factory.SubFactory(SubtaskResultVerifySlotsFactory)


class AckSubtaskResultVerifySlotsFactory(SlotsFactory):
    class Meta:
        model = tuple

    subtask_result_verify = factory.SubFactory(SubtaskResultVerifyFactory)


class AckSubtaskResultVerifyFactory(factory.Factory):
    class Meta:
        model = AckSubtaskResultVerify

    slots = factory.SubFactory(AckSubtaskResultVerifySlotsFactory)


class SubtaskResultSettledSlotsFactory(SlotsFactory):
    class Meta:
        model = tuple

    origin = SubtaskResultSettled.Origin.ResultsAcceptedTimeout
    task_to_compute = factory.SubFactory(TaskToComputeFactory)


class SubtaskResultSettledFactory(factory.Factory):
    class Meta:
        model = SubtaskResultSettled

    slots = factory.SubFactory(SubtaskResultSettledSlotsFactory)

    @classmethod
    def origin_acceptance_timeout(cls, *args, **kwargs):
        kwargs.update({
            'slots__origin':
                SubtaskResultSettled.Origin.ResultsAcceptedTimeout
        })
        return cls(*args, **kwargs)

    @classmethod
    def origin_results_rejected(cls, *args, **kwargs):
        kwargs.update({
            'slots__origin':
                SubtaskResultSettled.Origin.ResultsRejected
        })
        return cls(*args, **kwargs)
