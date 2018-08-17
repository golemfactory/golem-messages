# pylint: disable=too-few-public-methods,unnecessary-lambda
import calendar
import datetime
import os
import time
import typing

from eth_utils import encode_hex
import factory.fuzzy
import faker

from golem_messages import cryptography
from golem_messages.utils import encode_hex as encode_key_id
from golem_messages.message import tasks

from . import helpers


class TaskOwnerFactory(factory.DictFactory):
    key = factory.Faker('binary', length=64)
    node_name = factory.Faker('name')


class WantToComputeTaskFactory(helpers.MessageFactory):
    class Meta:
        model = tasks.WantToComputeTask

    node_name = factory.Faker('name')
    task_id = factory.Faker('uuid4')


class CTDBlenderExtraDataFactory(factory.DictFactory):
    class Meta:
        model = dict

    path_root = ''
    start_task = 1
    end_task = 1
    total_tasks = 1
    outfilebasename = 'test task'
    scene_file = '/golem/resources/look_to_windward.blend'
    script_src = 'pass'
    frames = [1]
    output_format = 'PNG'


class ComputeTaskDefFactory(factory.DictFactory):
    class Meta:
        model = tasks.ComputeTaskDef

    task_id = factory.Faker('uuid4')
    subtask_id = factory.Faker('uuid4')
    deadline = factory.LazyFunction(
        lambda: calendar.timegm(time.gmtime()) +
        int(datetime.timedelta(days=1).total_seconds()))
    src_code = factory.Faker('text')
    extra_data = factory.SubFactory(CTDBlenderExtraDataFactory)


class TaskToComputeFactory(helpers.MessageFactory):
    class Meta:
        model = tasks.TaskToCompute

    requestor_id = factory.SelfAttribute(
        'requestor_public_key')
    provider_id = factory.SelfAttribute(
        'provider_public_key'
    )
    compute_task_def = factory.SubFactory(ComputeTaskDefFactory)
    provider_public_key = factory.LazyFunction(
        lambda: encode_key_id(cryptography.ECCx(None).raw_pubkey))
    provider_ethereum_public_key = factory.SelfAttribute(
        'provider_public_key'
    )
    requestor_public_key = factory.LazyFunction(
        lambda: encode_key_id(cryptography.ECCx(None).raw_pubkey))

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

    # pylint: disable=no-self-argument

    @factory.post_generation
    def ethsig(
            ttc: tasks.TaskToCompute, _, __,
            privkey: typing.Optional[bytes] = None,
            keys: typing.Optional[cryptography.ECCx] = None,
    ):
        if keys and privkey:
            raise factory.errors.InvalidDeclarationError(
                "You need to specify either `privkey` or `keys`, not both.")

        # if there's no privkey given and there's also so
        # requestor_ethereum_public_key set on the TTC,
        # just use a keypair (given or generated) to
        # both fill message's public key field
        # and generate the ethereum signature
        if not privkey and not ttc.requestor_ethereum_public_key:
            keys = keys or cryptography.ECCx(None)
            privkey = keys.raw_privkey
            ttc.requestor_ethereum_public_key = encode_key_id(keys.raw_pubkey)

        if privkey:
            if not ttc.requestor_ethereum_public_key:
                raise factory.errors.InvalidDeclarationError(
                    "It doesn't really make sense to"
                    " generate the ethereum signature"
                    " with no `requestor_ethereum_public_key` in place...")
            ttc.generate_ethsig(privkey)

    # pylint: enable=no-self-argument


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
