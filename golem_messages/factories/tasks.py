# pylint: disable=too-few-public-methods,unnecessary-lambda
import calendar
from contextlib import suppress
import datetime
import time
import typing

import factory.fuzzy
import faker

from golem_messages import cryptography
from golem_messages.factories.datastructures.tasks import TaskHeaderFactory
from golem_messages.utils import encode_hex as encode_key_id
from golem_messages.message import tasks

from . import helpers


class WantToComputeTaskFactory(helpers.MessageFactory):
    class Meta:
        model = tasks.WantToComputeTask

    node_name = factory.Faker('name')
    provider_public_key = factory.LazyFunction(
        lambda: encode_key_id(cryptography.ECCx(None).raw_pubkey))
    provider_ethereum_public_key = factory.SelfAttribute(
        'provider_public_key'
    )
    task_header = factory.SubFactory(TaskHeaderFactory)


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
    provider_id = factory.LazyAttribute(
        lambda o: o.want_to_compute_task.provider_public_key
    )
    compute_task_def = factory.SubFactory(ComputeTaskDefFactory)
    requestor_public_key = factory.LazyFunction(
        lambda: encode_key_id(cryptography.ECCx(None).raw_pubkey))
    want_to_compute_task = factory.SubFactory(WantToComputeTaskFactory)
    package_hash = factory.LazyFunction(lambda: 'sha1:' + faker.Faker().sha1())
    size = factory.Faker('random_int', min=1 << 20, max=10 << 20)
    price = factory.Faker('random_int', min=1 << 20, max=10 << 20)

    @classmethod
    def with_signed_nested_messages(
            cls,
            *args,
            requestor_keys: cryptography.ECCx = None,
            provider_keys: cryptography.ECCx = None,
            **kwargs
    ):
        """
        Generate a TaskToCompute message with nested WantToComputeTask
        and TaskHeader, all signed and consistent with each other
        with regards to included node identities and task ids
        """
        WTCT_TH_KEY = 'want_to_compute_task__task_header'  # noqa
        WTCT_KEY = 'want_to_compute_task'  # noqa
        if requestor_keys:
            encoded_pubkey = encode_key_id(requestor_keys.raw_pubkey)
            # initialize the TTC's requestor public key from the requestor pair
            if 'requestor_public_key' not in kwargs:
                kwargs['requestor_public_key'] = encoded_pubkey

            # initialize the private key for the TTC signature from
            # the requestor pair
            if 'sign__privkey' not in kwargs:
                kwargs['sign__privkey'] = requestor_keys.raw_privkey

            # initialize the TaskHeader's requestor public key from
            # the requestor pair
            if (
                    WTCT_TH_KEY not in kwargs and
                    WTCT_TH_KEY + '__requestor_public_key' not in kwargs
            ):
                kwargs[WTCT_TH_KEY + '__requestor_public_key'] = \
                    encoded_pubkey

            # initialize the TaskHeader's signature private key from
            # the requestor pair
            if (
                    WTCT_TH_KEY not in kwargs and
                    WTCT_TH_KEY + '__sign__privkey' not in kwargs
            ):
                kwargs[WTCT_TH_KEY + '__sign__privkey'] = \
                    requestor_keys.raw_privkey

        if provider_keys:
            # initialize the WantToComputeTask's provider public key from
            # the provider key pair
            if (
                    WTCT_KEY not in kwargs and
                    WTCT_KEY + '__provider_public_key' not in kwargs
            ):
                kwargs[WTCT_KEY + '__provider_public_key'] = \
                    encode_key_id(provider_keys.raw_pubkey)

            # initialize the WantToComputeTask's signature private key from
            # the provider key pair
            if (
                    WTCT_KEY not in kwargs and
                    WTCT_KEY + '__sign__privkey' not in kwargs
            ):
                kwargs[WTCT_KEY + '__sign__privkey'] = \
                    provider_keys.raw_privkey

        return cls(*args, **kwargs)

    @classmethod
    def past_deadline(cls, *args, **kwargs):
        past_deadline = calendar.timegm(time.gmtime()) - \
                        int(datetime.timedelta(days=1).total_seconds())
        kwargs.update({
            'compute_task_def__deadline': past_deadline
        })
        return cls(*args, **kwargs)

    # pylint: disable=no-self-argument,attribute-defined-outside-init

    @factory.post_generation
    def task_id(
            ttc: tasks.TaskToCompute,
            _create,
            extracted,
    ):
        if ttc.compute_task_def is None:
            return

        _task_id = None
        with suppress(AttributeError):
            if ttc.requestor_id == \
                    ttc.want_to_compute_task.task_header.task_owner.key:
                _task_id = ttc.want_to_compute_task.task_header.task_id
        # except AttributeError:
        #     pass

        if extracted:
            _task_id = extracted

        ttc.compute_task_def['task_id'] = _task_id or helpers.fake_golem_uuid(  # noqa pylint: disable=unsupported-assignment-operation
            node_id=ttc.requestor_id,
        )

    @factory.post_generation
    def subtask_id(
            ttc: tasks.TaskToCompute,
            _create,
            extracted,
    ):
        if ttc.compute_task_def is None:
            return

        ttc.compute_task_def['subtask_id'] = extracted or helpers.fake_golem_uuid(  # noqa pylint: disable=unsupported-assignment-operation
            node_id=ttc.requestor_id,
        )

    @factory.post_generation
    def ethsig(
            ttc: tasks.TaskToCompute, _, __,
            privkey: typing.Optional[bytes] = None,
            keys: typing.Optional[cryptography.ECCx] = None,
            disable: bool = False,
    ):
        if (privkey or keys) and disable:
            raise factory.errors.InvalidDeclarationError(
                "Seems unlikely one would intentionally disable the default "
                "ethereum signature generation and at the same time provide "
                "the private key for that purpose")

        if disable:
            return

        if keys and privkey:
            raise factory.errors.InvalidDeclarationError(
                "You need to specify either `privkey` or `keys`, not both.")

        # if there's no privkey given and there's also no
        # requestor_ethereum_public_key set on the TTC,
        # just use a keypair (given or generated) to
        # both fill message's public key field
        # and generate the ethereum signature
        if not privkey and not ttc.requestor_ethereum_public_key:
            keys = keys or cryptography.ECCx(None)
            privkey = keys.raw_privkey
            ttc.requestor_ethereum_public_key = encode_key_id(keys.raw_pubkey)

        if privkey:
            ttc.generate_ethsig(privkey)

    # work around the implicit ordering of the hooks...
    # from: https://factoryboy.readthedocs.io/en/latest/reference.html
    # ```Post-generation hooks are called in the same order
    # they are declared in the factory class```

    @factory.post_generation
    def sign(msg: 'Message', _, __, **kwargs):
        helpers.MessageFactory.sign_message(msg, _, __, **kwargs)

    # pylint: enable=no-self-argument,attribute-defined-outside-init


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

    node_name = factory.Faker('name')
    address = factory.Faker('ipv4')
    port = factory.Faker('pyint')
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

    report_computed_task = factory.SubFactory(ReportComputedTaskFactory)
    payment_ts = factory.LazyFunction(lambda: int(time.time()))


class SubtaskResultsRejectedFactory(helpers.MessageFactory):
    """
    Produces a regular `SubtaskResultsRejected` message, containing the earlier
    `ReportComputedTask` message
    """
    class Meta:
        model = tasks.SubtaskResultsRejected

    report_computed_task = factory.SubFactory(ReportComputedTaskFactory)
