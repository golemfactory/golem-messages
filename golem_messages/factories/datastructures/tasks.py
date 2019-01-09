# pylint: disable=too-few-public-methods

import factory

from golem_messages import cryptography
from golem_messages.datastructures import masking
from golem_messages.datastructures import tasks as dt_tasks
from golem_messages.factories import helpers
from golem_messages.factories.datastructures import p2p as dt_p2p_factories
from golem_messages.utils import encode_hex as encode_key_id


class TaskHeaderFactory(factory.Factory):
    class Meta:
        model = dt_tasks.TaskHeader
        exclude = ('requestor_public_key', )

    requestor_public_key = factory.LazyFunction(
        lambda: cryptography.ECCx(None).raw_pubkey
    )

    task_id = factory.LazyAttribute(
        lambda o: helpers.fake_golem_uuid(
            encode_key_id(o.requestor_public_key)
        ),
    )
    task_owner = factory.LazyAttribute(
        lambda o: dt_p2p_factories.Node(
            key=encode_key_id(o.requestor_public_key)
        ).to_dict()
    )
    subtasks_count = factory.Faker('random_int', min=1)
    min_version = factory.LazyFunction(helpers.fake_version)
    mask = factory.Faker('binary', length=masking.Mask.MASK_BYTES)
    environment = "DEFAULT"

    @factory.post_generation
    def sign(th: dt_tasks.TaskHeader, _, __, **kwargs):  # noqa pylint: disable=no-self-argument
        privkey = kwargs.pop('privkey', None)

        if kwargs:
            raise factory.errors.InvalidDeclarationError(
                "Unknown arguments encountered %s" % list(kwargs.keys()))

        if privkey:
            th.sign(privkey)
