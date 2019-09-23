# pylint: disable=too-few-public-methods

import datetime
import factory

from golem_messages import constants
from golem_messages import cryptography
from golem_messages.datastructures import masking
from golem_messages.datastructures import tasks as dt_tasks
from golem_messages.factories import helpers
from golem_messages.factories.datastructures import p2p as dt_p2p_factories
from golem_messages.factories.helpers import random_eth_pub_key
from golem_messages.utils import encode_hex as encode_key_id


def _date_now() -> int:
    return int(datetime.datetime.now(tz=datetime.timezone.utc).timestamp())


class TaskHeaderFactory(factory.Factory):
    class Meta:
        model = dt_tasks.TaskHeader
        exclude = ('requestor_public_key', )

    requestor_public_key = factory.LazyFunction(lambda: random_eth_pub_key())
    mask = factory.Faker('binary', length=masking.Mask.MASK_BYTES)
    timestamp = factory.LazyFunction(lambda: _date_now())
    task_id = factory.LazyAttribute(
        lambda o: helpers.fake_golem_uuid(
            o.requestor_public_key
        ),
    )
    market_type = dt_tasks.TaskHeader.MARKET_TYPE.Brass
    budget = factory.Faker('random_int', min=1, max=10)
    task_owner = factory.LazyAttribute(
        lambda o: dt_p2p_factories.Node(
            key=o.requestor_public_key
        ).to_dict()
    )
    deadline = factory.LazyFunction(lambda: _date_now() + 3600)
    subtask_timeout = factory.Faker('random_int', min=60, max=600)
    environment = "DEFAULT"
    min_version = factory.LazyFunction(helpers.fake_version)
    estimated_memory = factory.Faker('random_int', max=4096)
    max_price = factory.Faker('random_int', min=10, max=50)
    subtasks_count = factory.Faker('random_int', min=1, max=256)

    @factory.post_generation
    def sign(th: dt_tasks.TaskHeader, _, __, **kwargs):  # noqa pylint: disable=no-self-argument
        privkey = kwargs.pop('privkey', None)

        if kwargs:
            raise factory.errors.InvalidDeclarationError(
                "Unknown arguments encountered %s" % list(kwargs.keys()))

        if privkey:
            th.sign(privkey)
