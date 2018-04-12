# pylint: disable=too-few-public-methods
import factory

from golem_messages.message import base


class HelloFactory(factory.Factory):
    class Meta:
        model = base.Hello

    rand_val = factory.Faker("pyint")
    proto_id = factory.Faker("pyint")
    node_name = factory.Faker("name")
