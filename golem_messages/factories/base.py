# pylint: disable=too-few-public-methods
import factory

from golem_messages.message import base
from golem_messages.factories import p2p as p2p_factories
from . import helpers


class HelloFactory(helpers.MessageFactory):
    class Meta:
        model = base.Hello

    rand_val = factory.Faker("pyint")
    proto_id = factory.Faker("pyint")
    node_info = factory.SubFactory(p2p_factories.Node)
