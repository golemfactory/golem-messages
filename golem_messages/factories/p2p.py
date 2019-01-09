# pylint: disable=too-few-public-methods
import uuid
import factory

from golem_messages.factories.datastructures.p2p import Node
from golem_messages.message import p2p as dt_p2p

from . import helpers


class WantToStartTaskSessionFactory(helpers.MessageFactory):
    class Meta:
        model = dt_p2p.WantToStartTaskSession

    node_info = factory.SubFactory(Node)
    conn_id = str(uuid.uuid4())
    super_node_info = factory.SubFactory(Node)


class SetTaskSessionFactory(helpers.MessageFactory):
    class Meta:
        model = dt_p2p.SetTaskSession

    key_id = str(uuid.uuid4())
    node_info = factory.SubFactory(Node)
    conn_id = str(uuid.uuid4())
    super_node_info = factory.SubFactory(Node)
