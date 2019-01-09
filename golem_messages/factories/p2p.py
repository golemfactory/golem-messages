# pylint: disable=too-few-public-methods
import factory

from golem_messages.factories.datastructures.p2p import Node
from golem_messages.message import p2p as dt_p2p

from . import helpers


class WantToStartTaskSessionFactory(helpers.MessageFactory):
    class Meta:
        model = dt_p2p.WantToStartTaskSession

    node_info = factory.SubFactory(Node)
    conn_id = 'mockuuid-want-tost-artt-asksession'
    super_node_info = factory.SubFactory(Node)


class SetTaskSessionFactory(helpers.MessageFactory):
    class Meta:
        model = dt_p2p.SetTaskSession

    key_id = 'mockuuid-sett-asks-essi-onkey'
    node_info = factory.SubFactory(Node)
    conn_id = 'mockuuid-sett-asks-essi-onkey'
    super_node_info = factory.SubFactory(Node)
