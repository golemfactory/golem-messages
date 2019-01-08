import uuid
import factory

from golem_messages.factories.datastructures.p2p import Node
from golem_messages.message import p2p as dt_p2p


class WantToStartTaskSession(factory.Factory):
    class Meta:
        model = dt_p2p.WantToStartTaskSession

    node_info = factory.SubFactory(Node)
    conn_id = 'mockuuid-want-tost-artt-asksession'
    super_node_info = factory.SubFactory(Node)
