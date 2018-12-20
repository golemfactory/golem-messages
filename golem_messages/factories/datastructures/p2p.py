# pylint: disable=too-few-public-methods

import factory

from golem_messages.datastructures import p2p as dt_p2p


class Node(factory.Factory):
    class Meta:
        model = dt_p2p.Node

    # considered as difficult by `keysauth.is_pubkey_difficult` with level 10
    key = '00adbeef' + 'deadbeef' * 15


class Peer(factory.DictFactory):
    class Meta:
        model = dt_p2p.Peer

    address = factory.Faker('ipv4')
    port = factory.Faker('random_int', min=1, max=2**16-1)
    node = factory.SubFactory(Node)
