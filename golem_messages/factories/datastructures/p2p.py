# pylint: disable=too-few-public-methods

import factory

from golem_messages.datastructures import p2p as dt_p2p


class Node(factory.Factory):
    class Meta:
        model = dt_p2p.Node

    #node_name = factory.Faker('name')
    # considered as difficult by `keysauth.is_pubkey_difficult` with level 10
    key = '00adbeef' + 'deadbeef' * 15
