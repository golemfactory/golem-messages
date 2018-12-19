import functools
import logging

from golem_messages import datastructures
from golem_messages import validators

logger = logging.getLogger(__name__)


class Node(datastructures.Container):
    __slots__ = {
        'node_name': (
            functools.partial(
                validators.validate_varchar,
                max_length=float('infinity'),
            ),
        ),
        'key': (validators.validate_varchar128, ),
        'prv_port': (validators.validate_integer, ),
        'pub_port': (validators.validate_integer, ),
        'p2p_prv_port': (validators.validate_integer, ),
        'p2p_pub_port': (validators.validate_integer, ),
        'prv_addr': (),  # str
        'pub_addr': (),  # str
        'prv_addresses': (),  # List[str]
        'hyperdrive_prv_port': (validators.validate_integer, ),
        'hyperdrive_pub_port': (validators.validate_integer, ),
        'port_statuses': (),   # dict
        # Please do not remove the nat_type property,
        # it's still useful for stats / debugging connectivity.
        'nat_type': (),  # List[str]
    }

    DEFAULTS = {
        'prv_addresses': lambda: [],
        'port_statuses': lambda: {},
        'nat_type': lambda: [],
    }

    def update_public_info(self) -> None:
        # pylint: disable=attribute-defined-outside-init
        if self.pub_addr is None:
            self.pub_addr = self.prv_addr
        if self.pub_port is None:
            self.pub_port = self.prv_port
        if self.p2p_pub_port is None:
            self.p2p_pub_port = self.p2p_prv_port
        if self.hyperdrive_pub_port is None:
            self.hyperdrive_pub_port = self.hyperdrive_prv_port

    def is_super_node(self) -> bool:
        if self.pub_addr is None or self.prv_addr is None:
            return False
        return self.pub_addr == self.prv_addr

    def __repr__(self) -> str:
        return "<Node {!r}, (key: {!r})>".format(self.node_name, self.key)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Node):
            raise TypeError(
                "Mismatched types: expected Node, got {}".format(type(other))
            )
        return self.to_dict() == other.to_dict()


class NodeSlotMixin:
    __slots__ = ()

    def serialize_slot(self, key, value):
        if key in self.NODE_SLOTS:
            return self.serialize_node(value)
        return super().serialize_slot(key, value)

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key=key, value=value)
        if key in self.NODE_SLOTS:
            return self.deserialize_node(key, value)
        return value

    @classmethod
    def serialize_node(cls, value: Node) -> dict:
        return value.to_dict()

    @classmethod
    def deserialize_node(cls, key, value: dict) -> Node:
        validators.validate_dict(key, value)
        return Node(**value)
