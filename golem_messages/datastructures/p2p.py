import functools
import logging

from golem_messages import datastructures
from golem_messages import exceptions
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
        'prv_port': (validators.validate_port, ),
        'pub_port': (validators.validate_port, ),
        'p2p_prv_port': (validators.validate_port, ),
        'p2p_pub_port': (validators.validate_port, ),
        'prv_addr': (validators.validate_ipaddress, ),
        'pub_addr': (validators.validate_ipaddress, ),
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
        if value and key in self.NODE_SLOTS:
            return self.serialize_node(key, value)
        return super().serialize_slot(key, value)

    def deserialize_slot(self, key, value):
        value = super().deserialize_slot(key=key, value=value)
        if value and key in self.NODE_SLOTS:
            return self.deserialize_node(key, value)
        return value

    @classmethod
    def serialize_node(cls, key, value: Node) -> dict:
        try:
            return value.to_dict()
        except exceptions.FieldError:
            raise
        except Exception:  # pylint: disable=broad-except
            raise exceptions.FieldError(
                "Can't serialize",
                field=key,
                value=value,
            )

    @classmethod
    def deserialize_node(cls, key, value: dict) -> Node:
        validators.validate_dict(key, value)
        return Node(**value)


class Peer(datastructures.ValidatingDict, datastructures.FrozenDict):
    ITEMS = {
        'address': None,
        'port': None,
        'node': None,
    }

    def __setitem__(self, key, value):
        if key == 'node':
            if isinstance(value, dict):
                value = Node(**value)
        super().__setitem__(key, value)

    validate_address = functools.partial(
        validators.validate_ipaddress,
        "address",
    )

    validate_port = functools.partial(
        validators.validate_port,
        "port",
    )

    @classmethod
    def validate_node(cls, value):
        if not isinstance(value, Node):
            raise exceptions.FieldError(
                "Node is expected not {}".format(
                    type(value),
                ),
                field="node",
                value=value,
            )

    def serialize(self) -> dict:
        serialized = dict(self)
        serialized['node'] = serialized['node'].to_dict()
        return serialized
