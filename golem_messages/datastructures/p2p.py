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

    REQUIRED = (
        'node_name',
    )

    def collect_network_info(self, seed_host=None, use_ipv6=False):
        from golem.core import hostaddress
        # pylint: disable=attribute-defined-outside-init
        self.prv_addresses = hostaddress.get_host_addresses(use_ipv6)

        if not self.pub_addr:
            self.pub_addr, _ = hostaddress.get_external_address()

        if not self.prv_addr:
            if self.pub_addr in self.prv_addresses:
                self.prv_addr = self.pub_addr
            else:
                self.prv_addr = hostaddress.get_host_address(
                    seed_host,
                    use_ipv6,
                )

        if self.prv_addr not in self.prv_addresses:
            logger.warning(
                "Specified node address %s is not among detected "
                "network addresses: %s",
                self.prv_addr,
                self.prv_addresses,
            )

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

    def __str__(self) -> str:
        return "Node {}, (key: {})".format(self.node_name, self.key)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Node):
            raise TypeError(
                "Mismatched types: expected Node, got {}".format(type(other))
            )
        return self.to_dict() == other.to_dict()
