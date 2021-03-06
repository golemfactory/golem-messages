import uuid

from . import utils


SEED_LEN = 6


def generate_id(seed: bytes) -> str:
    """
    seeds last 48 bits from given seed as node in generated uuid1
    :param bytes seed: for example `KeysAuth.public_key`
    :returns: string uuid1 based on timestamp and given seed
    """
    return str(uuid.uuid1(node=seed_to_node(seed)))


def generate_id_from_hex(hex_seed: str) -> str:
    seed = utils.decode_hex(hex_seed)
    return generate_id(seed)


def generate_new_id_from_id(id_: str) -> str:
    """
    seeds last 48 bits from id_ as node in generated uuid1
    :returns: uuid1 based on timestamp and id_
    """
    from_uuid = uuid.UUID(id_)
    return str(uuid.uuid1(node=from_uuid.node))


def check_id_seed(id_: str, seed: bytes) -> bool:
    try:
        checked_uuid = uuid.UUID(id_)
        return seed_to_node(seed) == checked_uuid.node
    except ValueError:
        return False


def check_id_hex_seed(id_: str, hex_seed: str) -> bool:
    seed = utils.decode_hex(hex_seed)
    return check_id_seed(id_, seed)


def seed_to_node(seed: bytes) -> int:
    return int.from_bytes(seed[:SEED_LEN], 'big')


def hex_seed_to_node(hex_seed: str) -> int:
    seed = utils.decode_hex(hex_seed)
    return seed_to_node(seed)
