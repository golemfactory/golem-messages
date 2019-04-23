import binascii
import copy
from uuid import UUID

from eth_utils import to_checksum_address
from ethereum.utils import sha3

from golem_messages import message


def pubkey_to_address(pubkey: str) -> str:
    """
    convert a hex-encoded pubkey into a checksummed address
    """
    return to_checksum_address(
        sha3(decode_hex(pubkey))[12:].hex(),
    )


def encode_hex(b):
    if isinstance(b, str):
        b = bytes(b, 'utf-8')
    if isinstance(b, (bytes, bytearray)):
        if b[0] == b'0' and b[1] == b'x':
            b = b[2:]
        return str(binascii.hexlify(b), 'utf-8')
    raise TypeError('Value must be an instance of str or bytes')


def decode_hex(b):
    return binascii.unhexlify(b)


def uuid_to_bytes32(uuid: UUID) -> bytes:
    return uuid.bytes + b'\x00' * 16


def bytes32_to_uuid(b: bytes) -> UUID:
    return UUID(bytes=b[:16])


def copy_and_sign(msg: message.base.Message, private_key: bytes) \
        -> message.base.Message:
    """Returns signed shallow copy of message

    Copy is made only if original is unsigned. It's useful
    when message is delayed in queue.
    """
    if msg.sig is None:
        msg = copy.copy(msg)
        msg.sign_message(private_key)
    return msg
