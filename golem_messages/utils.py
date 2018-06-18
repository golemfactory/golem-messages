from uuid import UUID
import binascii


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
