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
