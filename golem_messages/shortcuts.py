import functools

from . import cryptography
from . import message

def dump(msg, privkey, pubkey):
    sign = functools.partial(cryptography.ecdsa_sign, privkey)
    encrypt = functools.partial(cryptography.ECCx.encrypt, raw_pubkey=pubkey)
    return msg.serialize(sign_func=sign, encrypt_func=encrypt)

def load(data, privkey, pubkey):
    def decrypt(payload):
        ecc = cryptography.ECCx(privkey)
        return ecc.decrypt(payload)
    msg = message.Message.deserialize(data, decrypt)
    cryptography.ecdsa_verify(pubkey, msg.sig, msg.get_short_hash())
    return msg
