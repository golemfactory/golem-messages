import functools

from golem_messages.message import base
from . import cryptography

ecies = cryptography.ECIES()


def dump(msg, privkey, pubkey):
    if pubkey:
        encrypt = functools.partial(
            ecies.ecies_encrypt,
            raw_pubkey=pubkey
        )
    else:
        encrypt = None
    return msg.serialize(sign_as=privkey, encrypt_func=encrypt)


def load(data, privkey, pubkey, check_time=True):
    def decrypt(payload):
        if not privkey:
            return payload
        return ecies.ecies_decrypt(payload, privkey)

    msg = base.Message.deserialize(
        data, decrypt, check_time, sender_public_key=pubkey)
    return msg
