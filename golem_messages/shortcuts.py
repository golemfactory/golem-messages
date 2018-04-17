import functools

from golem_messages.message import base
from . import cryptography


def dump(msg, privkey, pubkey):
    if privkey:
        sign = functools.partial(cryptography.ecdsa_sign, privkey)
    else:
        sign = None
    if pubkey:
        encrypt = functools.partial(
            cryptography.ECCx.encrypt,
            raw_pubkey=pubkey,
        )
    else:
        encrypt = None
    return msg.serialize(sign_func=sign, encrypt_func=encrypt)


def load(data, privkey, pubkey, check_time=True):
    def decrypt(payload):
        if not privkey:
            return payload
        ecc = cryptography.ECCx(privkey)
        return ecc.decrypt(payload)

    msg = base.Message.deserialize(
        data, decrypt, check_time, verify_sender=pubkey)
    return msg
