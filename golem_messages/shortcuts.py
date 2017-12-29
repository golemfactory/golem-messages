import functools

from . import cryptography
from . import message


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

    def verify(msg_hash, signature):
        if not pubkey:
            return
        cryptography.ecdsa_verify(
            pubkey=pubkey,
            signature=signature,
            message=msg_hash
        )

    msg = message.Message.deserialize(data, decrypt, check_time, verify)
    return msg
