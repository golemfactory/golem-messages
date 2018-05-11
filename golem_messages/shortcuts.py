import functools
import time
from collections import defaultdict

from golem_messages.message import base
from . import cryptography


class Profiler:

    def __init__(self):
        self.ncalls = defaultdict(lambda: 0)
        self.calltime = defaultdict(lambda: 0)

    def profile(self, func):
        @functools.wraps(func)
        def wrapped(*args, **kwargs):
            start = time.perf_counter()
            result = func(*args, **kwargs)
            stop = time.perf_counter()
            self.ncalls[func.__qualname__] += 1
            self.calltime[func.__qualname__] += (stop - start)
            return result
        return wrapped

    def print_stats(self, *_, **__):
        for k in self.ncalls:
            print('%s : %0.6f s' % (k, self.calltime[k] / self.ncalls[k]))


profiler = Profiler()
ecies = cryptography.ECIES()


@profiler.profile
def dump(msg, privkey, pubkey):
    if pubkey:
        encrypt = functools.partial(
            ecies.ecies_encrypt,
            raw_pubkey=pubkey
        )
    else:
        encrypt = None
    return msg.serialize(sign_as=privkey, encrypt_func=encrypt)


@profiler.profile
def load(data, privkey, pubkey, check_time=True):
    def decrypt(payload):
        if not privkey:
            return payload
        return ecies.ecies_decrypt(payload, privkey)

    msg = base.Message.deserialize(
        data, decrypt, check_time, sender_public_key=pubkey)
    return msg
