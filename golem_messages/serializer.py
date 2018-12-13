import functools
import logging

import cbor

from . import exceptions


logger = logging.getLogger('golem.core.simpleserializer')


OBJECT_TAG = 239  # unused, old protocol
MESSAGE_TAG = 1000


def wrap_error(wrap_with):
    def _inner(f):
        @functools.wraps(f)
        def _curry(*args, **kwargs):
            try:
                return f(*args, **kwargs)
            except Exception as e:
                raise wrap_with from e
        return _curry
    return _inner


# Public functions

dumps = wrap_error(exceptions.SerializationError)(cbor.dumps)
loads = wrap_error(exceptions.SerializationError)(cbor.loads)
