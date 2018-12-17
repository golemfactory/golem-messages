import functools

import cbor

from . import exceptions


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
