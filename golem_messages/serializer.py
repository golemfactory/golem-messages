import functools
import logging

import cbor

from . import exceptions


logger = logging.getLogger(__name__)


def wrap_error(wrap_with):
    def _inner(f):
        @functools.wraps(f)
        def _curry(*args, **kwargs):
            try:
                return f(*args, **kwargs)
            except Exception as e:
                logger.debug(
                    'Wrapping exception with %s. e=%r',
                    wrap_with,
                    e.__class__,
                    exc_info=True,
                )
                raise wrap_with(
                    "({} ({})".format(e.__class__.__qualname__, e),
                ) from e
        return _curry
    return _inner


# Public functions

dumps = wrap_error(exceptions.SerializationError)(cbor.dumps)
loads = wrap_error(exceptions.SerializationError)(cbor.loads)
