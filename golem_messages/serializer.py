import collections
import collections.abc
import functools
import logging

import cbor2
import cbor2.encoder
import cbor2.types
import pytz

from . import exceptions


logger = logging.getLogger('golem.core.simpleserializer')


OBJECT_TAG = 239  # unused, old protocol
MESSAGE_TAG = 1000


def encode_message(encoder, value, fp):
    serialized_msg = value.serialize()
    encoder.encode(cbor2.types.CBORTag(MESSAGE_TAG, serialized_msg), fp)


def decode_message(decoder, value, fp, shareable_index):  # noqa pylint: disable=unused-argument
    from golem_messages.message import base  # pylint: disable=cyclic-import
    return base.Message.deserialize(
        value,
        decrypt_func=None,
        check_time=False
    )


def encode_dict(encoder, value, fp):
    """Modified cbor2.CBOREncoder.encode_map that encodes dicts sorted by keys

       This is needed for correct signing and verification."""

    fp.write(cbor2.encoder.encode_length(0xa0, len(value)))
    for key in sorted(value):
        encoder.encode(key, fp)
        encoder.encode(value[key], fp)


ENCODERS = collections.OrderedDict((
    (dict, encode_dict),
    (collections.abc.Mapping, encode_dict),
    (('golem_messages.message', 'Message'), encode_message),
))

DECODERS = collections.OrderedDict((
    (MESSAGE_TAG, decode_message),
))


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

dumps = wrap_error(exceptions.SerializationError)(functools.partial(
    cbor2.dumps,
    encoders=ENCODERS,
    datetime_as_timestamp=True,
    timezone=pytz.utc,
    value_sharing=False,
))


loads = wrap_error(exceptions.SerializationError)(functools.partial(
    cbor2.loads,
    semantic_decoders=DECODERS,
))
