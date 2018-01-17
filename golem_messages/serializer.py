import collections
import collections.abc
import enum
import functools
import inspect
import logging
import sys
import types
import warnings

import cbor2
import cbor2.encoder
import cbor2.types
import pytz

import cbor2
import cbor2.types
import pytz

logger = logging.getLogger('golem.core.simpleserializer')


OBJECT_TAG = 239
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


def to_unicode(value):
    if value is None:
        return None
    if isinstance(value, bytes):
        try:
            return value.decode('utf-8')
        except UnicodeDecodeError:
            return value
    return str(value)


class DictCoder:
    cls_key = 'py/object'
    deep_serialization = True
    builtin_types = [i for i in types.__dict__.values() if isinstance(i, type)]

    @classmethod
    def to_dict(cls, obj, typed=True):
        return cls._to_dict_traverse_obj(obj, typed)

    @classmethod
    def from_dict(cls, dictionary, as_class=None):
        if as_class:
            dictionary = dict(dictionary)
            dictionary[cls.cls_key] = cls.module_and_class(as_class)
        return cls._from_dict_traverse_obj(dictionary)

    @classmethod
    def obj_to_dict(cls, obj, typed=True):
        """Stores object's public properties in a dictionary"""
        result = cls._to_dict_traverse_dict(obj.__dict__, typed)
        if typed:
            result[cls.cls_key] = cls.module_and_class(obj)
        return result

    @classmethod
    def obj_from_dict(cls, dictionary):
        cls_path = dictionary.pop(cls.cls_key)

        module_name, cls_name = cls_path.rsplit('.', 1)
        cls_components = [cls_name, ]
        while module_name not in sys.modules:
            module_name, parent_name = module_name.rsplit('.', 1)
            cls_components.append(parent_name)
        module = sys.modules[module_name]
        sub_cls = None
        while cls_components:
            if sub_cls is not None:
                sub_cls = getattr(sub_cls, cls_components.pop())
                continue
            sub_cls = getattr(module, cls_components.pop())

        # Special case for enum.Enum
        if isinstance(sub_cls, enum.Enum):
            obj = sub_cls
        else:
            try:
                obj = sub_cls.__new__(sub_cls)
            except Exception:
                logger.debug('Problem instantiating new %r', sub_cls,
                             exc_info=True)
                raise

        for k, v in list(dictionary.items()):
            if cls._is_class(v):
                setattr(obj, k, cls.obj_from_dict(v))
            else:
                setattr(obj, k, cls._from_dict_traverse_obj(v))
        return obj

    @classmethod
    def _to_dict_traverse_dict(cls, dictionary, typed=True):
        result = dict()
        for k, v in list(dictionary.items()):
            if (isinstance(k, str) and k.startswith('_'))\
                    or isinstance(v, collections.Callable):
                continue
            result[str(k)] = cls._to_dict_traverse_obj(v, typed)
        return result

    @classmethod
    def _to_dict_traverse_obj(cls, obj, typed=True):
        if isinstance(obj, dict):
            return cls._to_dict_traverse_dict(obj, typed)
        elif isinstance(obj, str):
            return to_unicode(obj)
        elif isinstance(obj, collections.Iterable):
            iterated_obj = [cls._to_dict_traverse_obj(o, typed) for o in obj]
            return obj.__class__(iterated_obj)
        elif cls.deep_serialization:
            if hasattr(obj, '__dict__') and not cls._is_builtin(obj):
                return cls.obj_to_dict(obj, typed)
        return obj

    @classmethod
    def _from_dict_traverse_dict(cls, dictionary):
        result = dict()
        for k, v in list(dictionary.items()):
            result[k] = cls._from_dict_traverse_obj(v)
        return result

    @classmethod
    def _from_dict_traverse_obj(cls, obj):
        if isinstance(obj, dict):
            if cls._is_class(obj):
                return cls.obj_from_dict(obj)
            return cls._from_dict_traverse_dict(obj)
        elif isinstance(obj, str):
            return to_unicode(obj)
        elif isinstance(obj, collections.Iterable):
            return obj.__class__([cls._from_dict_traverse_obj(o) for o in obj])
        return obj

    @classmethod
    def _is_class(cls, obj):
        return isinstance(obj, dict) and cls.cls_key in obj

    @classmethod
    def _is_builtin(cls, obj):
        if not type(obj) in cls.builtin_types:  # noqa This class will be refactored out in v1.6 pylint: disable=unidiomatic-typecheck
            return False
        return not isinstance(obj, types.InstanceType)

    @staticmethod
    def module_and_class(obj):
        fmt = '{}.{}'
        if inspect.isclass(obj):
            return fmt.format(obj.__module__, obj.__qualname__)
        # Special case for Enum metaclass
        if isinstance(obj, enum.Enum):
            return '.'.join((
                fmt.format(obj.__module__, obj.__class__.__qualname__),
                obj.name,
            ))
        return fmt.format(obj.__module__, obj.__class__.__qualname__)


class CBORCoder(DictCoder):
    # Leave nested and special object serialization to CBOR
    deep_serialization = False


def encode_object(encoder, value, fp):
    warnings.warn(
        "Serialization of custom objects({class_}) is deprecated"
        " and will be removed in 1.6".format(
            class_=type(value),
        ),
        DeprecationWarning
    )
    if value is None:
        return
    obj_dict = CBORCoder.obj_to_dict(value)
    encoder.encode_semantic(
        OBJECT_TAG, obj_dict, fp,
        disable_value_sharing=True
    )


def decode_object(decoder, value, fp, shareable_index=None):  # noqa pylint: disable=unused-argument
    obj = CBORCoder.obj_from_dict(value)
    return obj


ENCODERS = collections.OrderedDict((
    (dict, encode_dict),
    (collections.abc.Mapping, encode_dict),
    (('golem_messages.message', 'Message'), encode_message),
    (object, encode_object),
))

DECODERS = collections.OrderedDict((
    (MESSAGE_TAG, decode_message),
    (OBJECT_TAG, decode_object),
))

# Public functions

dumps = functools.partial(
    cbor2.dumps,
    encoders=ENCODERS,
    datetime_as_timestamp=True,
    timezone=pytz.utc,
    value_sharing=False,
)


loads = functools.partial(
    cbor2.loads,
    semantic_decoders=DECODERS,
)
