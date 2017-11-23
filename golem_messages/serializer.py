import collections
import enum
import inspect
import logging
import sys
import types

logger = logging.getLogger('golem.core.simpleserializer')


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
        if not type(obj) in cls.builtin_types:
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


CODER_TAG = 0xef


def encode(encoder, value, fp):
    if value is None:
        return None
    obj_dict = CBORCoder.obj_to_dict(value)
    encoder.encode_semantic(
        CODER_TAG, obj_dict, fp,
        disable_value_sharing=True
    )


def decode(decoder, value, fp, shareable_index=None):
    obj = CBORCoder.obj_from_dict(value)
    return obj
