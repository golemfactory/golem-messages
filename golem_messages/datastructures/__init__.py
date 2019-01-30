import collections
import copy
import enum
import typing

from golem_messages import exceptions

MessageHeader = collections.namedtuple(
    "MessageHeader",
    ["type_", "timestamp", "encrypted"],
)


NestedMessage = collections.namedtuple(
    "NestedMessage",
    ["header", "sig", "slots"],
)


class SetItemDict(dict):
    """
    Mimics dict initialization but always uses __setitem__
    """

    def __init__(self, *args, **kwargs):
        super().__init__()
        if args:
            if isinstance(args[0], dict):
                for key, value in args[0].items():
                    self[key] = value
            else:
                for key, value in args[0]:
                    self[key] = value
        for key in kwargs:
            self[key] = kwargs[key]


class FrozenDict(SetItemDict):
    """
    FrozenDict allows only keys provided in ITEMS attribute.

    It also populates any missing keys with defaults from ITEMS.
    """

    ITEMS = {}

    def _set_defaults(self):
        for k, v in self.ITEMS.items():
            if k not in self:
                self[k] = copy.deepcopy(v)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._set_defaults()

    def __setitem__(self, key, value):
        if key not in self.ITEMS:
            raise KeyError("Invalid key: {}".format(key))
        return super().__setitem__(key, value)

    def __setattr__(self, key, value):
        raise AttributeError("Read only. Use mapping interface")


class ValidatingDict(SetItemDict):
    """
    Adds optional validation to the dict interface.

    To add validation to a dictionary key,
    add a `validate_<key>` method, accepting a value
    the return value is ignored and the method
    should raise `exceptions.FieldError`
    if the value doesn't pass the validation.
    """

    def __setitem__(self, key, value):
        validator = getattr(
            self, 'validate_{}'.format(key), None
        )

        if callable(validator):
            validator(value=value)  # noqa pylint:disable=not-callable

        super().__setitem__(key, value)


class StringEnum(str, enum.Enum):

    # pylint: disable=no-self-argument

    def _generate_next_value_(name: str, *_):
        return name

    # pylint: enable=no-self-argument


class Container:
    """Container implementation supporting serialization and deserialization"""
    # Values in __slots__ are iterables of validators.
    # Each validator is called with (field_name, value)
    # See: deserialize_slot()
    __slots__: typing.Dict[str, typing.Iterable[
        typing.Callable[[str, typing.Any], None]]] = {}
    # List of required slot names
    REQUIRED: typing.FrozenSet[str] = frozenset()
    # factories of default values for slots. See: load_slots
    DEFAULTS: typing.Dict[str, typing.Callable[[], typing.Any]] = {}

    def __init__(self, **kwargs):
        try:
            self.load_slots(**kwargs)
        except exceptions.FieldError:
            raise
        except Exception as e:
            raise exceptions.MessageError('Header load slots failed') from e

    def load_slots(self, **kwargs):
        for key in self.__slots__:
            try:
                value = kwargs.pop(key)
            except KeyError:
                if key in self.REQUIRED:
                    raise exceptions.FieldError(
                        'Field required',
                        field=key,
                        value=None,
                    )

                value = self.DEFAULTS.get(key, lambda: None)()
            else:
                value = self.deserialize_slot(key, value)
            setattr(self, key, value)
        for key in kwargs:
            raise exceptions.FieldError(
                '%s: Unknown slots' % type(self),
                field=key,
                value=kwargs[key],
            )

    def deserialize_slot(self, key, value):
        if value is None and (key not in self.REQUIRED):
            # Skip validation
            return value
        validators_ = self.__slots__[key]
        for validator in validators_:
            validator(
                field_name=key,
                value=value,
            )
        try:
            value = getattr(self, f'deserialize_{key}')(value)
        except AttributeError:
            pass
        return value

    def to_dict(self):
        """ Nullifies the properties not required for signature verification
        and sorts the task dict representation in order to have the same
        resulting binary blob after serialization.
        """
        dictionary = {}
        for key in self.__slots__:
            value = getattr(self, key, None)
            try:
                value = getattr(self, f'serialize_{key}')(value)
            except AttributeError:
                pass
            dictionary[key] = value
        return dictionary

    def __repr__(self):
        return '<%s: %r>' % (
            type(self).__name__, self.to_dict()
        )
