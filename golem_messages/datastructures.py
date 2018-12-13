import collections
import copy
import enum

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
                for key in args[0]:
                    self[key] = args[0][key]
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
