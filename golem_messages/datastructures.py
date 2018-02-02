import collections
import copy


MessageHeader = collections.namedtuple(
    "MessageHeader",
    ["type_", "timestamp", "encrypted"],
)


class FrozenDict(dict):
    """FrozenDict allows only keys provided in ITEMS attribute. It also acts
       as DefaultDict with values from ITEMS.
       """

    ITEMS = {}

    def __init__(self, *args, **kwargs):
        "Mimic dict __init__ but always use __setitem__"
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

    def __missing__(self, key):
        return copy.deepcopy(self.ITEMS[key])

    def __setitem__(self, key, value):
        if key not in self.ITEMS:
            raise KeyError("Invalid key: {}".format(key))
        return super().__setitem__(key, value)

    def __setattr__(self, key, value):
        raise AttributeError("Read only. Use mapping interface")
