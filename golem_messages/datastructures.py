import copy


class FrozenDict(dict):
    """FrozenDict allows only values provided in ITEMS attribute. It also acts
       as DefaultDict with values from ITEMS.
       """

    ITEMS = {}

    def __missing__(self, key):
        return copy.deepcopy(self.ITEMS[key])

    def __setitem__(self, key, value):
        if key not in self.ITEMS:
            raise KeyError("Invalid key: {}".format(key))
        return super().__setitem__(key, value)

    def __setattr__(self, key, value):
        raise AttributeError("Read only. Use mapping interface")
