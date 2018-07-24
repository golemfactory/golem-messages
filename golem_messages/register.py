import logging

logger = logging.getLogger(__name__)


class MessageRegister():
    """Register of all Message "types" that can be transferred on the wire"""
    __slots__ = ('_types', '_reversed')

    def __init__(self):
        self._types = {}  # typing.Dict[int, base.Message]
        self._reversed = {}  # typing/Dict[base.Message, int]

    def register(self, type_):
        def _wrapped(message_class):
            if type_ in self._types:
                raise RuntimeError(
                    "Duplicated message {}.TYPE: {}"
                    .format(message_class.__name__, type_)
                )
            logger.debug('Register %s as %s', message_class.__qualname__, type_)
            self._types[type_] = message_class
            self._reversed[message_class] = type_
            return message_class
        return _wrapped

    def __getitem__(self, key):
        return self._types[key]

    def __contains__(self, item):
        return item in self._types

    def get_type(self, message_class):
        return self._reversed[message_class]


# The only instance of MessageHandler that should be used
library = MessageRegister()
