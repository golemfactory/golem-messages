class MessageError(RuntimeError):
    pass


class HeaderError(MessageError):
    pass


class TimestampError(HeaderError):
    pass


class FieldError(MessageError):
    """Field validation failed"""

    def __init__(self, *args, **kwargs):
        self.field = kwargs.pop('field', '<unknown>')
        self.value = kwargs.pop('value', '<unknown>')
        super().__init__(*args)

    def __str__(self):
        return "{parent} [{field}:{value}]".format(
            parent=super().__str__(),
            field=self.field,
            value=repr(self.value),
        )


class MessageTooOldError(TimestampError):
    pass


class MessageFromFutureError(TimestampError):
    pass


class CryptoError(MessageError):
    pass


class CoincurveError(CryptoError):
    pass


class InvalidSignature(CryptoError):
    pass


class InvalidKeys(CryptoError):
    pass


class DecryptionError(CryptoError):
    pass


class SerializationError(MessageError):
    pass
