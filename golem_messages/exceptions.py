class MessageError(RuntimeError):
    pass


class HeaderError(MessageError):
    pass


class TimestampError(MessageError):
    pass


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
