class MessageError(RuntimeError):
    pass


class TimestampError(MessageError):
    pass


class MessageTooOldError(TimestampError):
    pass


class MessageFromFutureError(TimestampError):
    pass


class CryptoError(MessageError):
    pass


class InvalidSignature(CryptoError):
    pass


class InvalidKeys(CryptoError):
    pass


class DecryptionError(CryptoError):
    pass
