from . import base


RESOURCE_MSG_BASE = 3000


class AbstractResource(base.Message):
    """
    :param str resource: resource name
    """
    __slots__ = ['resource'] + base.Message.__slots__


class PushResource(AbstractResource):
    """Message with information that expected number of copies of
       given resource should be pushed to the network
    :param int copies: number of copies
    """

    TYPE = RESOURCE_MSG_BASE + 1

    __slots__ = [
        'copies'
    ] + AbstractResource.__slots__


class HasResource(AbstractResource):
    """Create message with information about having given resource"""
    TYPE = RESOURCE_MSG_BASE + 2

    __slots__ = AbstractResource.__slots__


class WantsResource(AbstractResource):
    """Send information that node wants to receive given resource"""
    TYPE = RESOURCE_MSG_BASE + 3

    __slots__ = AbstractResource.__slots__


class PullResource(AbstractResource):
    """Create message with information that given resource is needed"""
    TYPE = RESOURCE_MSG_BASE + 4

    __slots__ = AbstractResource.__slots__


class PullAnswer(base.Message):
    """Message with information whether current peer has given
       resource and may send it
    :param str resource: resource name
    :param bool has_resource: information if user has resource
    """

    TYPE = RESOURCE_MSG_BASE + 5

    __slots__ = [
        'resource',
        'has_resource'
    ] + base.Message.__slots__


class ResourceList(base.Message):
    """Message with resource request
    :param str resources: resource list
    """

    TYPE = RESOURCE_MSG_BASE + 7

    __slots__ = [
        'resources',
        'options'
    ] + base.Message.__slots__


class ResourceHandshakeStart(base.Message):
    TYPE = RESOURCE_MSG_BASE + 8

    __slots__ = [
        'resource',
        'options'
    ] + base.Message.__slots__


class ResourceHandshakeNonce(base.Message):
    TYPE = RESOURCE_MSG_BASE + 9

    __slots__ = [
        'nonce'
    ] + base.Message.__slots__


class ResourceHandshakeVerdict(base.Message):
    TYPE = RESOURCE_MSG_BASE + 10

    __slots__ = [
        'accepted',
        'nonce'
    ] + base.Message.__slots__
