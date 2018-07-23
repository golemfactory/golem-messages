from golem_messages.register import library
from . import base


RESOURCE_MSG_BASE = 3000


class AbstractResource(base.Message):
    """
    :param str resource: resource name
    """
    __slots__ = ['resource'] + base.Message.__slots__


@library.register(RESOURCE_MSG_BASE + 1)
class PushResource(AbstractResource):
    """Message with information that expected number of copies of
       given resource should be pushed to the network
    :param int copies: number of copies
    """
    __slots__ = [
        'copies'
    ] + AbstractResource.__slots__


@library.register(RESOURCE_MSG_BASE + 2)
class HasResource(AbstractResource):
    """Create message with information about having given resource"""
    __slots__ = AbstractResource.__slots__


@library.register(RESOURCE_MSG_BASE + 3)
class WantsResource(AbstractResource):
    """Send information that node wants to receive given resource"""
    __slots__ = AbstractResource.__slots__


@library.register(RESOURCE_MSG_BASE + 4)
class PullResource(AbstractResource):
    """Create message with information that given resource is needed"""
    __slots__ = AbstractResource.__slots__


@library.register(RESOURCE_MSG_BASE + 5)
class PullAnswer(base.Message):
    """Message with information whether current peer has given
       resource and may send it
    :param str resource: resource name
    :param bool has_resource: information if user has resource
    """
    __slots__ = [
        'resource',
        'has_resource'
    ] + base.Message.__slots__


@library.register(RESOURCE_MSG_BASE + 7)
class ResourceList(base.Message):
    """Message with resource request
    :param str resources: resource list
    """
    __slots__ = [
        'resources',
        'options'
    ] + base.Message.__slots__


@library.register(RESOURCE_MSG_BASE + 8)
class ResourceHandshakeStart(base.Message):
    __slots__ = [
        'resource',
        'options'
    ] + base.Message.__slots__


@library.register(RESOURCE_MSG_BASE + 9)
class ResourceHandshakeNonce(base.Message):
    __slots__ = [
        'nonce'
    ] + base.Message.__slots__


@library.register(RESOURCE_MSG_BASE + 10)
class ResourceHandshakeVerdict(base.Message):
    __slots__ = [
        'accepted',
        'nonce'
    ] + base.Message.__slots__
