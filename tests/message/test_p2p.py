import unittest

from golem_messages.factories import p2p as p2p_factories
from golem_messages.message import p2p

from tests.message import mixins


class WantToStartSessionTest(mixins.RegisteredMessageTestMixin,
                             mixins.SerializationMixin,
                             unittest.TestCase):
    FACTORY = p2p_factories.WantToStartTaskSessionFactory
    MSG_CLASS = p2p.WantToStartTaskSession


class SetTaskSessionTest(mixins.RegisteredMessageTestMixin,
                         mixins.SerializationMixin,
                         unittest.TestCase):
    FACTORY = p2p_factories.SetTaskSessionFactory
    MSG_CLASS = p2p.SetTaskSession
