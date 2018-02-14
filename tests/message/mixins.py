import golem_messages
from golem_messages import message

# pylint: disable=too-few-public-methods


class RegisteredMessageTestMixin():
    MSG_CLASS = None

    def test_registered(self):
        self.assertIn(self.MSG_CLASS,
                      message.registered_message_types.values())

# pylint: enable=too-few-public-methods


class SerializationMixin():
    def get_instance(self):
        return self.FACTORY()

    def test_serialization(self):
        msg = self.get_instance()
        s_msg = golem_messages.dump(msg, None, None)
        msg2 = golem_messages.load(s_msg, None, None)
        self.assertEqual(msg, msg2)
