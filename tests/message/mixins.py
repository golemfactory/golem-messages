from golem_messages import message

# pylint: disable=too-few-public-methods

class RegisteredMessageTestMixin():
    MSG_CLASS = None

    def test_registered(self):
        self.assertIn(self.MSG_CLASS,
                      message.registered_message_types.values())

#pylint: enable=too-few-public-methods
