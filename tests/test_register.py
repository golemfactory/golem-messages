import unittest

from golem_messages import register

class RegisterTest(unittest.TestCase):
    def setUp(self):
        self.library = register.MessageRegister()

    def test_duplicate(self):
        self.library.register(0)(type(list))
        with self.assertRaises(RuntimeError):
            self.library.register(0)(type(dict))
