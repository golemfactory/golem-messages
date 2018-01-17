import unittest

from golem_messages import datastructures


class FrozenTestCase(unittest.TestCase):
    def test_missing(self):
        default_value = (
            "You may not know much about 20th-century art"
            "manifestos, but you'll know what you like with"
            "Cate Blanchett's stunning turn as 13 wildly"
            "diverse characters who explore them in Manifesto."
        )

        class TestDict(datastructures.FrozenDict):
            ITEMS = {
                'default': default_value,
            }

        fd = TestDict()
        with self.assertRaises(KeyError):
            fd['missing']  # pylint: disable=pointless-statement

        self.assertEqual(fd['default'], default_value)

    def test_aliasing(self):
        """Aliasing of objects in python is a dangerous pitfall. (SEE aliasing
           in python). There is a countermeasure in __missing__(). Lets
           test it.
        """

        class TestDict(datastructures.FrozenDict):
            ITEMS = {
                'dict': {},
            }

        fd = TestDict()
        fd['dict']['watch out'] = 'for aliasing'
        fd2 = TestDict()
        self.assertEqual(fd2['dict'], {})

    def test_new_key(self):
        fd = datastructures.FrozenDict()
        with self.assertRaises(KeyError):
            fd['new_key'] = 'Mexico military crime-busters join ocean...'

    def test_set_attr(self):
        fd = datastructures.FrozenDict()
        with self.assertRaises(AttributeError):
            fd.new_attr = (
                'Pod moskitierą czuło się duchotę, przy oknie — '
                'gorąc zupełnie tropikalny.'
            )
