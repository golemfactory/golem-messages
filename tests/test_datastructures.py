import unittest

from golem_messages import datastructures


class FrozenTestCase(unittest.TestCase):
    def test_missing(self):
        default_value = ("You may not know much about 20th-century art"
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
            fd['missing']

        self.assertEqual(fd['default'], default_value)

    def test_new_key(self):
        fd = datastructures.FrozenDict()
        with self.assertRaises(KeyError):
            fd['new_key'] = 'Mexico military crime-busters join ocean...'

    def test_set_attr(self):
        fd = datastructures.FrozenDict()
        with self.assertRaises(AttributeError):
            fd.new_attr = ('Pod moskitierą czuło się duchotę, przy oknie — '
                           'gorąc zupełnie tropikalny.'
                           )
