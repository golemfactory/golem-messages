# pylint: disable=no-self-use
import unittest
import unittest.mock as mock

from golem_messages import (datastructures, exceptions)


class SetItemDictTest(unittest.TestCase):

    @mock.patch('golem_messages.datastructures.SetItemDict.__setitem__')
    def test_init_calls_setitem_on_kwargs(self, set_mock):
        datastructures.SetItemDict(a=1)
        set_mock.assert_called_once_with('a', 1)

    @mock.patch('golem_messages.datastructures.SetItemDict.__setitem__')
    def test_init_calls_setitem_on_dict(self, set_mock):
        datastructures.SetItemDict({'a': 1})
        set_mock.assert_called_once_with('a', 1)

    @mock.patch('golem_messages.datastructures.SetItemDict.__setitem__')
    def test_init_calls_setitem_on_iterable(self, set_mock):
        datastructures.SetItemDict([('a', 1)])
        set_mock.assert_called_once_with('a', 1)


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

    def test_implements_setitemdict(self):
        fd = datastructures.FrozenDict()
        self.assertIsInstance(fd, datastructures.SetItemDict)


class FrozenDictDefaultTest(unittest.TestCase):
    class TestDict(datastructures.FrozenDict):
        ANSWER = 42
        ITEMS = {
            'answer': ANSWER,
        }

    def test_default_direct(self):
        t = self.TestDict()
        self.assertEqual(t['answer'], self.TestDict.ANSWER)

    def test_default_get(self):
        t = self.TestDict()
        self.assertEqual(t.get('answer'), self.TestDict.ANSWER)

    def test_other_val(self):
        answer = 54
        t = self.TestDict({'answer': answer})
        self.assertEqual(t['answer'], answer)


class ValidatingDictTest(unittest.TestCase):
    GOODVAL = 'deadbeef'
    FAILVAL = 0xdeadbeef

    class TestDict(datastructures.ValidatingDict):
        ITEMS = {
            'stringval': '',
        }

        def validate_stringval(self, value):
            if not isinstance(value, str):
                raise exceptions.FieldError()

    def test_construct(self):
        t = self.TestDict({'stringval': self.GOODVAL})
        self.assertEqual(t['stringval'], self.GOODVAL)

    def test_set(self):
        t = self.TestDict()
        t['stringval'] = self.GOODVAL
        self.assertEqual(t['stringval'], self.GOODVAL)

    def test_construct_fail(self):
        with self.assertRaises(exceptions.FieldError):
            self.TestDict({'stringval': self.FAILVAL})

    def test_set_fail(self):
        t = self.TestDict()
        with self.assertRaises(exceptions.FieldError):
            t['stringval'] = self.FAILVAL
