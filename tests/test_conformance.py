import golem_messages
import itertools
import pathlib
import pycodestyle
import unittest


class PEP8TestCase(unittest.TestCase):
    def test_conformance(self):
        style = pycodestyle.StyleGuide(ignore=[], max_line_length=80)
        base_path = pathlib.Path(golem_messages.__file__).parent
        tests_path = pathlib.Path(__file__).parent
        for filepath in itertools.chain(base_path.iterdir(),
                                        tests_path.iterdir()):
            if filepath.suffix != '.py':
                continue
            absolute_path = str(base_path / filepath)
            result = style.check_files([absolute_path])
            self.assertEqual(result.total_errors, 0,
                             "Found code style errors (and warnings).")
