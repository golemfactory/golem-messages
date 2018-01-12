import golem_messages
import itertools
import pathlib
import pycodestyle
from pylint import epylint
import unittest


class PEP8TestCase(unittest.TestCase):
    maxDiff = None

    def test_codestyle(self):
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

    def test_lint(self):
        base_path = pathlib.Path(golem_messages.__file__).parent
        tests_path = pathlib.Path(__file__).parent
        options = "{tests_dir} {lib_dir} -f parseable".format(
            lib_dir=base_path,
            tests_dir=tests_path,
        )
        stdout_io, stderr_io = epylint.py_run(options, return_std=True)
        stdout = stdout_io.read()
        stderr = stderr_io.read()
        self.assertEqual(stdout, '')
        self.assertEqual(stderr, '')
