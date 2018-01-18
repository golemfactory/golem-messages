import itertools
import pathlib
import unittest

import pycodestyle

from pylint import epylint

import golem_messages


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
        options = "{tests_dir} {lib_dir} -f json".format(
            lib_dir=base_path,
            tests_dir=tests_path,
        )
        stdout_io, _ = epylint.py_run(options, return_std=True)
        stdout = stdout_io.read()
        self.assertEqual(stdout, '')
