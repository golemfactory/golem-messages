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
        files_to_test = []

        def inner(parent):
            for filepath in parent.iterdir():
                if filepath.is_dir():
                    inner(filepath)
                if filepath.suffix != '.py':
                    continue
                files_to_test.append(str(filepath.absolute()))
        inner(base_path)
        inner(tests_path)
        result = style.check_files(files_to_test)
        self.assertEqual(result.total_errors, 0,
                         "Found code style errors (and warnings).")

    def test_lint(self):
        base_path = pathlib.Path(golem_messages.__file__).parent
        tests_path = pathlib.Path(__file__).parent
        options = "{tests_dir} {lib_dir} -f json".format(
            lib_dir=base_path.as_posix(),
            tests_dir=tests_path.as_posix(),
        )
        stdout_io, _ = epylint.py_run(options, return_std=True)
        stdout = stdout_io.read()
        self.assertEqual(stdout, '')
