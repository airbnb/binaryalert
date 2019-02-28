"""Verify that the YARA rules are identified and compile correctly."""
# pylint: disable=protected-access
import os
from unittest import mock, TestCase

from pyfakefs import fake_filesystem_unittest
import yara

from rules import compile_rules


@mock.patch.object(compile_rules, 'RULES_DIR', '/rules')
class FindYaraFilesTest(fake_filesystem_unittest.TestCase):
    """Verify that we can walk the rules directory and retrieve all .yar[a] rules."""
    # pylint: disable=no-member

    def setUp(self):
        """Setup the fake filesystem."""
        self.setUpPyfakefs()

    @staticmethod
    def _sorted_find():
        """Return the sorted list of found YARA rules files."""
        return sorted(list(compile_rules._find_yara_files()))

    def test_find_yara_rules(self):
        """Make sure all .yar and .yara files are found."""
        self.fs.create_file('/rules/file1.yar')
        self.fs.create_file('/rules/file2.yara')
        self.fs.create_file('/rules/community/nested.yar')
        self.fs.create_file('/rules/a/b/c/d/e/deep_nested.yara')
        expected = ['a/b/c/d/e/deep_nested.yara', 'community/nested.yar', 'file1.yar', 'file2.yara']
        self.assertEqual(expected, self._sorted_find())

    def test_find_yara_rules_mixed_case(self):
        """Uppercase .yar or .yara extensions are allowed, but the original filename is returned."""
        self.fs.create_file('/rules/file1.YAR')
        self.fs.create_file('/rules/file2.YaRa')
        self.assertEqual(['file1.YAR', 'file2.YaRa'], self._sorted_find())

    def test_find_yara_rules_skip_other_files(self):
        """Non-YARA files are skipped during the traversal."""
        self.fs.create_file('/rules/clone_rules.py')
        self.fs.create_file('/rules/compile_rules.py')
        self.fs.create_file('/rules/eicar.yar')
        self.fs.create_file('/rules/README.md')
        self.assertEqual(['eicar.yar'], self._sorted_find())


class CompileRulesTest(TestCase):
    """Verify that all YARA rules in the repo compile successfully."""

    def tearDown(self):
        """Remove compiled rules file."""
        if os.path.isfile('compiled_yara_rules.bin'):
            os.remove('compiled_yara_rules.bin')

    def test_compilation(self):
        """Ensure all real YARA rules compile correctly."""
        compile_rules.compile_rules('compiled_yara_rules.bin')
        rules = yara.load('compiled_yara_rules.bin')
        num_rules_files = sum(1 for _ in compile_rules._find_yara_files())
        # The number of compiled YARA rules should be >= the number of YARA rule files.
        self.assertGreaterEqual(sum(1 for _ in rules), num_rules_files)
