"""Unit tests for yara_analyzer.py. Uses fake filesystem."""
import os
import subprocess
from unittest import mock

from pyfakefs import fake_filesystem_unittest

from lambda_functions.analyzer import yara_analyzer
from tests.lambda_functions.analyzer import yara_mocks


@mock.patch.dict(os.environ, {'LAMBDA_TASK_ROOT': '/var/task'})
class YaraAnalyzerTest(fake_filesystem_unittest.TestCase):
    """Uses the real YARA library to parse the test rules."""
    # pylint: disable=protected-access

    def setUp(self):
        """For each test, build a new YaraAnalyzer."""
        self.setUpPyfakefs()
        yara_mocks.save_test_yara_rules('./all.yara.rules')
        with mock.patch.object(yara_analyzer.yara, 'load', side_effect=yara_mocks.mock_yara_load):
            self._analyzer = yara_analyzer.YaraAnalyzer('./all.yara.rules')

        # Write target file.
        self.fs.CreateFile('./target.exe', contents='This is definitely not an evil file. ^_^\n')

    @staticmethod
    def _rule_id(match):
        """Convert a YARA match into a string rule ID (file_name:rule_name)."""
        return '{}:{}'.format(match.rule_namespace, match.rule_name)

    def test_yara_variables(self):
        """Verify path variables are extracted correctly."""
        variables = self._analyzer._yara_variables('/path/to/file.exe')
        self.assertEqual(
            {'extension': '.exe',
             'filename': 'file.exe',
             'filepath': '/path/to/file.exe',
             'filetype': 'EXE'},
            variables)

    def test_yara_variables_no_file_extension(self):
        """Verify path variables extracted correcty if file has no extension."""
        variables = yara_analyzer.YaraAnalyzer._yara_variables('/path/to/file')
        self.assertEqual(
            {'extension': '', 'filename': 'file', 'filepath': '/path/to/file', 'filetype': ''},
            variables)

    def test_yara_variables_no_file_path(self):
        """All variables should be empty strings if no path is specified."""
        variables = yara_analyzer.YaraAnalyzer._yara_variables('')
        self.assertEqual(
            {'extension': '', 'filename': '', 'filepath': '', 'filetype': ''}, variables)

    @mock.patch.object(subprocess, 'check_output', return_value=b'[{"yara_matches_found": false}]')
    def test_analyze(self, mock_subprocess: mock.MagicMock):
        """Analyze returns the expected list of rule matches."""
        yara_matches = self._analyzer.analyze('/target.exe')
        mock_subprocess.assert_called_once()
        self.assertIsInstance(yara_matches, list)

        match = yara_matches[0]
        self.assertEqual('evil_check.yar', match.rule_namespace)
        self.assertEqual('contains_evil', match.rule_name)

    @mock.patch.object(subprocess, 'check_output', return_value=b'[{"yara_matches_found": false}]')
    def test_analyze_no_matches(self, mock_subprocess: mock.MagicMock):
        """Analyze returns empty list if no matches."""
        # Setup a different YaraAnalyzer with an empty ruleset.
        yara_mocks.save_test_yara_rules('./empty.yara.rules', empty_rules_file=True)
        with mock.patch.object(yara_analyzer.yara, 'load', side_effect=yara_mocks.mock_yara_load):
            empty_analyzer = yara_analyzer.YaraAnalyzer('./empty.yara.rules')

        self.assertEqual([], empty_analyzer.analyze('/target.exe'))
        mock_subprocess.assert_called_once()

    @mock.patch.object(subprocess, 'check_output', return_value=b'[{"yara_matches_found": false}]')
    def test_analyze_match_with_target_path(self, mock_subprocess: mock.MagicMock):
        """Match additional rules if the target path is provided."""
        matched_rule_ids = [
            self._rule_id(match) for match in self._analyzer.analyze(
                '/target.exe', original_target_path='/usr/bin/win32.exe')]
        mock_subprocess.assert_called_once()

        self.assertEqual(
            ['evil_check.yar:contains_evil', 'externals.yar:extension_is_exe',
             'externals.yar:filename_contains_win32'],
            list(sorted(matched_rule_ids)))
