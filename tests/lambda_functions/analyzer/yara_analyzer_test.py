"""Unit tests for yara_analyzer.py. Uses fake filesystem."""
# pylint: disable=protected-access
import os
import subprocess
import unittest
from unittest import mock

from pyfakefs import fake_filesystem_unittest

from lambda_functions.analyzer import yara_analyzer
from tests.lambda_functions.analyzer import yara_mocks


@mock.patch.dict(os.environ, {'LAMBDA_TASK_ROOT': '/var/task'})
class YaraAnalyzerTest(fake_filesystem_unittest.TestCase):
    """Uses the real YARA library to parse the test rules."""

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


class YextendConversionTest(unittest.TestCase):
    """Test Yextend output conversion logic."""

    def setUp(self):
        self._converter = yara_analyzer._convert_yextend_to_yara_match

    def test_convert_no_matches(self):
        """No YaraMatch tuples are returned if there were no yextend YARA matches."""
        self.assertEqual([], self._converter({'yara_matches_found': False}))

    def test_convert_one_match(self):
        """One simple Yextend YARA match is converted into a YaraMatch tuple."""
        yextend = {
            'scan_results': [
                {
                    "child_file_name": "child/file/path.txt",
                    "parent_file_name": "archive.tar.gz",
                    "scan_type": "ScanType1",
                    "yara_matches_found": True,
                    "yara_rule_id": "Rule1"
                }
            ],
            'yara_matches_found': True
        }
        expected = [yara_analyzer.YaraMatch('Rule1', 'yextend', {'scan_type': 'ScanType1'}, set())]

        self.assertEqual(expected, yara_analyzer._convert_yextend_to_yara_match(yextend))

    def test_convert_complex_matches(self):
        """Multiple rule matches, with offsets and more rule metadata."""
        yextend = {
            'scan_results': [
                {
                    "detected offsets": ["0x30:$a", "0x59:$a", "0x12b3:$b", "0x7078:$c"],
                    "scan_type": "Scan1",
                    "yara_matches_found": True,
                    "yara_rule_id": "Rule1"
                },
                {
                    "scan_type": "Scan2",
                    "yara_matches_found": False,
                },
                {
                    "author": "Airbnb",
                    "detected offsets": ["0x0:$longer_string_name"],
                    "description": "Hello, YARA world",
                    "scan_type": "Scan3",
                    "yara_matches_found": True,
                    "yara_rule_id": "Rule3"
                }
            ],
            'yara_matches_found': True
        }
        expected = [
            yara_analyzer.YaraMatch('Rule1', 'yextend', {'scan_type': 'Scan1'}, {'$a', '$b', '$c'}),
            yara_analyzer.YaraMatch(
                'Rule3', 'yextend',
                {'author': 'Airbnb', 'description': 'Hello, YARA world', 'scan_type': 'Scan3'},
                {'$longer_string_name'}
            )
        ]

        self.assertEqual(expected, yara_analyzer._convert_yextend_to_yara_match(yextend))
