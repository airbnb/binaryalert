"""Unit tests for yara_analyzer.py. Uses fake filesystem."""
# pylint: disable=protected-access
import json
import os
import subprocess
import unittest
from unittest import mock

from pyfakefs import fake_filesystem_unittest

from lambda_functions.analyzer import yara_analyzer
from tests.lambda_functions.analyzer import yara_mocks

_YEXTEND_NO_MATCHES = b'[{"yara_matches_found": false}]'
_YEXTEND_MATCH = [
    {
        'scan_results': [
            {
                "detected offsets": ["0x30:$a", "0x59:$a", "0x12b3:$b", "0x7078:$c", "0x9999"],
                "scan_type": "Scan1",
                "yara_matches_found": True,
                "yara_rule_id": "Rule1"
            },
            {
                "scan_type": "Scan2",
                "yara_matches_found": False,
            },
            {
                # This should be ignored
                "detected offsets": ["0x30:$abc"],
                "scan_type": "Scan1",
                "yara_matches_found": True,
                "yara_rule_id": "Anomalies present in Archive (possible Decompression Bomb)"
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
]


@mock.patch.dict(os.environ, values={'LAMBDA_TASK_ROOT': '/var/task'})
class YaraAnalyzerTest(fake_filesystem_unittest.TestCase):
    """Uses the real YARA library to parse the test rules."""

    def setUp(self):
        """For each test, build a new YaraAnalyzer."""
        self.setUpPyfakefs()
        yara_mocks.save_test_yara_rules('./all.yara.rules')
        with mock.patch.object(yara_analyzer.yara, 'load', side_effect=yara_mocks.mock_yara_load):
            self._analyzer = yara_analyzer.YaraAnalyzer('./all.yara.rules')

        # Write target file.
        # pylint: disable=no-member
        self.fs.create_file('./target.exe', contents='This is definitely not an evil file. ^_^\n')

    @staticmethod
    def _rule_id(match):
        """Convert a YARA match into a string rule ID (file_name:rule_name)."""
        return '{}:{}'.format(match.rule_namespace, match.rule_name)

    @staticmethod
    def _assert_subprocess_calls(mock_subprocess: mock.MagicMock):
        """Verify the mocked subprocess calls match expectations."""
        mock_subprocess.assert_has_calls([
            mock.call(['./upx', '-q', '-d', '/target.exe'], stderr=subprocess.STDOUT),
            mock.call(['./yextend', '-r', mock.ANY, '-t', '/target.exe', '-j'],
                      stderr=subprocess.STDOUT)
        ])

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

    @mock.patch.object(subprocess, 'check_output', return_value=_YEXTEND_NO_MATCHES)
    def test_analyze(self, mock_subprocess: mock.MagicMock):
        """Analyze returns the expected list of rule matches."""
        yara_matches = self._analyzer.analyze('/target.exe')
        self._assert_subprocess_calls(mock_subprocess)
        self.assertEqual(1, len(yara_matches))

        match = yara_matches[0]
        self.assertEqual('evil_check.yar', match.rule_namespace)
        self.assertEqual('contains_evil', match.rule_name)

    @mock.patch.object(subprocess, 'check_call', mock.MagicMock())
    @mock.patch.object(subprocess, 'check_output', return_value=_YEXTEND_NO_MATCHES)
    def test_analyze_no_matches(self, mock_subprocess: mock.MagicMock):
        """Analyze returns empty list if no matches."""
        # Setup a different YaraAnalyzer with an empty ruleset.
        yara_mocks.save_test_yara_rules('./empty.yara.rules', empty_rules_file=True)
        with mock.patch.object(yara_analyzer.yara, 'load', side_effect=yara_mocks.mock_yara_load):
            empty_analyzer = yara_analyzer.YaraAnalyzer('./empty.yara.rules')

        self.assertEqual([], empty_analyzer.analyze('/target.exe'))
        self._assert_subprocess_calls(mock_subprocess)

    @mock.patch.object(subprocess, 'check_call', mock.MagicMock())
    @mock.patch.object(subprocess, 'check_output', return_value=_YEXTEND_NO_MATCHES)
    def test_analyze_match_with_target_path(self, mock_subprocess: mock.MagicMock):
        """Match additional rules if the target path is provided."""
        matched_rule_ids = [
            self._rule_id(match) for match in self._analyzer.analyze(
                '/target.exe', original_target_path='/usr/bin/win32.exe')]
        self._assert_subprocess_calls(mock_subprocess)

        self.assertEqual(
            ['evil_check.yar:contains_evil', 'externals.yar:extension_is_exe',
             'externals.yar:filename_contains_win32'],
            list(sorted(matched_rule_ids)))

    @mock.patch.object(subprocess, 'check_call', mock.MagicMock())
    @mock.patch.object(
        subprocess, 'check_output', return_value=json.dumps(_YEXTEND_MATCH).encode('utf-8'))
    def test_analyze_with_yextend(self, mock_subprocess: mock.MagicMock):
        """Yextend match results are combined with those from yara-python."""
        yara_matches = self._analyzer.analyze('/target.exe')
        self._assert_subprocess_calls(mock_subprocess)

        expected = [
            yara_analyzer.YaraMatch(
                rule_name='contains_evil',
                rule_namespace='evil_check.yar',
                rule_metadata={
                    'author': 'Austin Byers',
                    'description': ('A helpful description about why this rule '
                                    'matches dastardly evil files.')
                },
                matched_strings={'$evil_string'},
                matched_data={'evil'}
            ),
            yara_analyzer.YaraMatch(
                rule_name='Rule1',
                rule_namespace='yextend',
                rule_metadata={'scan_type': 'Scan1'},
                matched_strings={'$a', '$b', '$c'},
                matched_data=set()
            ),
            yara_analyzer.YaraMatch(
                rule_name='Rule3',
                rule_namespace='yextend',
                rule_metadata={
                    'author': 'Airbnb',
                    'description': 'Hello, YARA world',
                    'scan_type': 'Scan3'
                },
                matched_strings={'$longer_string_name'},
                matched_data=set()
            )
        ]
        self.assertEqual(expected, yara_matches)

    @mock.patch.object(subprocess, 'check_call', mock.MagicMock())
    @mock.patch.object(subprocess, 'check_output', return_value=b'nonsense-yextend-output')
    def test_analyze_yextend_exception(self, mock_subprocess: mock.MagicMock):
        """Yextend exceptions are logged, but yara-python results are still returned."""
        with mock.patch.object(yara_analyzer, 'LOGGER') as mock_logger:
            yara_matches = self._analyzer.analyze('/target.exe')

            self._assert_subprocess_calls(mock_subprocess)

            # The yara_python match result should still have been returned.
            self.assertEqual(1, len(yara_matches))

            # The logger should have printed errors and the bad yextend output.
            mock_logger.error.assert_called_once_with(
                'Cannot parse yextend output as JSON:\n%s', 'nonsense-yextend-output')


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
        expected = [
            yara_analyzer.YaraMatch(
                rule_name='Rule1',
                rule_namespace='yextend',
                rule_metadata={'scan_type': 'ScanType1'},
                matched_strings=set(),
                matched_data=set()
            )
        ]

        self.assertEqual(expected, yara_analyzer._convert_yextend_to_yara_match(yextend))

    def test_convert_complex_matches(self):
        """Multiple rule matches, with offsets and more rule metadata."""
        yextend = _YEXTEND_MATCH[0]
        expected = [
            yara_analyzer.YaraMatch(
                rule_name='Rule1',
                rule_namespace='yextend',
                rule_metadata={'scan_type': 'Scan1'},
                matched_strings={'$a', '$b', '$c'},
                matched_data=set()
            ),
            yara_analyzer.YaraMatch(
                rule_name='Rule3',
                rule_namespace='yextend',
                rule_metadata={
                    'author': 'Airbnb',
                    'description': 'Hello, YARA world',
                    'scan_type': 'Scan3'
                },
                matched_strings={'$longer_string_name'},
                matched_data=set()
            )
        ]

        self.assertEqual(expected, yara_analyzer._convert_yextend_to_yara_match(yextend))
