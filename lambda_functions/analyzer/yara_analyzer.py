"""Wrapper around YARA analysis."""
import collections
import json
import os
import subprocess
from typing import Any, Dict, List

import yara

from lambda_functions.analyzer.common import LOGGER


# YARA matches from both yara-python and yextend are stored in this generic YaraMatch tuple.
YaraMatch = collections.namedtuple(
    'YaraMatch',
    [
        'rule_name',        # str: Name of the YARA rule
        'rule_namespace',   # str: Namespace of YARA rule (original YARA filename)
        'rule_metadata',    # Dict: String metadata associated with the YARA rule
        'matched_strings',  # Set: Set of string string names matched (e.g. "{$a, $b}")
        'matched_data'      # Set: Matched YARA data
    ]
)

# Yextend includes rule metadata at the same level as all other match information, so we need to
# distinguish keys from yextend vs. keys from rule metadata.
_YEXTEND_RESULT_KEYS = {
    'child_file_name', 'detected offsets', 'file_name', 'file_signature_MD5', 'file_size',
    'hit_count', 'parent_file_name', 'yara_matches_found', 'yara_rule_id'
}


def _convert_yextend_to_yara_match(yextend_json: Dict[str, Any]) -> List[YaraMatch]:
    """Convert Yextend archive analysis results (JSON) into a list of YaraMatch tuples."""
    if not yextend_json.get('yara_matches_found'):
        return []

    matches = []
    for result in yextend_json['scan_results']:
        if not result['yara_matches_found']:
            continue

        rule_name = result['yara_rule_id']
        if rule_name.lower().startswith('anomalies present in archive'):
            # Yextend was unable to analyze this archive, e.g. password-protected zipfile.
            # This isn't actually a YARA match result, so we elide it.
            continue

        # Note: Yextend does not report rule namespaces nor the match data
        rule_namespace = 'yextend'
        matched_strings = set(
            x.split(':')[1] for x in result.get('detected offsets', []) if ':' in x)

        rule_metadata = {}
        for key, value in result.items():
            if key not in _YEXTEND_RESULT_KEYS:
                rule_metadata[key] = value

        matches.append(YaraMatch(rule_name, rule_namespace, rule_metadata, matched_strings, set()))

    return matches


class YaraAnalyzer:
    """Encapsulates YARA analysis and matching functions."""

    def __init__(self, compiled_rules_file: str) -> None:
        """Initialize the analyzer with a prebuilt binary YARA rules file.

        Args:
            compiled_rules_file: Path to the binary rules file.
        """
        self._rules = yara.load(compiled_rules_file)
        self._compiled_rules_file = compiled_rules_file

    @property
    def num_rules(self) -> int:
        """Count the number of YARA rules loaded in the analyzer."""
        return sum(1 for _ in self._rules)

    @staticmethod
    def _yara_variables(original_target_path: str) -> Dict[str, str]:
        """Compute external variables needed for some YARA rules.

        Args:
            original_target_path: Path where the binary was originally discovered.

        Returns:
            A map from YARA variable names to their computed values.
        """
        file_name = os.path.basename(original_target_path)
        file_suffix = file_name.split('.')[-1] if '.' in file_name else ''  # e.g. "exe" or "rar".
        return {
            'extension': '.' + file_suffix if file_suffix else '',
            'filename': file_name,
            'filepath': original_target_path,
            'filetype': file_suffix.upper()  # Used in only one rule (checking for "GIF").
        }

    def _yextend_matches(self, target_file: str) -> List[YaraMatch]:
        """Use yextend to check for YARA matches against archive contents.

        Args:
            target_file: Local path to target file to be analyzed.

        Returns:
            List of YaraMatch tuples, or an empty list if yextend didn't work correctly.
        """
        try:
            output = subprocess.check_output(
                ['./yextend', '-r', self._compiled_rules_file, '-t', target_file, '-j'],
                stderr=subprocess.STDOUT
            )
        except subprocess.CalledProcessError:
            LOGGER.exception('Yextend invocation failed')
            return []

        try:
            decoded_output = output.decode('utf-8')
        except UnicodeDecodeError:
            LOGGER.error('Yextend output could not be decoded to utf-8:\n%s', output)
            return []

        try:
            yextend_list = json.loads(decoded_output)
        except json.JSONDecodeError:
            # There may be an error message on the first line and then the JSON result.
            try:
                yextend_list = json.loads('\n'.join(decoded_output.split('\n')[1:]))
            except json.JSONDecodeError:
                # Still can't parse as JSON
                LOGGER.error('Cannot parse yextend output as JSON:\n%s', decoded_output)
                return []

        # Yextend worked!
        try:
            return _convert_yextend_to_yara_match(yextend_list[0])
        except (KeyError, IndexError):
            LOGGER.exception('Unexpected yextend output format')
            LOGGER.error('Yextend output: %s', decoded_output)
            return []

    def analyze(self, target_file: str, original_target_path: str = '') -> List[YaraMatch]:
        """Run YARA analysis on a file.

        Args:
            target_file: Local path to target file to be analyzed.
            original_target_path: Path where the target file was originally discovered.

        Returns:
            List of YaraMatch tuples.
        """
        # UPX-unpack the file if possible
        try:
            # Ignore all UPX output
            subprocess.check_output(['./upx', '-q', '-d', target_file], stderr=subprocess.STDOUT)
            LOGGER.info('Unpacked UPX-compressed file %s', target_file)
        except subprocess.CalledProcessError:
            pass  # Not a packed file

        # Raw YARA matches (yara-python)
        raw_yara_matches = self._rules.match(
            target_file, externals=self._yara_variables(original_target_path))
        yara_python_matches = []

        for match in raw_yara_matches:
            string_names = set()
            string_data = set()
            for _, name, data in match.strings:
                string_names.add(name)
                try:
                    string_data.add(data.decode('utf-8'))
                except UnicodeDecodeError:
                    # Bytes string is not unicode - print its hex values instead
                    string_data.add(data.hex())
            yara_python_matches.append(
                YaraMatch(match.rule, match.namespace, match.meta, string_names, string_data))

        return yara_python_matches + self._yextend_matches(target_file)
