"""Wrapper around YARA analysis."""
import collections
import json
import os
import subprocess
from typing import Dict, List

import yara


# YARA matches from both yara-python and yextend are stored in this generic YaraMatch tuple.
YaraMatch = collections.namedtuple(
    'YaraMatch',
    [
        'rule_name',       # str: Name of the YARA rule
        'rule_namespace',  # str: Namespace of YARA rule (original YARA filename)
        'rule_metadata',   # Dict: String metadata associated with the YARA rule
        'matched_strings'  # Set: Set of string string names matched (e.g. "{$a, $b}")
    ]
)


class YaraAnalyzer(object):
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

    def analyze(self, target_file: str, original_target_path: str = '') -> List[YaraMatch]:
        """Run YARA analysis on a file.

        Args:
            target_file: Local path to target file to be analyzed.
            original_target_path: Path where the target file was originally discovered.

        Returns:
            List of YaraMatch tuples.
        """
        os.environ['LD_LIBRARY_PATH'] = os.environ['LAMBDA_TASK_ROOT']
        yextend_output = subprocess.check_output(
            ['./yextend', '-r', self._compiled_rules_file, '-t', target_file, '-j'])
        yextend_results = json.loads(yextend_output.decode('utf-8'))
        print(yextend_results)

        # TODO: Once yextend is more robust, we may eventually not need yara-python anymore.
        raw_yara_matches = self._rules.match(
            target_file, externals=self._yara_variables(original_target_path)
        )
        return [
            YaraMatch(m.rule, m.namespace, m.meta, set(t[1] for t in m.strings))
            for m in raw_yara_matches
        ]
