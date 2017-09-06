"""Wrapper around YARA analysis."""
import os
from typing import Dict, List

import yara


class YaraAnalyzer(object):
    """Encapsulates YARA analysis and matching functions."""

    def __init__(self, rules_file: str):
        """Initialize the analyzer with a prebuilt binary YARA rules file.

        Args:
            rules_file: Path to the binary rules file.
        """
        self._rules = yara.load(rules_file)

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

    def analyze(self, target_file: str, original_target_path: str = '') -> List:
        """Run YARA analysis on a file.

        Args:
            target_file: Local path to target file to be analyzed.
            original_target_path: Path where the target file was originally discovered.

        Returns:
            List of yara.Match objects.
        """
        return self._rules.match(target_file, externals=self._yara_variables(original_target_path))
