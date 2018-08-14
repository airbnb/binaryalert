"""Redefine YARA operations to be mockable with pyfakefs."""
# Since YARA is natively compiled, it accesses the filesystem directly. In order to make pyfakefs
# work, this module redirects yara operations to use Python's file operations.
import io

import yara
REAL_YARA_LOAD = yara.load

# Sample YARA rules for testing.
EVIL_STRING_RULE = r"""
rule contains_evil : mock_rule has_meta {
    meta:
        author = "Austin Byers"
        description = "A helpful description about why this rule matches dastardly evil files."

    strings:
        $evil_string = "evil" nocase

    condition:
        $evil_string
}
"""

RULES_WITH_VARIABLES = r"""
rule extension_is_exe : mock_rule { condition: extension matches /\.exe/i }
rule filename_contains_win32 : mock_rule { condition: filename contains "win32" }
"""


class YaraRulesMock:
    """A wrapper around Yara.Rules which redirects .match() to open files with Python's open()."""

    def __init__(self, yara_rules_object):
        self._rules = yara_rules_object  # Real yara.Rules object.

    def __iter__(self):
        yield from self._rules

    def match(self, target_file, externals=None):
        """Same signature as Yara.Rules.match, but reads data from a string instead of a file."""
        with open(target_file, mode='r') as file:
            return self._rules.match(data=file.read(), externals=externals)


def mock_yara_load(rules_file: str) -> YaraRulesMock:
    """Redirect yara.load to read from Python's open()."""
    with open(rules_file, 'rb') as f:
        return YaraRulesMock(REAL_YARA_LOAD(file=f))


def save_test_yara_rules(rules_save_file: str, empty_rules_file: bool = False):
    """Save compiled test YARA rules to the filesystem, which should already be mocked.

    Args:
        rules_save_file: Path to rules save file.
        empty_rules_file: If true, writes an empty rules file.
    """
    if empty_rules_file:
        sources = {'empty.yar': ''}
    else:
        sources = {'evil_check.yar': EVIL_STRING_RULE, 'externals.yar': RULES_WITH_VARIABLES}

    # Compile YARA rules and save them as an in-memory binary string.
    rules = yara.compile(
        sources=sources,
        externals={'extension': '', 'filename': '', 'filepath': '', 'filetype': ''})
    rule_data = io.BytesIO()
    rules.save(file=rule_data)
    rule_data.seek(0)

    # Save the files to the mock filesysytem.
    with open(rules_save_file, 'wb') as file:
        file.write(rule_data.read())
