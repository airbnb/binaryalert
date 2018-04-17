"""Test the correctness of the EICAR YARA rule."""
import os
import unittest

import yara

THIS_DIRECTORY = os.path.dirname(os.path.realpath(__file__))  # Directory containing this file.
EICAR_RULE_FILE = os.path.join(THIS_DIRECTORY, '..', '..', 'rules', 'public', 'eicar.yara')
EICAR_TXT_FILE = os.path.join(THIS_DIRECTORY, '..', 'files', 'eicar.txt')


class EicarRuleTest(unittest.TestCase):
    """Verify that the EICAR rules file matches only the expected string."""
    def setUp(self):
        """Compile the EICAR YARA rule."""
        with open(EICAR_TXT_FILE, 'r') as f:
            self.eicar_string = f.read()
        self.eicar_rule = yara.compile(EICAR_RULE_FILE)

    def test_match_eicar_string(self):
        """Should match the exact EICAR string."""
        matches = self.eicar_rule.match(data=self.eicar_string)
        self.assertEqual(
            ['eicar_av_test', 'eicar_substring_test'],
            [match.rule for match in matches]
        )

    def test_match_eicar_with_trailing_spaces(self):
        """Trailing whitespace is allowed after the EICAR string."""
        matches = self.eicar_rule.match(data='{}    \n\t'.format(self.eicar_string))
        self.assertEqual(
            ['eicar_av_test', 'eicar_substring_test'],
            [match.rule for match in matches]
        )

    def test_no_match_if_eicar_is_not_beginning(self):
        """No match for eicar_av_test if EICAR string is not the beginning of the file."""
        matches = self.eicar_rule.match(data='other-text {}'.format(self.eicar_string))
        self.assertEqual(
            ['eicar_substring_test'],
            [match.rule for match in matches]
        )

    def test_no_match_if_eicar_is_not_end(self):
        """No match for eicar_av_test if non-whitespace comes after the EICAR string."""
        matches = self.eicar_rule.match(data='{} other-text'.format(self.eicar_string))
        self.assertEqual(
            ['eicar_substring_test'],
            [match.rule for match in matches]
        )
