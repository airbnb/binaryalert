"""Test the correctness of the EICAR YARA rule."""
import os
import unittest

import yara

THIS_DIRECTORY = os.path.dirname(os.path.realpath(__file__))  # Directory containing this file.
EICAR_RULE_FILE = os.path.join(THIS_DIRECTORY, '..', '..', 'rules', 'public', 'eicar.yara')
EICAR_STRING = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


class EicarRuleTest(unittest.TestCase):
    """Verify that the EICAR rules file matches only the expected string."""
    def setUp(self):
        """Compile the EICAR YARA rule."""
        self.eicar_rule = yara.compile(EICAR_RULE_FILE)

    def test_match_eicar_string(self):
        """Should match the exact EICAR string."""
        self.assertEqual(1, len(self.eicar_rule.match(data=EICAR_STRING)))

    def test_match_eicar_with_trailing_spaces(self):
        """Trailing whitespace is allowed after the EICAR string."""
        self.assertEqual(1, len(self.eicar_rule.match(data='{}    \n\t'.format(EICAR_STRING))))

    def test_no_match_if_eicar_is_not_beginning(self):
        """No match if EICAR string is not the beginning of the file."""
        self.assertEqual(0, len(self.eicar_rule.match(data='other-text {}'.format(EICAR_STRING))))

    def test_no_match_if_eicar_is_not_end(self):
        """No match if non-whitespace comes after the EICAR string."""
        self.assertEqual(0, len(self.eicar_rule.match(data='{} other-text'.format(EICAR_STRING))))


if __name__ == '__main__':
    unittest.main()
