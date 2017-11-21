"""Tests for rule update/clone logic."""
# pylint: disable=protected-access
import os
import tempfile
from typing import List
from unittest import mock

from pyfakefs import fake_filesystem_unittest

from rules import compile_rules, clone_rules


class UpdateRulesTest(fake_filesystem_unittest.TestCase):
    """Tests for the rule-cloning logic."""
    def setUp(self):
        """Setup the fake filesystem with the expected rules folder structure."""
        self.setUpPyfakefs()
        os.makedirs(clone_rules.RULES_DIR)

        # Add extra rules (which should be deleted).
        self.fs.CreateFile(os.path.join(
            clone_rules.RULES_DIR,
            'github.com', 'YARA-Rules', 'rules.git', 'CVE_Rules', 'delete-me.yara'
        ))

        # Add some other rules (which should be preserved).
        self.fs.CreateFile(os.path.join(clone_rules.RULES_DIR, 'private', 'private.yara'))

    def _mock_git_clone(self, args: List[str]) -> None:
        """Mock out git clone by creating the "cloned" directory."""
        cloned_repo_root = args[-1]

        # Create "cloned" directory and subfolders.
        if cloned_repo_root.endswith('signature-base.git'):
            self.fs.CreateFile(os.path.join(cloned_repo_root, 'yara', 'cloned.yara'))
        else:
            self.fs.CreateFile(os.path.join(cloned_repo_root, 'CVE_Rules', 'cloned.yara'))

    @mock.patch.object(clone_rules, 'print')
    def test_update_rules(self, mock_print: mock.MagicMock):
        """Verify which rules files were saved and deleted."""
        with mock.patch('subprocess.check_call', side_effect=self._mock_git_clone):
            clone_rules.clone_rules_from_github()

        # There should be one print statement for each repo.
        mock_print.assert_has_calls([mock.ANY] * len(clone_rules.REMOTE_RULE_SOURCES))

        expected_files = {
            'github.com/Neo23x0/signature-base.git/yara/cloned.yara',
            'github.com/YARA-Rules/rules.git/CVE_Rules/cloned.yara',
            'private/private.yara'
        }
        self.assertEqual(expected_files, set(compile_rules._find_yara_files()))
