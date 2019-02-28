"""Tests for rule update/clone logic."""
# pylint: disable=protected-access
import json
import os
from typing import List
import unittest
from unittest import mock

from pyfakefs import fake_filesystem_unittest

from rules import compile_rules, clone_rules


class CopyRequiredTest(unittest.TestCase):
    """Test the _copy_required private method."""

    def test_copy_required_no_lists(self):
        """If neither an exclude nor an include list is specified, YARA files should be copied."""
        self.assertTrue(clone_rules._copy_required('path/to/file.yar', None, None))
        self.assertTrue(clone_rules._copy_required('path/fo/file.YARA', [], []))
        self.assertFalse(clone_rules._copy_required('.git/HEAD', None, None))
        self.assertFalse(clone_rules._copy_required('path/to/file.txt', None, None))

    def test_copy_required_include_list(self):
        """Only files matching the include list should be copied."""
        include_list = ['path/to/*', '[abc]?/*/file*']

        self.assertTrue(clone_rules._copy_required('path/to/rules.yara', include_list, []))
        self.assertTrue(clone_rules._copy_required(
            'a1/some/long/path/file_apt.yara', include_list, []))
        self.assertTrue(clone_rules._copy_required('b2/malware/file ROOTKIT.YAR', include_list, []))

        self.assertFalse(clone_rules._copy_required('base.yara', include_list, []))
        self.assertFalse(clone_rules._copy_required('path/to/file.txt', include_list, []))
        self.assertFalse(clone_rules._copy_required('a1/file.yara', include_list, []))

    def test_copy_required_exclude_list(self):
        """Skip any file matching the exclude list."""
        exclude_list = ['*.yar', 'skip/these/file*']
        self.assertTrue(clone_rules._copy_required('base.yara', [], exclude_list))
        self.assertTrue(clone_rules._copy_required('path/to/file.yara', [], exclude_list))
        self.assertFalse(clone_rules._copy_required('file.yar', [], exclude_list))
        self.assertFalse(clone_rules._copy_required('skip/these/file.yara', [], exclude_list))

    def test_copy_required_include_and_exclude(self):
        """Test copy required with both an include and exclude list specified."""
        include = ['yara/*', '*_malware_*']
        exclude = ['*mobile*', 'yara/?.yara']

        self.assertTrue(clone_rules._copy_required('yara/packed.yara', include, exclude))
        self.assertTrue(clone_rules._copy_required('base_malware_index.yara', include, exclude))
        self.assertTrue(clone_rules._copy_required('yara/mac_malware.yar', include, exclude))

        self.assertFalse(clone_rules._copy_required('not_included.yara', include, exclude))
        self.assertFalse(clone_rules._copy_required('yara/mobile_malware.yara', include, exclude))
        self.assertFalse(clone_rules._copy_required('yara/A.yara', include, exclude))


class CloneRulesTest(fake_filesystem_unittest.TestCase):
    """Tests for the rule-cloning logic."""
    # pylint: disable=no-member

    def setUp(self):
        """Setup the fake filesystem with the expected rules folder structure."""
        self.setUpPyfakefs()
        os.makedirs(clone_rules.RULES_DIR)

        # Add fake rule sources.
        self.fs.create_file(clone_rules.REMOTE_RULE_SOURCES, contents=json.dumps(
            {
                "repos": [
                    {
                        "url": "https://github.com/test-user1/test-repo1",
                        "include": ["yara/*"]
                    },
                    {
                        "url": "https://github.com/test-user2/test-repo2",
                        "exclude": ["windows/*", "*_mobile.yara"]
                    },
                    {
                        "url": "git@github.com:test-user3/test-repo3",

                    }
                ]
            }
        ))

        # Add extra rules (which should be deleted).
        self.fs.create_file(os.path.join(
            clone_rules.RULES_DIR,
            'github.com', 'test-user1', 'test-repo1', 'CVE_Rules', 'delete-me.yara'
        ))

        # Add some other rules (which should be preserved).
        self.fs.create_file(os.path.join(clone_rules.RULES_DIR, 'private', 'private.yara'))

    def _mock_git_clone(self, args: List[str]) -> None:
        """Mock out git clone by creating the "cloned" directory."""
        cloned_repo_root = args[-1]

        # Create "cloned" directory and subfolders.
        if cloned_repo_root.endswith('test-repo1'):
            self.fs.create_file(os.path.join(cloned_repo_root, 'yara', 'cloned.yara'))
            self.fs.create_file(os.path.join(cloned_repo_root, 'not_included.yara'))
        elif cloned_repo_root.endswith('test-repo2'):
            self.fs.create_file(os.path.join(cloned_repo_root, 'yara', 'cloned.yara'))
            self.fs.create_file(os.path.join(cloned_repo_root, 'yara', 'exluded_mobile.yara'))
            self.fs.create_file(os.path.join(cloned_repo_root, 'windows', 'excluded.yara'))
        elif cloned_repo_root.endswith('test-repo3'):
            self.fs.create_file(os.path.join(cloned_repo_root, 'yara', 'cloned.yara'))

    @mock.patch.object(clone_rules, 'print')
    def test_clone_remote_rules(self, mock_print: mock.MagicMock):
        """Mock out the clone process and verify which rules files were saved/deleted."""
        with mock.patch('subprocess.check_call', side_effect=self._mock_git_clone):
            clone_rules.clone_remote_rules()

        mock_print.assert_has_calls([
            mock.call('[1/3] Cloning https://github.com/test-user1/test-repo1... ',
                      end='', flush=True),
            mock.call('1 YARA file copied'),
            mock.call('[2/3] Cloning https://github.com/test-user2/test-repo2... ',
                      end='', flush=True),
            mock.call('1 YARA file copied'),
            mock.call('[3/3] Cloning git@github.com:test-user3/test-repo3... ',
                      end='', flush=True),
            mock.call('1 YARA file copied'),
            mock.call('Done! 3 YARA files cloned from 3 repositories.')
        ])

        expected_files = {
            'github.com/test-user1/test-repo1/yara/cloned.yara',
            'github.com/test-user2/test-repo2/yara/cloned.yara',
            'github.com/test-user3/test-repo3/yara/cloned.yara',
            'private/private.yara'
        }
        self.assertEqual(expected_files, set(compile_rules._find_yara_files()))
