"""Unit tests for analyzer_aws_lib.py. Uses mock boto3 clients."""
import unittest
from unittest import mock

import boto3

from lambda_functions.analyzer import analyzer_aws_lib, binary_info
from tests import boto3_mocks, yara_mocks

MOCK_DYNAMO_TABLE_NAME = 'mock-dynamo-table'
HASH_KEY = 'SHA256'
RANGE_KEY = 'LambdaVersion'

REAL_BOTO3_CLIENT = boto3.client


class AnalyzerAWSLibStandaloneTest(unittest.TestCase):
    """Test top-level functions in analyzer_aws_lib.py"""
    # pylint: disable=protected-access

    def test_elide_string_middle(self):
        """Check that string elision works as expected (generated string is not too long)."""
        alphabet = 'abcdefghijklmnopqrstuvwxyz'

        # String shortened.
        self.assertEqual('ab ... yz', analyzer_aws_lib._elide_string_middle(alphabet, 10))
        self.assertEqual('abcde ... vwxyz', analyzer_aws_lib._elide_string_middle(alphabet, 15))
        self.assertEqual('abcdefg ... tuvwxyz', analyzer_aws_lib._elide_string_middle(alphabet, 20))
        self.assertEqual(
            'abcdefghij ... qrstuvwxyz', analyzer_aws_lib._elide_string_middle(alphabet, 25))

        # String unchanged.
        self.assertEqual(alphabet, analyzer_aws_lib._elide_string_middle(alphabet, 26))
        self.assertEqual(alphabet, analyzer_aws_lib._elide_string_middle(alphabet, 50))


class DynamoMatchTableTest(unittest.TestCase):
    """Test DynamoMatchTable class."""
    def setUp(self):
        """Before each test, create the mock environment."""
        # Create a mock Dynamo table.
        self._mock_dynamo_client = boto3_mocks.MockDynamoDBClient(
            MOCK_DYNAMO_TABLE_NAME, HASH_KEY, RANGE_KEY)
        self._mock_dynamo_table = self._mock_dynamo_client.tables[MOCK_DYNAMO_TABLE_NAME]

        # Setup mocks.
        boto3.client = mock.MagicMock(return_value=self._mock_dynamo_client)

        self._binary = binary_info.BinaryInfo('Bucket', 'Key', None)
        self._binary.reported_md5 = 'Original_MD5'
        self._binary.observed_path = '/bin/path/run.exe'
        self._binary.yara_matches = [yara_mocks.YaraMatchMock('file.yara', 'rule_name')]
        self._binary.computed_sha = 'Computed_SHA'
        self._binary.computed_md5 = 'Computed_MD5'

        self._match_table = analyzer_aws_lib.DynamoMatchTable(MOCK_DYNAMO_TABLE_NAME)

    @classmethod
    def tearDown(cls):
        """Restore the mocked out methods to their originals for other unit tests."""
        boto3.client = REAL_BOTO3_CLIENT

    def _add_item(self, lambda_version=1, s3_objects=None):
        """Add an item to the mock Dynamo table."""
        self._mock_dynamo_table.put_item(
            {
                'SHA256': {'S': self._binary.computed_sha},
                'LambdaVersion': {'N': str(lambda_version)},
                'MatchedRules': {'SS': self._binary.matched_rule_ids},
                'S3Objects': {'SS': s3_objects or [self._binary.s3_identifier]}
            }
        )

    def test_new_sha(self):
        """A binary matches YARA rules for the first time - create DB entry and alert."""
        needs_alert = self._match_table.save_matches(self._binary, 1)

        self.assertTrue(needs_alert)
        stored_item = self._mock_dynamo_table.items[(self._binary.computed_sha, '1')]
        for expected in [self._binary.observed_path, self._binary.matched_rule_ids[0]]:
            self.assertTrue(expected in str(stored_item.key_value_dict.values()))

    def test_new_version_same_rules_same_objects(self):
        """Same results with new Lambda version - create DB entry but do not alert."""
        self._add_item()
        needs_alert = self._match_table.save_matches(self._binary, 2)

        self.assertFalse(needs_alert)
        self.assertEqual([(self._binary.computed_sha, '1'), (self._binary.computed_sha, '2')],
                         sorted(self._mock_dynamo_table.items))

    def test_new_version_multiple_objects(self):
        """Multiple S3 objects can be added without triggering an alert if seen previously."""
        self._add_item(lambda_version=1, s3_objects=['S3_1', 'S3_2', 'S3_3'])

        self._binary.s3_identifier = 'S3_1'
        self.assertFalse(self._match_table.save_matches(self._binary, 2))

        self._binary.s3_identifier = 'S3_2'
        self.assertFalse(self._match_table.save_matches(self._binary, 2))

        self._binary.s3_identifier = 'S3_3'
        self.assertFalse(self._match_table.save_matches(self._binary, 2))

    def test_new_version_new_rules_same_objects(self):
        """A previously analyzed binary matches a new YARA rule - create DB entry and alert."""
        self._add_item()
        self._binary.yara_matches.append(
            yara_mocks.YaraMatchMock('new_file.yara', 'better_rule_name'))
        needs_alert = self._match_table.save_matches(self._binary, 2)

        self.assertTrue(needs_alert)
        stored_item = self._mock_dynamo_table.items[(self._binary.computed_sha, '2')]
        self.assertTrue('new_file.yara' in str(stored_item.key_value_dict.values()))

    def test_same_version_same_rules_new_object(self):
        """The only thing that changes is a new S3 key - update DB entry and alert."""
        self._add_item()
        self._binary.s3_identifier = 'S3:{}:{}'.format(self._binary.bucket_name, 'NEW_KEY')
        needs_alert = self._match_table.save_matches(self._binary, 1)

        self.assertTrue(needs_alert)
        stored_item = self._mock_dynamo_table.items[(self._binary.computed_sha, '1')]
        for expected in ['ADD', 'NEW_KEY']:
            self.assertTrue(expected in stored_item.updates[0])

    def test_old_version(self):
        """Analyze with an older version of the Lambda function - update DB but do not alert."""
        self._add_item()
        self._binary.yara_matches.append(
            yara_mocks.YaraMatchMock('new_file.yara', 'better_rule_name'))
        needs_alert = self._match_table.save_matches(self._binary, 0)

        self.assertFalse(needs_alert)  # Don't alert even if there was a change
        self.assertEqual([(self._binary.computed_sha, '0'), (self._binary.computed_sha, '1')],
                         sorted(self._mock_dynamo_table.items))


if __name__ == '__main__':
    unittest.main()
