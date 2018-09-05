"""Unit tests for analyzer_aws_lib.py. Uses mock boto3 clients."""
# pylint: disable=protected-access
import unittest
from unittest import mock

from lambda_functions.analyzer import analyzer_aws_lib, binary_info, yara_analyzer

MOCK_DYNAMO_TABLE_NAME = 'mock-dynamo-table'
YaraMatch = yara_analyzer.YaraMatch


class AnalyzerAWSLibStandaloneTest(unittest.TestCase):
    """Test top-level functions in analyzer_aws_lib.py"""
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


@mock.patch.object(analyzer_aws_lib, 'DYNAMODB')
class DynamoMatchTableTest(unittest.TestCase):
    """Test DynamoMatchTable class."""
    def setUp(self):
        """Before each test, setup a BinaryInfo."""
        self._binary = binary_info.BinaryInfo('test-bucket', 'test-key', None)
        self._binary.s3_last_modified = 'time:right_now'
        self._binary.s3_metadata = {'test-filename': 'test.txt', 'empty-filename': ''}
        self._binary.computed_md5 = 'Computed_MD5'
        self._binary.computed_sha = 'Computed_SHA'
        self._binary.yara_matches = [YaraMatch('rule_name', 'file.yara', dict(), set(), set())]

    def test_new_sha(self, mock_table: mock.MagicMock):
        """A binary matches YARA rules for the first time - create DB entry and alert."""
        match_table = analyzer_aws_lib.DynamoMatchTable(MOCK_DYNAMO_TABLE_NAME)
        match_table._table.query = lambda **kwargs: {}

        needs_alert = match_table.save_matches(self._binary, 1)

        self.assertTrue(needs_alert)
        mock_table.assert_has_calls([
            mock.call.Table().put_item(Item={
                'SHA256': 'Computed_SHA',
                'AnalyzerVersion': 1,
                'MatchedRules': {'file.yara:rule_name'},
                'MD5': 'Computed_MD5',
                'S3LastModified': 'time:right_now',
                'S3Metadata': {'test-filename': 'test.txt', 'empty-filename': '(empty)'},
                'S3Objects': {'S3:test-bucket:test-key'}
            })
        ])

    def test_new_version_same_rules_same_objects(self, mock_table: mock.MagicMock):
        """Same results with new Lambda version - create new DB entry but do not alert."""
        match_table = analyzer_aws_lib.DynamoMatchTable(MOCK_DYNAMO_TABLE_NAME)
        match_table._table.query = lambda **kwargs: {
            'Items': [
                {
                    'AnalyzerVersion': 1,
                    'MatchedRules': {'file.yara:rule_name'},
                    'S3Objects': {'S3:test-bucket:test-key'}
                }
            ]
        }

        needs_alert = match_table.save_matches(self._binary, 2)

        self.assertFalse(needs_alert)
        mock_table.assert_has_calls([
            mock.call.Table().put_item(Item={
                'SHA256': 'Computed_SHA',
                'AnalyzerVersion': 2,
                'MatchedRules': {'file.yara:rule_name'},
                'MD5': 'Computed_MD5',
                'S3LastModified': 'time:right_now',
                'S3Metadata': {'test-filename': 'test.txt', 'empty-filename': '(empty)'},
                'S3Objects': {'S3:test-bucket:test-key'}
            })
        ])

    def test_new_version_multiple_objects(self, mock_table: mock.MagicMock):
        """No alerts should fire for any of multiple binaries which have already matched."""
        match_table = analyzer_aws_lib.DynamoMatchTable(MOCK_DYNAMO_TABLE_NAME)
        match_table._table.query = lambda **kwargs: {
            'Items': [
                {
                    'AnalyzerVersion': 1,
                    'MatchedRules': {'file.yara:rule_name'},
                    'S3Objects': {'S3_1', 'S3_2', 'S3_3'}
                }
            ]
        }

        self._binary.s3_identifier = 'S3_1'
        self.assertFalse(match_table.save_matches(self._binary, 2))

        match_table._table.query = lambda **kwargs: {
            'Items': [
                {
                    'AnalyzerVersion': 2,
                    'MatchedRules': {'file.yara:rule_name'},
                    'S3Objects': {'S3_1'}
                },
                {
                    'AnalyzerVersion': 1,
                    'MatchedRules': {'file.yara:rule_name'},
                    'S3Objects': {'S3_1', 'S3_2', 'S3_3'}
                }
            ]
        }

        self._binary.s3_identifier = 'S3_2'
        self.assertFalse(match_table.save_matches(self._binary, 2))

        self._binary.s3_identifier = 'S3_3'
        self.assertFalse(match_table.save_matches(self._binary, 2))

        mock_table.assert_has_calls([
            mock.call.Table().put_item(Item=mock.ANY),
            mock.call.Table().update_item(
                ExpressionAttributeValues={':s3_string_set': {'S3_2'}},
                Key={'SHA256': 'Computed_SHA', 'AnalyzerVersion': 2},
                UpdateExpression='ADD S3Objects :s3_string_set'
            ),
            mock.call.Table().update_item(
                ExpressionAttributeValues={':s3_string_set': {'S3_3'}},
                Key={'SHA256': 'Computed_SHA', 'AnalyzerVersion': 2},
                UpdateExpression='ADD S3Objects :s3_string_set'
            )
        ])

    def test_new_version_new_rules_same_objects(self, mock_table: mock.MagicMock):
        """A previously analyzed binary matches a new YARA rule - create DB entry and alert."""
        match_table = analyzer_aws_lib.DynamoMatchTable(MOCK_DYNAMO_TABLE_NAME)
        match_table._table.query = lambda **kwargs: {
            'Items': [
                {
                    'AnalyzerVersion': 1,
                    'MatchedRules': {'file.yara:rule_name'},
                    'S3Objects': {'S3:test-bucket:test-key'}
                }
            ]
        }
        self._binary.yara_matches.append(
            YaraMatch('different_rule_name', 'new_file.yara', dict(), set(), set()))

        needs_alert = match_table.save_matches(self._binary, 2)

        self.assertTrue(needs_alert)
        mock_table.assert_has_calls([
            mock.call.Table().put_item(Item={
                'SHA256': 'Computed_SHA',
                'AnalyzerVersion': 2,
                'MatchedRules': {'new_file.yara:different_rule_name', 'file.yara:rule_name'},
                'MD5': 'Computed_MD5',
                'S3LastModified': 'time:right_now',
                'S3Metadata': {'test-filename': 'test.txt', 'empty-filename': '(empty)'},
                'S3Objects': {'S3:test-bucket:test-key'}})
        ])

    def test_same_version_same_rules_new_object(self, mock_table: mock.MagicMock):
        """The only thing that changes is a new S3 key - update DB entry and alert."""
        match_table = analyzer_aws_lib.DynamoMatchTable(MOCK_DYNAMO_TABLE_NAME)
        match_table._table.query = lambda **kwargs: {
            'Items': [
                {
                    'AnalyzerVersion': 1,
                    'MatchedRules': {'file.yara:rule_name'},
                    'S3Objects': {'S3:test-bucket:test-key'}
                }
            ]
        }
        self._binary.s3_identifier = 'S3:{}:{}'.format(self._binary.bucket_name, 'NEW_KEY')

        needs_alert = match_table.save_matches(self._binary, 1)

        self.assertTrue(needs_alert)
        mock_table.assert_has_calls([
            mock.call.Table().update_item(
                ExpressionAttributeValues={':s3_string_set': {'S3:test-bucket:NEW_KEY'}},
                Key={'SHA256': 'Computed_SHA', 'AnalyzerVersion': 1},
                UpdateExpression='ADD S3Objects :s3_string_set'
            )
        ])

    @mock.patch.object(analyzer_aws_lib, 'LOGGER')
    def test_old_version(self, mock_logger: mock.MagicMock, mock_table: mock.MagicMock):
        """Analyze with an older version of the Lambda function - update DB but do not alert."""
        match_table = analyzer_aws_lib.DynamoMatchTable(MOCK_DYNAMO_TABLE_NAME)
        match_table._table.query = lambda **kwargs: {
            'Items': [
                {
                    'AnalyzerVersion': 1,
                    'MatchedRules': {'file.yara:rule_name'},
                    'S3Objects': {'S3:test-bucket:test-key'}
                }
            ]
        }
        self._binary.yara_matches.append(
            YaraMatch('different_rule_name', 'new_file.yara', dict(), set(), set()))
        needs_alert = match_table.save_matches(self._binary, 0)

        self.assertFalse(needs_alert)  # Don't alert even if there was a change
        mock_logger.assert_has_calls([
            mock.call.warning(
                'Current Lambda version %d is < version %d from previous analysis', 0, 1
            )
        ])
        mock_table.assert_has_calls([mock.call.Table().put_item(Item=mock.ANY)])
