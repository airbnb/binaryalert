"""Unit tests for analyzer main.py. Mocks out filesystem and boto3 clients."""
import hashlib
import json
import os
import unittest
from unittest import mock
import urllib

import boto3
from pyfakefs import fake_filesystem_unittest

from lambda_functions.analyzer import main
from tests import boto3_mocks, yara_mocks

# Mock S3 bucket and object.
MOCK_S3_BUCKET_NAME = 'mock-bucket'
MOCK_FILE_CONTENTS = 'Hello, evil world!\n'
MOCK_FILE_METADATA = {
    'observed_path': '/path/to/mock-evil.exe',
    'reported_md5': 'REPORTED MD5'
}
MOCK_S3_OBJECT_KEY = 'space plus+file.test'

# Mimics minimal parts of S3:ObjectAdded event that triggers the lambda function.
LAMBDA_VERSION = 1
TEST_CONTEXT = boto3_mocks.MockLambdaContext(LAMBDA_VERSION)

MOCK_DYNAMO_TABLE_NAME = 'mock-dynamo-table'
HASH_KEY = 'SHA256'
RANGE_KEY = 'LambdaVersion'
MOCK_SNS_TOPIC_ARN = 's3:mock-sns-arn'
MOCK_SQS_URL = 'https://sqs.mock.url'
MOCK_SQS_RECEIPTS = ['sqs_receipt1', 'sqs_receipt2']


class MainTest(fake_filesystem_unittest.TestCase):
    """Test end-to-end functionality of the analyzer."""
    @classmethod
    def setUpClass(cls):
        """Compile test YARA rules and mock yara.load for all tests."""
        yara_mocks.enable_yara_mocks()

    def setUp(self):
        """Before each test, create the mock environment."""
        # Show all differences on assertion failures, even for large dictionaries.
        self.maxDiff = None  # pylint: disable=invalid-name

        # Set up the fake filesystem.
        self.setUpPyfakefs()
        os.mkdir('/tmp')
        os.makedirs(os.path.dirname(main.COMPILED_RULES_FILEPATH))
        yara_mocks.save_test_yara_rules(main.COMPILED_RULES_FILEPATH)

        # Mock cloudwatch client.
        self._mock_cloudwatch_client = boto3_mocks.MockCloudwatchCient()

        # Create a mock Dynamo table.
        self._mock_dynamo_client = boto3_mocks.MockDynamoDBClient(
            MOCK_DYNAMO_TABLE_NAME, HASH_KEY, RANGE_KEY)
        self._mock_dynamo_table = self._mock_dynamo_client.tables[MOCK_DYNAMO_TABLE_NAME]
        os.environ['YARA_MATCHES_DYNAMO_TABLE_NAME'] = MOCK_DYNAMO_TABLE_NAME

        # Create a mock S3 bucket and "upload" a file to it.
        self._mock_s3_client = boto3_mocks.MockS3Client(
            MOCK_S3_BUCKET_NAME, MOCK_S3_OBJECT_KEY, MOCK_FILE_CONTENTS, MOCK_FILE_METADATA)
        os.environ['S3_BUCKET_NAME'] = MOCK_S3_BUCKET_NAME

        # Create mock SNS topic.
        self._mock_sns_client = boto3_mocks.MockSNSClient()
        os.environ['YARA_ALERTS_SNS_TOPIC_ARN'] = MOCK_SNS_TOPIC_ARN

        # Create mock SQS queue.
        self._mock_sqs_client = boto3_mocks.MockSQSClient(MOCK_SQS_URL, MOCK_SQS_RECEIPTS)
        os.environ['SQS_QUEUE_URL'] = MOCK_SQS_URL

        # Enable the boto3 mocks.
        self._real_boto3_client = boto3.client
        boto3.client = mock.MagicMock(side_effect=self._boto3_client_mock)

        # Create test event.
        self._test_event = {
            'S3Objects': [urllib.parse.quote_plus(MOCK_S3_OBJECT_KEY)],
            'SQSReceipts': MOCK_SQS_RECEIPTS
        }

    def tearDown(self):
        """Restore boto3.client to its original."""
        boto3.client = self._real_boto3_client

    @classmethod
    def tearDownClass(cls):
        """Restore YARA calls to their original."""
        yara_mocks.disable_yara_mocks()

    def _boto3_client_mock(self, service_name):
        """Return one of the internal mocks for boto3.client()."""
        service_map = {
            'cloudwatch': self._mock_cloudwatch_client,
            'dynamodb': self._mock_dynamo_client,
            's3': self._mock_s3_client,
            'sns': self._mock_sns_client,
            'sqs': self._mock_sqs_client
        }
        return service_map[service_name]

    def test_new_matching_file_added(self):
        """Verify return value, Dynamo update, and SNS alert when a new file matches a YARA rule."""
        md5 = hashlib.md5(MOCK_FILE_CONTENTS.encode('utf-8')).hexdigest()
        sha = hashlib.sha256(MOCK_FILE_CONTENTS.encode('utf-8')).hexdigest()
        result = main.analyze_lambda_handler(self._test_event, TEST_CONTEXT)

        # Verify return value.
        s3_id = 'S3:{}:{}'.format(MOCK_S3_BUCKET_NAME, MOCK_S3_OBJECT_KEY)
        expected = {
            s3_id: {
                'FileInfo': {
                    'ComputedMD5': md5,
                    'ComputedSHA256': sha,
                    'ReportedMD5': MOCK_FILE_METADATA['reported_md5'],
                    'S3Location': s3_id,
                    'SamplePath': MOCK_FILE_METADATA['observed_path']
                },
                'NumMatchedRules': 2,
                'MatchedRules': {
                    'Rule1': {
                        'MatchedStrings': ['$evil_string'],
                        'Meta': {
                            'author': 'Austin Byers',
                            'description': ('A helpful description about why this rule matches '
                                            'dastardly evil files.')
                        },
                        'RuleFile': 'evil_check.yar',
                        'RuleName': 'contains_evil',
                        'RuleTags': ['mock_rule', 'has_meta']
                    },
                    'Rule2': {
                        'MatchedStrings': [],
                        'Meta': {},
                        'RuleFile': 'externals.yar',
                        'RuleName': 'extension_is_exe',
                        'RuleTags': ['mock_rule']
                    }
                }
            }
        }

        self.assertEqual(expected, result)

        # Verify that the return value can be encoded as JSON.
        json.dumps(result)

        # Verify that a new entry was made to Dynamo with all of the expected data.
        key_value_dict = self._mock_dynamo_table.items[(sha, str(LAMBDA_VERSION))].key_value_dict
        for expected in [md5, MOCK_S3_OBJECT_KEY, 'evil_check.yar:contains_evil']:
            self.assertIn(expected, str(key_value_dict.values()))

        # Verify that an alert was published to SNS.
        alert = self._mock_sns_client.topics[MOCK_SNS_TOPIC_ARN][0]['Message']
        for data in [md5, sha, 'evil_check.yar', 'externals.yar', s3_id]:
            self.assertIn(data, alert)

        # Verify that the SQS receipts were deleted.
        self.assertEqual([], self._mock_sqs_client.queues[MOCK_SQS_URL])

        # Verify that the correct metrics were published to Cloudwatch.
        expected_metrics = {
            'AnalyzedBinaries': 1, 'MatchedBinaries': 1, 'YaraRules': 3, 'LambdaVersion': 1
        }
        for metric in self._mock_cloudwatch_client.metric_data['BinaryAlert']:
            if metric['MetricName'] in expected_metrics:
                self.assertEqual(expected_metrics[metric['MetricName']], metric['Value'])

        # Verify that the downloaded file was removed from /tmp.
        self.assertEqual([], os.listdir('/tmp'))

    def test_multiple_records(self):
        """Verify that results are returned for multiple records."""
        # Add two different files to mock S3.
        self._mock_s3_client.buckets[MOCK_S3_BUCKET_NAME]['KEY2'] = ('Evilicious', {})
        self._mock_s3_client.buckets[MOCK_S3_BUCKET_NAME]['KEY3'] = ('', {'observed_path': 'win32'})
        self._test_event['S3Objects'] = ['KEY2', 'KEY3']

        # Verify return value.
        result = main.analyze_lambda_handler(self._test_event, TEST_CONTEXT)
        expected = {
            'S3:{}:KEY2'.format(MOCK_S3_BUCKET_NAME): {
                'FileInfo': {
                    'ComputedMD5': hashlib.md5('Evilicious'.encode('utf-8')).hexdigest(),
                    'ComputedSHA256': hashlib.sha256('Evilicious'.encode('utf-8')).hexdigest(),
                    'ReportedMD5': '',
                    'S3Location': 'S3:{}:KEY2'.format(MOCK_S3_BUCKET_NAME),
                    'SamplePath': ''
                },
                'NumMatchedRules': 1,
                'MatchedRules': {
                    'Rule1': {
                        'MatchedStrings': ['$evil_string'],
                        'Meta': {
                            'author': 'Austin Byers',
                            'description': ('A helpful description about why this rule matches '
                                            'dastardly evil files.')
                        },
                        'RuleFile': 'evil_check.yar',
                        'RuleName': 'contains_evil',
                        'RuleTags': ['mock_rule', 'has_meta']
                    }
                }
            },
            'S3:{}:KEY3'.format(MOCK_S3_BUCKET_NAME): {
                'FileInfo': {
                    'ComputedMD5': hashlib.md5(''.encode('utf-8')).hexdigest(),
                    'ComputedSHA256': hashlib.sha256(''.encode('utf-8')).hexdigest(),
                    'ReportedMD5': '',
                    'S3Location': 'S3:{}:KEY3'.format(MOCK_S3_BUCKET_NAME),
                    'SamplePath': 'win32'
                },
                'NumMatchedRules': 1,
                'MatchedRules': {
                    'Rule1': {
                        'MatchedStrings': [],
                        'Meta': {},
                        'RuleFile': 'externals.yar',
                        'RuleName': 'filename_contains_win32',
                        'RuleTags': ['mock_rule']
                    }
                }
            }
        }
        self.assertEqual(expected, result)

        # Verify that return value can be encoded as JSON.
        json.dumps(result)

        # Verify cloudwatch metrics.
        expected_metrics = {
            'AnalyzedBinaries': 2, 'MatchedBinaries': 2, 'YaraRules': 3, 'LambdaVersion': 1
        }
        for metric in self._mock_cloudwatch_client.metric_data['BinaryAlert']:
            if metric['MetricName'] in expected_metrics:
                self.assertEqual(expected_metrics[metric['MetricName']], metric['Value'])


if __name__ == '__main__':
    unittest.main()
