"""Unit tests for analyzer main.py. Mocks out filesystem and boto3 clients."""
import hashlib
import json
import os
import subprocess
from unittest import mock
import urllib.parse

from pyfakefs import fake_filesystem_unittest

from lambda_functions.analyzer import yara_analyzer
from lambda_functions.analyzer.common import COMPILED_RULES_FILEPATH
from tests import common
from tests.lambda_functions.analyzer import yara_mocks

# Mock S3 bucket and objects.
MOCK_S3_BUCKET_NAME = 'mock-bucket'
FILE_MODIFIED_TIME = 'test-last-modified'
GOOD_FILE_CONTENTS = 'Hello, world!\n'
GOOD_FILE_METADATA = {'filepath': 'win32'}
GOOD_S3_OBJECT_KEY = 'space plus+file.test'
EVIL_FILE_CONTENTS = 'Hello, evil world!\n'
EVIL_FILE_METADATA = {'filepath': '/path/to/mock-evil.exe'}
EVIL_S3_OBJECT_KEY = 'evil.exe'

MOCK_DYNAMO_TABLE_NAME = 'mock-dynamo-table'
MOCK_SNS_TOPIC_ARN = 's3:mock-sns-arn'
MOCK_SQS_URL = 'https://sqs.mock.url'
MOCK_SQS_RECEIPTS = ['sqs_receipt1', 'sqs_receipt2']

# Mimics minimal parts of S3:ObjectAdded event that triggers the lambda function.
LAMBDA_VERSION = 1
TEST_CONTEXT = common.MockLambdaContext(LAMBDA_VERSION)


class MockS3Object(object):
    """Simple mock for boto3.resource('s3').Object"""
    def __init__(self, bucket_name, object_key):
        self.name = bucket_name
        self.key = object_key

    def download_file(self, download_path):
        with open(download_path, 'w') as f:
            f.write(GOOD_FILE_CONTENTS if self.key == GOOD_S3_OBJECT_KEY else EVIL_FILE_CONTENTS)

    @property
    def last_modified(self):
        return FILE_MODIFIED_TIME

    @property
    def metadata(self):
        return GOOD_FILE_METADATA if self.key == GOOD_S3_OBJECT_KEY else EVIL_FILE_METADATA


@mock.patch.object(subprocess, 'check_call')
@mock.patch.object(subprocess, 'check_output', return_value=b'[{"yara_matches_found": false}]')
class MainTest(fake_filesystem_unittest.TestCase):
    """Test end-to-end functionality of the analyzer."""
    def setUp(self):
        """Before each test, create the mock environment."""
        # Show all differences on assertion failures, even for large dictionaries.
        self.maxDiff = None  # pylint: disable=invalid-name

        # Set up the fake filesystem.
        self.setUpPyfakefs()
        os.makedirs(os.path.dirname(COMPILED_RULES_FILEPATH))
        yara_mocks.save_test_yara_rules(COMPILED_RULES_FILEPATH)

        # Set environment variables.
        os.environ['LAMBDA_TASK_ROOT'] = '/var/task'
        os.environ['S3_BUCKET_NAME'] = MOCK_S3_BUCKET_NAME
        os.environ['SQS_QUEUE_URL'] = MOCK_SQS_URL
        os.environ['YARA_MATCHES_DYNAMO_TABLE_NAME'] = MOCK_DYNAMO_TABLE_NAME
        os.environ['YARA_ALERTS_SNS_TOPIC_ARN'] = MOCK_SNS_TOPIC_ARN

        # Create test event.
        self._test_event = {
            # Two objects, which match different YARA rules.
            'S3Objects': [urllib.parse.quote_plus(GOOD_S3_OBJECT_KEY), EVIL_S3_OBJECT_KEY],
            'SQSReceipts': MOCK_SQS_RECEIPTS
        }

        # Import the module under test (now that YARA is mocked out).
        with mock.patch('boto3.client'), mock.patch('boto3.resource'), \
                mock.patch.object(yara_analyzer.yara, 'load',
                                  side_effect=yara_mocks.mock_yara_load):
            from lambda_functions.analyzer import main
            self.main = main

        # Reset each boto3 resource (sometimes necessary depending on import order).
        self.main.analyzer_aws_lib.CLOUDWATCH = mock.MagicMock()
        self.main.analyzer_aws_lib.DYNAMODB = mock.MagicMock()
        self.main.analyzer_aws_lib.S3 = mock.MagicMock()
        self.main.analyzer_aws_lib.SNS = mock.MagicMock()
        self.main.analyzer_aws_lib.SQS = mock.MagicMock()

        # Mock S3 Object
        self.main.analyzer_aws_lib.S3.Object = MockS3Object

    def test_analyze_lambda_handler(self, mock_output: mock.MagicMock, mock_call: mock.MagicMock):
        """Verify return value, logging, and boto3 calls when multiple files match YARA rules."""
        with mock.patch.object(self.main, 'LOGGER') as mock_logger:
            result = self.main.analyze_lambda_handler(self._test_event, TEST_CONTEXT)
            # Verify logging statements.
            mock_logger.assert_has_calls([
                mock.call.info('Processing %d record(s)', 2),
                mock.call.info('Analyzing "%s"', GOOD_S3_OBJECT_KEY),
                mock.call.warning(
                    '%s matched YARA rules: %s',
                    mock.ANY,
                    {'externals.yar:filename_contains_win32'}
                ),
                mock.call.info('Analyzing "%s"', EVIL_S3_OBJECT_KEY),
                mock.call.warning(
                    '%s matched YARA rules: %s',
                    mock.ANY,
                    {'evil_check.yar:contains_evil', 'externals.yar:extension_is_exe'}
                )
            ])

            # Verify 2 subprocess calls (yextend over each binary)
            mock_output.assert_has_calls([
                mock.call(['./yextend', '-r', COMPILED_RULES_FILEPATH, '-t', mock.ANY, '-j']),
                mock.call(['./yextend', '-r', COMPILED_RULES_FILEPATH, '-t', mock.ANY, '-j'])
            ])

            # Verify 2 shred calls
            mock_call.assert_has_calls([
                mock.call(['shred', '--remove', mock.ANY]),
                mock.call(['shred', '--remove', mock.ANY])
            ])

        # Verify return value.
        good_s3_id = 'S3:{}:{}'.format(MOCK_S3_BUCKET_NAME, GOOD_S3_OBJECT_KEY)
        evil_s3_id = 'S3:{}:{}'.format(MOCK_S3_BUCKET_NAME, EVIL_S3_OBJECT_KEY)
        expected = {
            good_s3_id: {
                'FileInfo': {
                    'MD5': hashlib.md5(GOOD_FILE_CONTENTS.encode('utf-8')).hexdigest(),
                    'S3LastModified': FILE_MODIFIED_TIME,
                    'S3Location': good_s3_id,
                    'S3Metadata': GOOD_FILE_METADATA,
                    'SHA256': hashlib.sha256(GOOD_FILE_CONTENTS.encode('utf-8')).hexdigest()
                },
                'MatchedRules': {
                    'Rule1': {
                        'MatchedStrings': [],
                        'Meta': {},
                        'RuleFile': 'externals.yar',
                        'RuleName': 'filename_contains_win32',
                    }
                },
                'NumMatchedRules': 1
            },
            evil_s3_id: {
                'FileInfo': {
                    'MD5': hashlib.md5(EVIL_FILE_CONTENTS.encode('utf-8')).hexdigest(),
                    'S3LastModified': FILE_MODIFIED_TIME,
                    'S3Location': evil_s3_id,
                    'S3Metadata': EVIL_FILE_METADATA,
                    'SHA256': hashlib.sha256(EVIL_FILE_CONTENTS.encode('utf-8')).hexdigest()
                },
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
                    },
                    'Rule2': {
                        'MatchedStrings': [],
                        'Meta': {},
                        'RuleFile': 'externals.yar',
                        'RuleName': 'extension_is_exe',
                    }
                },
                'NumMatchedRules': 2
            }
        }

        self.assertEqual(expected, result)

        # Verify that the return value can be encoded as JSON.
        json.dumps(result)

        # Verify that the Dynamo table was created.
        self.main.analyzer_aws_lib.DYNAMODB.assert_has_calls([
            mock.call.Table(MOCK_DYNAMO_TABLE_NAME)
        ])

        # Verify an SNS message was published.
        self.main.analyzer_aws_lib.SNS.assert_has_calls([
            mock.call.Topic(MOCK_SNS_TOPIC_ARN),
            mock.call.Topic().publish(
                Message=mock.ANY,
                Subject='[BinaryAlert] win32 matches a YARA rule'
            ),
            mock.call.Topic(MOCK_SNS_TOPIC_ARN),
            mock.call.Topic().publish(
                Message=mock.ANY,
                Subject='[BinaryAlert] /path/to/mock-evil.exe matches a YARA rule'
            )
        ])

        # Verify the SQS receipts were deleted.
        self.main.analyzer_aws_lib.SQS.assert_has_calls([
            mock.call.Queue(MOCK_SQS_URL),
            mock.call.Queue().delete_messages(Entries=[
                {'Id': '0', 'ReceiptHandle': 'sqs_receipt1'},
                {'Id': '1', 'ReceiptHandle': 'sqs_receipt2'}
            ])
        ])

        # Verify the correct metrics were published to Cloudwatch.
        self.main.analyzer_aws_lib.CLOUDWATCH.assert_has_calls([
            mock.call.put_metric_data(
                MetricData=[
                    {
                        'MetricName': 'AnalyzedBinaries',
                        'Value': 2,
                        'Unit': 'Count'
                    },
                    {
                        'MetricName': 'MatchedBinaries',
                        'Value': 2,
                        'Unit': 'Count'
                    },
                    {
                        'MetricName': 'YaraRules',
                        'Value': 3,
                        'Unit': 'Count'
                    },
                    {
                        'MetricName': 'S3DownloadLatency',
                        'StatisticValues': {
                            'Minimum': mock.ANY,
                            'Maximum': mock.ANY,
                            'SampleCount': 2,
                            'Sum': mock.ANY
                        },
                        'Unit': 'Milliseconds'
                    }
                ],
                Namespace='BinaryAlert'
            )
        ])
