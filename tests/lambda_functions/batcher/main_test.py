"""Unit tests for batcher main.py. Mocks out boto3 clients."""
# pylint: disable=protected-access
import json
import os
import unittest
from unittest import mock

import boto3

from tests import common


# TODO: mock.patch
class MainTest(unittest.TestCase):
    """Test the batcher enqueuing everything from S3 into SQS."""

    def setUp(self):
        """Set environment variables and setup the mocks."""
        os.environ['BATCH_LAMBDA_NAME'] = 'test_batch_lambda_name'
        os.environ['BATCH_LAMBDA_QUALIFIER'] = 'Production'
        os.environ['OBJECTS_PER_MESSAGE'] = '2'
        os.environ['S3_BUCKET_NAME'] = 'test_s3_bucket'
        os.environ['SQS_QUEUE_URL'] = 'test_queue'

        with mock.patch.object(boto3, 'client'), mock.patch.object(boto3, 'resource'):
            from lambda_functions.batcher import main
            self.batcher_main = main

    def test_batcher_empty_bucket(self):
        """Batcher does nothing for an empty bucket."""
        self.batcher_main.S3.list_objects_v2 = lambda **kwargs: {}

        with mock.patch.object(self.batcher_main, 'LOGGER') as mock_logger:
            num_keys = self.batcher_main.batch_lambda_handler({}, common.MockLambdaContext())
            self.assertEqual(0, num_keys)

            mock_logger.assert_has_calls([
                mock.call.info('Invoked with event %s', {}),
                mock.call.info('The S3 bucket is empty; nothing to do')
            ])

    def test_batcher_one_object(self):
        """Batcher enqueues a single S3 object."""
        self.batcher_main.S3.list_objects_v2 = lambda **kwargs: {
            'Contents': [
                {'Key': 'test-key-1'}
            ],
            'IsTruncated': False
        }

        with mock.patch.object(self.batcher_main, 'LOGGER') as mock_logger:
            num_keys = self.batcher_main.batch_lambda_handler({}, common.MockLambdaContext())
            self.assertEqual(1, num_keys)

            mock_logger.assert_has_calls([
                mock.call.info('Invoked with event %s', {}),
                mock.call.info('Finalize: sending last batch of keys'),
                mock.call.info('Sending SQS batch of %d keys: %s ... %s',
                               1, 'test-key-1', 'test-key-1')
            ])

        self.batcher_main.SQS.assert_has_calls([
            mock.call.Queue('test_queue'),
            mock.call.Queue().send_messages(Entries=[
                {
                    'Id': '0',
                    'MessageBody': json.dumps({
                        'Records': [
                            {
                                's3': {
                                    'bucket': {'name': 'test_s3_bucket'},
                                    'object': {'key': 'test-key-1'}
                                }
                            }
                        ]
                    })
                }
            ])
        ])

        self.batcher_main.CLOUDWATCH.assert_not_called()  # No error metrics to report.
        self.batcher_main.LAMBDA.assert_not_called()  # Second batcher invocation not necessary.

    def test_batcher_one_full_batch(self):
        """Batcher enqueues the configured maximum number of objects in a single SQS message."""
        self.batcher_main.S3.list_objects_v2 = lambda **kwargs: {
            'Contents': [
                {'Key': 'test-key-1'},
                {'Key': 'test-key-2'}
            ],
            'IsTruncated': False
        }

        with mock.patch.object(self.batcher_main, 'LOGGER') as mock_logger:
            num_keys = self.batcher_main.batch_lambda_handler({}, common.MockLambdaContext())
            self.assertEqual(2, num_keys)

            mock_logger.assert_has_calls([
                mock.call.info('Invoked with event %s', {}),
                mock.call.info('Finalize: sending last batch of keys'),
                mock.call.info('Sending SQS batch of %d keys: %s ... %s',
                               2, 'test-key-1', 'test-key-2')
            ])

        self.batcher_main.SQS.assert_has_calls([
            mock.call.Queue('test_queue'),
            mock.call.Queue().send_messages(Entries=[
                {
                    'Id': '0',
                    'MessageBody': json.dumps({
                        'Records': [
                            {
                                's3': {
                                    'bucket': {'name': 'test_s3_bucket'},
                                    'object': {'key': 'test-key-1'}
                                }
                            },
                            {
                                's3': {
                                    'bucket': {'name': 'test_s3_bucket'},
                                    'object': {'key': 'test-key-2'}
                                }
                            }
                        ]
                    })
                }
            ])
        ])

        self.batcher_main.CLOUDWATCH.assert_not_called()
        self.batcher_main.LAMBDA.assert_not_called()

    def test_batcher_multiple_messages(self):
        """Batcher enqueues 2 SQS messages."""
        def mock_list(**kwargs):
            """Mock for S3.list_objects_v2 which includes multiple pages of results."""
            if 'ContinuationToken' in kwargs:
                return {
                    'Contents': [
                        {'Key': 'test-key-3'}
                    ],
                    'IsTruncated': False
                }
            return {
                'Contents': [
                    {'Key': 'test-key-1'},
                    {'Key': 'test-key-2'}
                ],
                'IsTruncated': True,
                'NextContinuationToken': 'test-continuation-token'
            }

        self.batcher_main.S3.list_objects_v2 = mock_list

        with mock.patch.object(self.batcher_main, 'LOGGER') as mock_logger:
            num_keys = self.batcher_main.batch_lambda_handler({}, common.MockLambdaContext())
            self.assertEqual(3, num_keys)

            mock_logger.assert_has_calls([
                mock.call.info('Invoked with event %s', {}),
                mock.call.info('Finalize: sending last batch of keys'),
                mock.call.info('Sending SQS batch of %d keys: %s ... %s',
                               3, 'test-key-1', 'test-key-3')
            ])

        self.batcher_main.SQS.assert_has_calls([
            mock.call.Queue('test_queue'),
            mock.call.Queue().send_messages(Entries=[
                {
                    'Id': '0',
                    'MessageBody': json.dumps({
                        'Records': [
                            {
                                's3': {
                                    'bucket': {'name': 'test_s3_bucket'},
                                    'object': {'key': 'test-key-1'}
                                }
                            },
                            {
                                's3': {
                                    'bucket': {'name': 'test_s3_bucket'},
                                    'object': {'key': 'test-key-2'}
                                }
                            }
                        ]
                    })
                },
                {
                    'Id': '1',
                    'MessageBody': json.dumps({
                        'Records': [
                            {
                                's3': {
                                    'bucket': {'name': 'test_s3_bucket'},
                                    'object': {'key': 'test-key-3'}
                                }
                            }
                        ]
                    })
                }
            ])
        ])

        self.batcher_main.CLOUDWATCH.assert_not_called()
        self.batcher_main.LAMBDA.assert_not_called()

    def test_batcher_re_invoke(self):
        """If the batcher runs out of time, it has to re-invoke itself."""
        class MockEnumerator(object):
            """Simple mock for S3BucketEnumerator which never finishes."""
            def __init__(self, *args):  # pylint: disable=unused-argument
                self.continuation_token = 'test-continuation-token'
                self.finished = False

        with mock.patch.object(self.batcher_main, 'S3BucketEnumerator', MockEnumerator),\
                mock.patch.object(self.batcher_main, 'LOGGER') as mock_logger:
            self.batcher_main.batch_lambda_handler(
                {}, common.MockLambdaContext(time_limit_ms=1)
            )
            mock_logger.assert_has_calls([mock.call.info('Invoking another batcher')])

        self.batcher_main.LAMBDA.assert_has_calls([
            mock.call.invoke(
                FunctionName='test_batch_lambda_name',
                InvocationType='Event',
                Payload='{"S3ContinuationToken": "test-continuation-token"}',
                Qualifier='Production'
            )
        ])

    def test_batcher_invoke_with_continuation(self):
        """Invoke the batcher with a continuation token."""
        self.batcher_main.S3.list_objects_v2 = lambda **kwargs: {
            'Contents': [
                {'Key': kwargs['ContinuationToken']}  # Make sure continuation token is included.
            ],
            'IsTruncated': False
        }

        with mock.patch.object(self.batcher_main, 'LOGGER'):
            num_keys = self.batcher_main.batch_lambda_handler(
                {'S3ContinuationToken': 'test-continuation-token'},
                common.MockLambdaContext()
            )
            self.assertEqual(1, num_keys)

        self.batcher_main.SQS.assert_has_calls([
            mock.call.Queue().send_messages(Entries=[
                {
                    'Id': '0',
                    'MessageBody': json.dumps({
                        'Records': [
                            {
                                's3': {
                                    'bucket': {'name': 'test_s3_bucket'},
                                    'object': {'key': 'test-continuation-token'}
                                }
                            }
                        ]
                    })
                }
            ])
        ])

    def test_batcher_sqs_errors(self):
        """Verify SQS errors are logged and reported to CloudWatch."""
        sqs_batcher = self.batcher_main.SQSBatcher('test_queue', 1)
        sqs_batcher._queue.send_messages.side_effect = lambda **kwargs: {
            'Failed': [
                {
                    'Id': msg['Id'],
                    'Message': 'msg',
                    'SenderFault': False,
                }
                for msg in kwargs['Entries']
            ]
        }
        sqs_batcher.add_key('test-key-1')
        sqs_batcher.add_key('test-key-2')

        with mock.patch.object(self.batcher_main, 'LOGGER') as mock_logger:
            sqs_batcher.finalize()

            mock_logger.assert_has_calls([
                mock.call.error(
                    'Unable to enqueue SQS message: %s',
                    {'Id': str(i), 'Message': 'msg', 'SenderFault': False}
                ) for i in range(2)
            ])

        self.batcher_main.CLOUDWATCH.assert_has_calls([
            mock.call.put_metric_data(
                Namespace='BinaryAlert',
                MetricData=[{
                    'MetricName': 'BatchEnqueueFailures',
                    'Value': 2,
                    'Unit': 'Count'
                }]
            )
        ])
