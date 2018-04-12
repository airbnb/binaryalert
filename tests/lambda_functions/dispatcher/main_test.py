"""Unit tests for batcher main.py. Mocks out boto3 clients."""
import collections
import os
import unittest
from unittest import mock

import boto3
import moto

from tests import common

MockSQSMessage = collections.namedtuple('MockSQSMessage', ['attributes', 'body', 'receipt_handle'])


@moto.mock_cloudwatch()
@moto.mock_lambda()
@moto.mock_sqs()
class MainTest(unittest.TestCase):
    """Test the dispatch handler."""

    def setUp(self):
        """Set environment variables and setup the mocks."""
        url1 = boto3.client('sqs').create_queue(QueueName='q1')['QueueUrl']
        url2 = boto3.client('sqs').create_queue(QueueName='q2')['QueueUrl']

        mock_environ = {
            'LAMBDA_TARGETS': 'analyzer:production,downloader:staging',
            'SQS_QUEUE_URLS': '{},{}'.format(url1, url2)
        }

        with mock.patch.dict(os.environ, mock_environ):
            from lambda_functions.dispatcher import main
            self.main = main

        self.config1 = self.main.DISPATCH_CONFIGS[0]
        self.config2 = self.main.DISPATCH_CONFIGS[1]

    def test_dispatch_configs(self):
        """Environment variables were parsed correctly into 2 DispatchConfig tuples."""
        self.assertTrue(self.config1.queue.url.endswith('q1'))
        self.assertEqual('analyzer', self.config1.lambda_name)
        self.assertEqual('production', self.config1.lambda_qualifier)

        self.assertTrue(self.config2.queue.url.endswith('q2'))
        self.assertNotEqual(self.config1.queue, self.config2.queue)
        self.assertEqual('downloader', self.config2.lambda_name)
        self.assertEqual('staging', self.config2.lambda_qualifier)

    def test_dispatch_no_messages(self):
        """Dispatcher doesn't do anything if there are no SQS messages."""
        with mock.patch.object(self.main, 'WAIT_TIME_SECONDS', 0), \
                mock.patch.object(self.main, 'LOGGER') as mock_logger:
            self.main.dispatch_lambda_handler(None, common.MockLambdaContext())
            mock_logger.assert_not_called()

    def test_dispatch_invokes_all_targets(self):
        """Dispatcher invokes each of the Lambda targets with data from its respective queue."""
        self.config1.queue.send_message(MessageBody='queue1-message1')
        self.config1.queue.send_message(MessageBody='queue1-message2')
        self.config2.queue.send_message(MessageBody='queue2-message1')

        with mock.patch.object(self.main, 'LOGGER') as mock_logger, \
                mock.patch.object(self.main, 'CLOUDWATCH') as mock_cloudwatch, \
                mock.patch.object(self.main, 'LAMBDA') as mock_lambda:
            self.main.dispatch_lambda_handler(None, common.MockLambdaContext())

            mock_logger.assert_has_calls([
                mock.call.info('Sending %d messages to %s:%s', 2, 'analyzer', 'production'),
                mock.call.info('Sending %d messages to %s:%s', 1, 'downloader', 'staging'),
                mock.call.info('Publishing invocation metrics')
            ])

            mock_lambda.assert_has_calls([
                mock.call.invoke(
                    FunctionName='analyzer',
                    InvocationType='Event',
                    Payload=mock.ANY,
                    Qualifier='production'
                ),
                mock.call.invoke(
                    FunctionName='downloader',
                    InvocationType='Event',
                    Payload=mock.ANY,
                    Qualifier='staging'
                )
            ])

            mock_cloudwatch.assert_has_calls([
                mock.call.put_metric_data(
                    Namespace='BinaryAlert',
                    MetricData=[
                        {
                            'MetricName': 'DispatchInvocations',
                            'Dimensions': [{'Name': 'FunctionName', 'Value': 'analyzer'}],
                            'Value': 1,
                            'Unit': 'Count'
                        },
                        {
                            'MetricName': 'DispatchBatchSize',
                            'Dimensions': [{'Name': 'FunctionName', 'Value': 'analyzer'}],
                            'StatisticValues': {
                                'Minimum': 2,
                                'Maximum': 2,
                                'SampleCount': 1,
                                'Sum': 2
                            },
                            'Unit': 'Count'
                        },
                        {
                            'MetricName': 'DispatchInvocations',
                            'Dimensions': [{'Name': 'FunctionName', 'Value': 'downloader'}],
                            'Value': 1,
                            'Unit': 'Count'
                        },
                        {
                            'MetricName': 'DispatchBatchSize',
                            'Dimensions': [{'Name': 'FunctionName', 'Value': 'downloader'}],
                            'StatisticValues': {
                                'Minimum': 1,
                                'Maximum': 1,
                                'SampleCount': 1,
                                'Sum': 1
                            },
                            'Unit': 'Count'
                        }
                    ]
                )
            ])
