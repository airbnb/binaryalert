"""Unit tests for batcher main.py. Mocks out boto3 clients."""
import os
import unittest
from unittest import mock

import boto3
import moto

from tests import common


@moto.mock_sqs()
class MainTest(unittest.TestCase):
    """Test lambda_functions/dispatcher"""
    # pylint: disable=protected-access

    def setUp(self):
        """Set environment variables and setup the mocks."""
        url1 = boto3.client('sqs').create_queue(QueueName='q1')['QueueUrl']
        url2 = boto3.client('sqs').create_queue(QueueName='q2')['QueueUrl']

        mock_environ = {
            'LAMBDA_TARGETS': 'analyzer:production,downloader:staging',
            'SQS_QUEUE_URLS': '{},{}'.format(url1, url2)
        }

        with mock.patch.dict(os.environ, values=mock_environ):
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

    def test_sqs_poll(self):
        """Dispatcher invokes each of the Lambda targets with data from its respective queue."""
        self.config1.queue.send_message(MessageBody='queue1-message1')
        self.config1.queue.send_message(MessageBody='queue1-message2')

        with mock.patch.object(self.main, 'LOGGER') as mock_logger, \
                mock.patch.object(self.main, 'LAMBDA') as mock_lambda, \
                mock.patch.object(self.main, 'WAIT_TIME_SECONDS', 0):
            self.main._sqs_poll(self.config1, common.MockLambdaContext())

            mock_logger.assert_has_calls([
                mock.call.info(
                    'Polling process started: %s => lambda:%s:%s',
                    self.config1.queue.url,
                    self.config1.lambda_name, self.config1.lambda_qualifier),
                mock.call.info('Sending %d messages to %s:%s', 2, 'analyzer', 'production')
            ])

            mock_lambda.invoke.assert_called_once_with(
                FunctionName='analyzer',
                InvocationType='Event',
                Payload=mock.ANY,
                Qualifier='production'
            )

    def test_dispatch_handler(self):
        """Dispatch handler creates and starts processes."""
        with mock.patch.object(self.main, 'Process') as mock_process:
            self.main.dispatch_lambda_handler(None, common.MockLambdaContext())
            mock_process.assert_has_calls([
                mock.call(target=self.main._sqs_poll, args=(self.config1, mock.ANY)),
                mock.call(target=self.main._sqs_poll, args=(self.config2, mock.ANY)),
                mock.call().start(),
                mock.call().start(),
                mock.call().join(),
                mock.call().join()
            ])
