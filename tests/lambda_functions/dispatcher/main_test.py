"""Unit tests for batcher main.py. Mocks out boto3 clients."""
import collections
import json
import os
import unittest
from unittest import mock

import boto3

from tests import common

MockSQSMessage = collections.namedtuple('MockSQSMessage', ['body', 'receipt_handle'])


class MainTest(unittest.TestCase):
    """Test the dispatch handler."""

    def setUp(self):
        """Set environment variables and setup the mocks."""
        os.environ['ANALYZE_LAMBDA_NAME'] = 'test-analyzer'
        os.environ['ANALYZE_LAMBDA_QUALIFIER'] = 'Production'
        os.environ['MAX_DISPATCHES'] = '10'
        os.environ['SQS_QUEUE_URL'] = 'test-queue-url'

        with mock.patch.object(boto3, 'client'), mock.patch.object(boto3, 'resource'):
            from lambda_functions.dispatcher import main
            self.dispatcher_main = main

        # Reset mocks
        self.dispatcher_main.LAMBDA = mock.MagicMock()
        self.dispatcher_main.SQS_QUEUE = mock.MagicMock()

    def test_dispatcher_no_messages(self):
        """Dispatcher doesn't do anything if there are no SQS messages."""
        self.dispatcher_main.SQS_QUEUE.receive_messages.return_value = []

        with mock.patch.object(self.dispatcher_main, 'LOGGER') as mock_logger:
            invocations = self.dispatcher_main.dispatch_lambda_handler(
                {},
                common.MockLambdaContext(decrement_ms=10000)
            )
            self.assertEqual(0, invocations)

            mock_logger.assert_has_calls([
                mock.call.info('No SQS messages found'),
                mock.call.info('Invoked %d total analyzers', 0)
            ])

    def test_dispatcher_invalid_message(self):
        """Dispatcher discards invalid SQS messages."""
        self.dispatcher_main.SQS_QUEUE.receive_messages.return_value = [
            MockSQSMessage(body=json.dumps({'InvalidKey': 'Value'}), receipt_handle='receipt1'),
            MockSQSMessage(body=json.dumps({}), receipt_handle='receipt2'),
        ]

        with mock.patch.object(self.dispatcher_main, 'LOGGER') as mock_logger:
            invocations = self.dispatcher_main.dispatch_lambda_handler(
                {},
                common.MockLambdaContext(decrement_ms=10000)
            )
            self.assertEqual(0, invocations)

            mock_logger.assert_has_calls([
                mock.call.warning('Invalid SQS message body: %s', mock.ANY),
                mock.call.warning('Invalid SQS message body: %s', mock.ANY),
                mock.call.warning('Removing %d invalid messages', 2),
                mock.call.info('Invoked %d total analyzers', 0)
            ])

    def test_dispatcher_invokes_analyzer(self):
        """Dispatcher flattens multiple messages and invokes an analyzer."""
        self.dispatcher_main.SQS_QUEUE.receive_messages.return_value = [
            MockSQSMessage(
                body=json.dumps({
                    'Records': [
                        {
                            's3': {
                                'bucket': {'name': 'test-bucket'},
                                'object': {'key': 'test-key-1'}
                            }
                        },
                        {
                            's3': {
                                'bucket': {'name': 'test-bucket'},
                                'object': {'key': 'test-key-2'}
                            }
                        }
                    ]
                }),
                receipt_handle='receipt1'
            ),
            MockSQSMessage(
                body=json.dumps({
                    'Records': [
                        {
                            's3': {
                                'bucket': {'name': 'test-bucket'},
                                'object': {'key': 'test-key-3'}
                            }
                        }
                    ]
                }),
                receipt_handle='receipt2'
            )
        ]

        with mock.patch.object(self.dispatcher_main, 'LOGGER') as mock_logger:
            invocations = self.dispatcher_main.dispatch_lambda_handler(
                {},
                common.MockLambdaContext(decrement_ms=10000)
            )
            self.assertEqual(1, invocations)

            mock_logger.assert_has_calls([
                mock.call.info('Sending %d object(s) from %d SQS receipt(s)', 3, 2),
                mock.call.info('Invoked %d total analyzers', 1)
            ])

        self.dispatcher_main.LAMBDA.assert_has_calls([
            mock.call.invoke(
                FunctionName='test-analyzer',
                InvocationType='Event',
                Payload=json.dumps({
                    'Records': [
                        {
                            's3': {
                                'bucket': {'name': 'test-bucket'},
                                'object': {'key': 'test-key-1'}
                            }
                        },
                        {
                            's3': {
                                'bucket': {'name': 'test-bucket'},
                                'object': {'key': 'test-key-2'}
                            }
                        },
                        {
                            's3': {
                                'bucket': {'name': 'test-bucket'},
                                'object': {'key': 'test-key-3'}
                            }
                        },
                    ],
                    'SQSReceipts': ['receipt1', 'receipt2']
                }),
                Qualifier='Production'
            )
        ])
