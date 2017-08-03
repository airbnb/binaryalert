"""Unit tests for batcher main.py. Mocks out boto3 clients."""
import json
import os
import unittest

import boto3
import moto

from lambda_functions.batcher import main
from tests import boto3_mocks


class MainTest(unittest.TestCase):
    """Test the batcher enqueuing everything from S3 into SQS."""

    def setUp(self):
        """Set environment variables and setup the mocks."""
        os.environ['BATCH_LAMBDA_NAME'] = 'test_batch_lambda_name'
        os.environ['BATCH_LAMBDA_QUALIFIER'] = 'Production'
        os.environ['OBJECTS_PER_MESSAGE'] = '2'
        os.environ['S3_BUCKET_NAME'] = 'test_s3_bucket'
        os.environ['SQS_QUEUE_URL'] = 'https://sqs.us-east-1.amazonaws.com/1234/test_queue'

        self._mocks = [moto.mock_cloudwatch(), moto.mock_lambda(), moto.mock_s3(), moto.mock_sqs()]
        for mock in self._mocks:
            mock.start()

        self._bucket = boto3.resource('s3').Bucket(os.environ['S3_BUCKET_NAME'])
        self._bucket.create()

        response = boto3.client('sqs').create_queue(QueueName='test_queue')
        self._queue = boto3.resource('sqs').Queue(response['QueueUrl'])

    def tearDown(self):
        """Reset moto mocks."""
        for mock in self._mocks:
            mock.stop()

    def _sqs_messages(self):
        """Retrieve parsed form of all pending SQS messages."""
        return [
            json.loads(msg.body) for msg in self._queue.receive_messages(MaxNumberOfMessages=10)]

    def test_batcher_empty_bucket(self):
        """Batcher does nothing for an empty bucket."""
        result = main.batch_lambda_handler({}, boto3_mocks.MockLambdaContext())
        self.assertEqual(0, result)
        self.assertEqual([], self._sqs_messages())

    def test_batcher_one_object(self):
        """Batcher enqueues a single S3 object."""
        self._bucket.put_object(Body=b'Object 1', Key='key1')

        result = main.batch_lambda_handler({}, boto3_mocks.MockLambdaContext())
        self.assertEqual(1, result)

        expected_sqs_msg = {'Records': [{'s3': {'object': {'key': 'key1'}}}]}
        self.assertEqual([expected_sqs_msg], self._sqs_messages())

    def test_batcher_one_full_batch(self):
        """Batcher enqueues the configured maximum number of objects in a single SQS message."""
        self._bucket.put_object(Body=b'Object 1', Key='key1')
        self._bucket.put_object(Body=b'Object 2', Key='key2')

        result = main.batch_lambda_handler({}, boto3_mocks.MockLambdaContext())
        self.assertEqual(2, result)

        expected_sqs_msg = {'Records': [{'s3': {'object': {'key': 'key1'}}},
                                        {'s3': {'object': {'key': 'key2'}}}]}
        self.assertEqual([expected_sqs_msg], self._sqs_messages())

    def test_batcher_one_batch_plus_one(self):
        """Batcher enqueues more than 1 full batch; less than 2."""
        self._bucket.put_object(Body=b'Object 1', Key='key1')
        self._bucket.put_object(Body=b'Object 2', Key='key2')
        self._bucket.put_object(Body=b'Object 3', Key='key3')

        result = main.batch_lambda_handler({}, boto3_mocks.MockLambdaContext())
        self.assertEqual(3, result)

        expected_sqs_msgs = [
            {'Records': [{'s3': {'object': {'key': 'key1'}}},
                         {'s3': {'object': {'key': 'key2'}}}]},
            {'Records': [{'s3': {'object': {'key': 'key3'}}}]}
        ]
        self.assertEqual(expected_sqs_msgs, self._sqs_messages())


if __name__ == '__main__':
    unittest.main()
