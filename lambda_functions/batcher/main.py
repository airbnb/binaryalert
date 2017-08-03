"""Batching Lambda function - puts all S3 objects into SQS to be re-analyzed."""
# Expects the following environment variables:
#   BATCH_LAMBDA_NAME: The name of this Lambda function.
#   BATCH_LAMBDA_QUALIFIER: The qualifier (alias) which is used to invoke this function.
#   OBJECTS_PER_MESSAGE: The number of S3 objects to pack into a single SQS message.
#   S3_BUCKET_NAME: Name of the S3 bucket to enumerate.
#   SQS_QUEUE_URL: URL of the SQS queue which will buffer all of the S3 objects for analysis.
import json
import logging
import os

import boto3

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

LAMBDA_CLIENT = boto3.client('lambda')
S3_CLIENT = boto3.client('s3')
SQS_CLIENT = boto3.client('sqs')


class SQSMessage(object):
    """Encapsulates a single SQS message (which will contain multiple S3 keys)."""

    def __init__(self, msg_id):
        """Create a new message structure, which will store a list of S3 keys.

        Args:
            msg_id: [int] Message index in the global list.
        """
        self._id = msg_id
        self._keys = []

    @property
    def num_keys(self):
        """Returns [int] the number of keys stored in the SQS message so far."""
        return len(self._keys)

    def add_key(self, key):
        """Add another S3 key (string) to the message."""
        self._keys.append(key)

    def sqs_entry(self):
        """Returns a message entry [dict], as required by sqs_client.send_message_batch().

        Moreover, the message body matches the structure of an S3 added event. This gives all
        messages in the SQS the same format and enables the dispatcher to parse them consistently.
        """
        return {
            'Id': str(self._id),
            'MessageBody': json.dumps({
                'Records': [{'s3': {'object': {'key': key}}} for key in self._keys]
            })
        }

    def reset(self):
        """Remove the stored list of S3 keys."""
        self._keys = []


class SQSBatcher(object):
    """Collect groups of S3 keys and batch them into as few SQS requests as possible."""

    def __init__(self, queue_url, objects_per_message, messages_per_batch=10):
        """Create a new SQS batcher.

        Args:
            queue_url: [string] URL of the queue to send messages to.
            objects_per_message: [int] The maximum number of S3 keys to put in each SQS message.
            messages_per_batch: [int] The maximum number of SQS messages to batch together.
                SQS caps this value at 10.

        Note that the downstream analyzer Lambdas will each process at most
        (objects_per_message * messages_per_batch) binaries. The analyzer runtime limit is the
        ultimate constraint on the size of each batch.
        """
        self._queue_url = queue_url
        self._objects_per_message = objects_per_message
        self._messages_per_batch = messages_per_batch

        self._messages = [SQSMessage(i) for i in range(messages_per_batch)]
        self._msg_index = 0  # The index of the SQS message where keys are currently being added.

        # The first and last keys added to this batch.
        self._first_key = None
        self._last_key = None

    def _send_batch(self):
        """Group keys into messages and make a single batch request."""
        LOGGER.info('Sending SQS batch of %d keys: %s ... %s',
                    sum(msg.num_keys for msg in self._messages), self._first_key, self._last_key)
        response = SQS_CLIENT.send_message_batch(
            QueueUrl=self._queue_url,
            Entries=[msg.sqs_entry() for msg in self._messages if msg.num_keys > 0]
        )

        failures = response.get('Failed', [])
        if failures:
            for failure in failures:
                LOGGER.error('Unable to enqueue SQS message: %s', failure)
            boto3.client('cloudwatch').put_metric_data(Namespace='BinaryAlert', MetricData=[{
                'MetricName': 'BatchEnqueueFailures',
                'Value': len(failures),
                'Unit': 'Count'
            }])

        for msg in self._messages:
            msg.reset()
        self._first_key = None

    def add_key(self, key):
        """Add a new S3 key [string] to the message batch and send to SQS if necessary."""
        if not self._first_key:
            self._first_key = key
        self._last_key = key

        msg = self._messages[self._msg_index]
        msg.add_key(key)

        # If the current message is full, move to the next one.
        if msg.num_keys == self._objects_per_message:
            self._msg_index += 1

            # If all of the messages are full, fire off to SQS.
            if self._msg_index == self._messages_per_batch:
                self._send_batch()
                self._msg_index = 0

    def finalize(self):
        """After all messages have been added, send the remaining as a last batch to SQS."""
        if self._first_key:
            LOGGER.info('Finalize: sending last batch of keys')
            self._send_batch()


class S3BucketEnumerator(object):
    """Enumerates all of the S3 objects in a given bucket."""

    def __init__(self, bucket_name, continuation_token=None):
        """Instantiate with an optional continuation token.

        Args:
            bucket_name: [string] Name of the S3 bucket to enumerate.
            continuation_token: [string] Continuation token returned from S3 list objects.
        """
        self.bucket_name = bucket_name
        self.continuation_token = continuation_token
        self.finished = False  # Have we finished enumerating all of the S3 bucket?

    def next_page(self):
        """Get the next page of S3 objects.

        Returns:
            List of string S3 object keys. Also sets self.finished = True if this is the last page.
        """
        if self.continuation_token:
            response = S3_CLIENT.list_objects_v2(
                Bucket=self.bucket_name, ContinuationToken=self.continuation_token)
        else:
            response = S3_CLIENT.list_objects_v2(Bucket=self.bucket_name)

        if 'Contents' not in response:
            LOGGER.info('The S3 bucket is empty; nothing to do')
            self.finished = True
            return []

        self.continuation_token = response.get('NextContinuationToken')
        if not response['IsTruncated']:
            self.finished = True

        return [obj['Key'] for obj in response['Contents']]


def batch_lambda_handler(event, lambda_context):
    """Entry point for the batch Lambda function.

    Args:
        event: [dict] Invocation event. If 'S3ContinuationToken' is one of the keys, the S3 bucket
            will be enumerated beginning with that continuation token.
        lambda_context: [LambdaContext] object with .get_remaining_time_in_millis().

    Returns:
        [int] The number of enumerated S3 keys.
    """
    LOGGER.info('Invoked with event %s', json.dumps(event))

    s3_enumerator = S3BucketEnumerator(
        os.environ['S3_BUCKET_NAME'], event.get('S3ContinuationToken'))
    sqs_batcher = SQSBatcher(os.environ['SQS_QUEUE_URL'], int(os.environ['OBJECTS_PER_MESSAGE']))

    # As long as there are at least 10 seconds remaining, enumerate S3 objects into SQS.
    num_keys = 0
    while lambda_context.get_remaining_time_in_millis() > 10000 and not s3_enumerator.finished:
        keys = s3_enumerator.next_page()
        num_keys += len(keys)
        for key in keys:
            sqs_batcher.add_key(key)

    # Send the last batch of keys.
    sqs_batcher.finalize()

    # If the enumerator has not yet finished but we're low on time, invoke this function again.
    if not s3_enumerator.finished:
        LOGGER.info('Invoking another batcher')
        LAMBDA_CLIENT.invoke(
            FunctionName=os.environ['BATCH_LAMBDA_NAME'],
            InvocationType='Event',  # Asynchronous invocation.
            Payload=json.dumps({'S3ContinuationToken': s3_enumerator.continuation_token}),
            Qualifier=os.environ['BATCH_LAMBDA_QUALIFIER']
        )

    return num_keys
