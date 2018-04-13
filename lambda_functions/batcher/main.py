"""Batching Lambda function - puts all S3 objects into SQS to be re-analyzed."""
# Expects the following environment variables:
#   BATCH_LAMBDA_NAME: The name of this Lambda function.
#   BATCH_LAMBDA_QUALIFIER: The qualifier (alias) which is used to invoke this function.
#   OBJECT_PREFIX: (Optional) Limit batching to keys which begin with the specified prefix.
#   OBJECTS_PER_MESSAGE: The number of S3 objects to pack into a single SQS message.
#   S3_BUCKET_NAME: Name of the S3 bucket to enumerate.
#   SQS_QUEUE_URL: URL of the SQS queue which will buffer all of the S3 objects for analysis.
import json
import logging
import os
from typing import Any, Dict, List, Optional

import boto3

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

CLOUDWATCH = boto3.client('cloudwatch')
LAMBDA = boto3.client('lambda')
S3 = boto3.client('s3')
SQS = boto3.resource('sqs')
SQS_MAX_MESSAGES_PER_BATCH = 10


class SQSMessage(object):
    """Encapsulates a single SQS message (which will contain multiple S3 keys)."""

    def __init__(self, msg_id: int) -> None:
        """Create a new message structure, which will store a list of S3 keys.

        Args:
            msg_id: Message index in the global list.
        """
        self._id = msg_id
        self._keys: List[str] = []

    @property
    def num_keys(self) -> int:
        """Returns the number of keys stored in the SQS message so far."""
        return len(self._keys)

    def add_key(self, key: str) -> None:
        """Add another S3 key to the message."""
        self._keys.append(key)

    def sqs_entry(self) -> Dict[str, str]:
        """Returns a message entry in the format expected by sqs_client.send_message_batch().

        Moreover, the message body matches the structure of an S3 added event. This gives all
        messages in the queue the same format and enables the dispatcher to parse them consistently.
        """
        return {
            'Id': str(self._id),
            'MessageBody': json.dumps({
                'Records': [
                    {
                        's3': {
                            'bucket': {'name': os.environ['S3_BUCKET_NAME']},
                            'object': {'key': key}
                        }
                    }
                    for key in self._keys
                ]
            })
        }

    def reset(self) -> None:
        """Remove the stored list of S3 keys."""
        self._keys = []


class SQSBatcher(object):
    """Collect groups of S3 keys and batch them into as few SQS requests as possible."""

    def __init__(self, queue_url: str, objects_per_message: int) -> None:
        """Create a new SQS batcher.

        Args:
            queue_url: Destination SQS queue URL.
            objects_per_message: The maximum number of S3 keys to put in each SQS message.

        Note that the downstream analyzer Lambdas will each process at most
        (objects_per_message * messages_per_batch) binaries. The analyzer runtime limit is the
        ultimate constraint on the size of each batch.
        """
        self._queue = SQS.Queue(queue_url)
        self._objects_per_message = objects_per_message

        self._messages = [SQSMessage(i) for i in range(SQS_MAX_MESSAGES_PER_BATCH)]
        self._msg_index = 0  # The index of the SQS message where keys are currently being added.

        # The first and last keys added to this batch.
        self._first_key: Optional[str] = None
        self._last_key: Optional[str] = None

    def _send_batch(self) -> None:
        """Group keys into messages and make a single batch request."""
        LOGGER.info('Sending SQS batch of %d keys: %s ... %s',
                    sum(msg.num_keys for msg in self._messages), self._first_key, self._last_key)
        response = self._queue.send_messages(
            Entries=[msg.sqs_entry() for msg in self._messages if msg.num_keys > 0]
        )

        failures = response.get('Failed', [])
        if failures:
            # TODO: If failure['SenderFault'] == False, we could retry the failed messages
            for failure in failures:
                LOGGER.error('Unable to enqueue SQS message: %s', failure)
            CLOUDWATCH.put_metric_data(Namespace='BinaryAlert', MetricData=[{
                'MetricName': 'BatchEnqueueFailures',
                'Value': len(failures),
                'Unit': 'Count'
            }])

        for msg in self._messages:
            msg.reset()
        self._first_key = None

    def add_key(self, key: str) -> None:
        """Add a new S3 key to the message batch and send to SQS if necessary."""
        if not self._first_key:
            self._first_key = key
        self._last_key = key

        msg = self._messages[self._msg_index]
        msg.add_key(key)

        # If the current message is full, move to the next one.
        if msg.num_keys == self._objects_per_message:
            self._msg_index += 1

            # If all of the messages are full, fire off to SQS.
            if self._msg_index == SQS_MAX_MESSAGES_PER_BATCH:
                self._send_batch()
                self._msg_index = 0

    def finalize(self) -> None:
        """After all messages have been added, send the remaining as a last batch to SQS."""
        if self._first_key:
            LOGGER.info('Finalize: sending last batch of keys')
            self._send_batch()


class S3BucketEnumerator(object):
    """Enumerates all of the S3 objects in a given bucket."""

    def __init__(self, bucket_name: str, prefix: Optional[str],
                 continuation_token: Optional[str] = None) -> None:
        """Instantiate with an optional continuation token.

        Args:
            bucket_name: Name of the S3 bucket to enumerate.
            prefix: Limit the enumeration to keys which begin with the specified prefix.
            continuation_token: Continuation token returned from S3 list objects.
        """
        # Construct the list_objects keyword arguments.
        self.kwargs = {'Bucket': bucket_name}
        if prefix:
            LOGGER.info('Restricting batch operation to prefix: %s', prefix)
            self.kwargs['Prefix'] = prefix
        if continuation_token:
            self.kwargs['ContinuationToken'] = continuation_token
        self.finished = False  # Have we finished enumerating all of the S3 bucket?

    @property
    def continuation_token(self) -> str:
        return self.kwargs.get('ContinuationToken')

    def next_page(self) -> List[str]:
        """Get the next page of S3 objects and sets self.finished = True if this is the last page.

        Returns:
            List of S3 object keys.
        """
        response = S3.list_objects_v2(**self.kwargs)

        if 'Contents' not in response:
            LOGGER.info('The S3 bucket is empty; nothing to do')
            self.finished = True
            return []

        self.kwargs['ContinuationToken'] = response.get('NextContinuationToken')
        if not response['IsTruncated']:
            self.finished = True

        return [obj['Key'] for obj in response['Contents']]


def batch_lambda_handler(event: Dict[str, str], lambda_context: Any) -> int:
    """Entry point for the batch Lambda function.

    Args:
        event: Invocation event. If 'S3ContinuationToken' is one of the keys, the S3 bucket
            will be enumerated beginning with that continuation token.
        lambda_context: LambdaContext object with .get_remaining_time_in_millis().

    Returns:
        The number of enumerated S3 keys.
    """
    LOGGER.info('Invoked with event %s', event)

    s3_enumerator = S3BucketEnumerator(
        os.environ['S3_BUCKET_NAME'],
        os.environ.get('OBJECT_PREFIX'),
        event.get('S3ContinuationToken')
    )
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
        LAMBDA.invoke(
            FunctionName=os.environ['BATCH_LAMBDA_NAME'],
            InvocationType='Event',  # Asynchronous invocation.
            Payload=json.dumps({'S3ContinuationToken': s3_enumerator.continuation_token}),
            Qualifier=os.environ['BATCH_LAMBDA_QUALIFIER']
        )

    return num_keys
