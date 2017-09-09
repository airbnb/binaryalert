"""The dispatch Lambda function."""
# Expects the following environment variables:
#   ANALYZE_LAMBDA_NAME: Name of the analysis Lambda function.
#   ANALYZE_LAMBDA_QUALIFIER: Alias name for the analysis Lambda function (e.g. "Production").
#   MAX_DISPATCHES: Maximum number of analysis invocations allowed during our runtime.
#   SQS_QUEUE_URL: URL of the SQS queue from which to poll S3 object data.
import json
import logging
import os
from typing import Any, Dict, List, Optional

import boto3

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

LAMBDA = boto3.client('lambda')
SQS_QUEUE = boto3.resource('sqs').Queue(os.environ['SQS_QUEUE_URL'])
SQS_MAX_MESSAGES = 10  # Maximum number of messages to request (highest allowed by SQS).
WAIT_TIME_SECONDS = 10  # Maximum amount of time to hold a receive_message connection open.


def _build_payload(sqs_messages: Dict[str, Any]) -> Optional[Dict[str, List[str]]]:
    """Convert a batch of SQS messages into an analysis Lambda payload.

    Args:
        sqs_messages: Response from SQS.receive_message. Expected format:
            {
                'Messages': [
                    {
                        'Body': '{"Records": [{"s3": {"object": {"key": "..."}}}, ...]}',
                        'ReceiptHandle': '...'
                    },
                    ...
                ]
            }
            There may be multiple SQS messages, each of which may contain multiple S3 keys.
            Each message body is a JSON string, in the format of an S3 object added event.

    Returns:
        Non-empty payload for the analysis Lambda function in the following format:
            {
                'S3Objects': ['key1', 'key2', ...],
                'SQSReceipts': ['receipt1', 'receipt2', ...]
            }
        Returns None if the SQS message was empty or invalid.
    """
    if 'Messages' not in sqs_messages:
        LOGGER.info('No SQS messages found')
        return None

    # The payload consists of S3 object keys and SQS receipts (analyzers will delete the message).
    payload: Dict[str, List[str]] = {'S3Objects': [], 'SQSReceipts': []}
    invalid_receipts = []  # List of invalid SQS message receipts to delete.
    for msg in sqs_messages['Messages']:
        try:
            payload['S3Objects'].extend(
                record['s3']['object']['key'] for record in json.loads(msg['Body'])['Records'])
            payload['SQSReceipts'].append(msg['ReceiptHandle'])
        except (KeyError, ValueError):
            LOGGER.warning('Invalid SQS message body: %s', msg['Body'])
            invalid_receipts.append(msg['ReceiptHandle'])
            continue

    # Remove invalid messages from the SQS queue (happens when queue is first created).
    if invalid_receipts:
        LOGGER.warning('Removing %d invalid messages', len(invalid_receipts))
        SQS_QUEUE.delete_messages(
            Entries=[{'Id': str(index), 'ReceiptHandle': receipt}
                     for index, receipt in enumerate(invalid_receipts)]
        )

    # If there were no valid S3 objects, return None.
    if not payload['S3Objects']:
        return None

    return payload


def dispatch_lambda_handler(_, lambda_context) -> int:
    """Dispatch Lambda function entry point.

    Args:
        lambda_context: LambdaContext object with .get_remaining_time_in_millis().

    Returns:
        The number of analysis Lambda functions invoked.
    """
    invocations = 0

    # The maximum amount of time needed in the execution loop.
    # This allows us to dispatch as long as possible while still staying under the time limit.
    # We need time to wait for sqs messages as well as a few seconds (e.g. 3) to process them.
    loop_execution_time_ms = (WAIT_TIME_SECONDS + 3) * 1000

    # Poll for messages until we either reach our invocation limit or run out of time.
    while (invocations < int(os.environ['MAX_DISPATCHES']) and
           lambda_context.get_remaining_time_in_millis() > loop_execution_time_ms):
        # Long-polling of SQS: Wait up to 10 seconds and receive up to 10 messages.
        sqs_messages = SQS_QUEUE.receive_message(
            MaxNumberOfMessages=SQS_MAX_MESSAGES,
            WaitTimeSeconds=WAIT_TIME_SECONDS
        )

        # Validate the SQS message and construct the payload.
        payload = _build_payload(sqs_messages)
        if not payload:
            continue
        LOGGER.info('Sending %d object(s) to an analyzer: %s',
                    len(payload['S3Objects']), payload['S3Objects'])

        # Asynchronously invoke an analyzer lambda.
        LAMBDA.invoke(
            FunctionName=os.environ['ANALYZE_LAMBDA_NAME'],
            InvocationType='Event',  # Request asynchronous invocation.
            Payload=json.dumps(payload),
            Qualifier=os.environ['ANALYZE_LAMBDA_QUALIFIER']
        )
        invocations += 1

    LOGGER.info('Invoked %d total analyzers', invocations)
    return invocations
