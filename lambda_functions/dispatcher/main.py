"""The generic SQS dispatch Lambda function."""
# The dispatcher rotates through all of the SQS queues listed, polling a batch of up to 10 records
# and forwarding them to the Lambda function configured for that queue.
#
# Expects the following environment variables:
#   SQS_QUEUE_URLS: Comma-separated list of SQS queues to poll.
#   LAMBDA_TARGETS: Comma-separated list of Lambda function:qualifier to dispatch to.
import collections
import json
import logging
from multiprocessing import Process
import os
from typing import Any, Dict, List

import boto3

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

LAMBDA = boto3.client('lambda')

# Build a DispatchConfig tuple for each queue specified in the environment variables.
DispatchConfig = collections.namedtuple(
    'DispatchConfig', ['queue', 'lambda_name', 'lambda_qualifier'])
DISPATCH_CONFIGS = [
    DispatchConfig(
        queue=boto3.resource('sqs').Queue(url),
        lambda_name=target.split(':')[0],
        lambda_qualifier=target.split(':')[1]
    )
    for (url, target) in zip(
        os.environ['SQS_QUEUE_URLS'].split(','),
        os.environ['LAMBDA_TARGETS'].split(',')
    )
]

SQS_MAX_MESSAGES = 10  # Maximum number of messages to request (highest allowed by SQS).
WAIT_TIME_SECONDS = 20  # Maximum amount of time to hold a receive_message connection open.


def _invoke_lambda(queue_url: str, sqs_messages: List[Any], config: DispatchConfig) -> None:
    """Invoke the target Lambda with a batch of SQS messages."""
    payload = {
        'messages': [
            {
                'body': msg.body,
                'receipt': msg.receipt_handle,
                # Approx. # of times message was received from the queue but not deleted.
                'receive_count': int(msg.attributes['ApproximateReceiveCount']),
            }
            for msg in sqs_messages
        ],
        'queue_url': queue_url
    }

    # Invoke the target Lambda.
    LOGGER.info('Sending %d messages to %s:%s',
                len(sqs_messages), config.lambda_name, config.lambda_qualifier)
    LAMBDA.invoke(
        FunctionName=config.lambda_name,
        InvocationType='Event',  # Asynchronous invocation
        Payload=json.dumps(payload, separators=(',', ':')),
        Qualifier=config.lambda_qualifier
    )


def _sqs_poll(config: DispatchConfig, lambda_context: Any):
    """Process entry point: long polling of a single queue."""
    LOGGER.info('Polling process started: %s => lambda:%s:%s',
                config.queue.url, config.lambda_name, config.lambda_qualifier)

    # Keep polling the queue until we're about to run out of time.
    while lambda_context.get_remaining_time_in_millis() > (WAIT_TIME_SECONDS + 3) * 1000:
        # Long-polling: blocks until at least one message is available or the connection times out.
        sqs_messages = config.queue.receive_messages(
            AttributeNames=['ApproximateReceiveCount'],
            MaxNumberOfMessages=SQS_MAX_MESSAGES,
            WaitTimeSeconds=WAIT_TIME_SECONDS
        )
        if sqs_messages:
            _invoke_lambda(config.queue.url, sqs_messages, config)


def dispatch_lambda_handler(_: Dict[str, Any], lambda_context: Any) -> None:
    """Dispatch Lambda function entry point.

    Args:
        _: Unused invocation event.
        lambda_context: LambdaContext object with .get_remaining_time_in_millis().
    """
    # Create a separate process for polling each queue.
    processes = [Process(target=_sqs_poll, args=(config, lambda_context))
                 for config in DISPATCH_CONFIGS]

    # Start each polling process.
    for process in processes:
        process.start()

    # Wait for all of the polling processes to finish, then exit normally.
    for process in processes:
        process.join()
