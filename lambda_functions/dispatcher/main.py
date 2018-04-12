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
import os
from typing import Any, Dict, List

import boto3

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

CLOUDWATCH = boto3.client('cloudwatch')
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
WAIT_TIME_SECONDS = 3  # Maximum amount of time to hold a receive_message connection open.


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


def _publish_metrics(batch_sizes: Dict[str, List[int]]) -> None:
    """Publish metrics about how many times each function was invoked, and with what batch sizes."""
    metric_data = []

    for function_name, batches in batch_sizes.items():
        if not batches:
            continue

        dimensions = [{'Name': 'FunctionName', 'Value': function_name}]
        metric_data.append({
            'MetricName': 'DispatchInvocations',
            'Dimensions': dimensions,
            'Value': len(batches),
            'Unit': 'Count'
        })
        metric_data.append({
            'MetricName': 'DispatchBatchSize',
            'Dimensions': dimensions,
            'StatisticValues': {
                'Minimum': min(batches),
                'Maximum': max(batches),
                'SampleCount': len(batches),
                'Sum': sum(batches)
            },
            'Unit': 'Count'
        })

    if metric_data:
        LOGGER.info('Publishing invocation metrics')
        CLOUDWATCH.put_metric_data(Namespace='BinaryAlert', MetricData=metric_data)


def dispatch_lambda_handler(_, lambda_context):
    """Dispatch Lambda function entry point.

    Args:
        _: Unused invocation event.
        lambda_context: LambdaContext object with .get_remaining_time_in_millis().
    """
    # Keep track of the batch sizes (one element for each invocation) for each target function.
    batch_sizes = {config.lambda_name: [] for config in DISPATCH_CONFIGS}

    # The maximum amount of time needed in the execution loop.
    # This allows us to dispatch as long as possible while still staying under the time limit.
    # We need time to wait for sqs messages as well as a few seconds (e.g. 3) to forward them.
    loop_execution_time_ms = (WAIT_TIME_SECONDS + 3) * 1000 * len(DISPATCH_CONFIGS)

    while lambda_context.get_remaining_time_in_millis() > loop_execution_time_ms:
        # Receive a batch of messages for each configured queue.
        for config in DISPATCH_CONFIGS:
            sqs_messages = config.queue.receive_messages(
                AttributeNames=['ApproximateReceiveCount'],
                MaxNumberOfMessages=SQS_MAX_MESSAGES,
                WaitTimeSeconds=WAIT_TIME_SECONDS
            )
            if sqs_messages:
                _invoke_lambda(config.queue.url, sqs_messages, config)
                batch_sizes[config.lambda_name].append(len(sqs_messages))

    _publish_metrics(batch_sizes)
