"""AWS Lambda function for testing a binary against a list of YARA rules."""
# Expects the following environment variables:
#   NO_MATCHES_SNS_TOPIC_ARN: Optional ARN of an SNS topic to notify if there are no YARA matches.
#   YARA_MATCHES_DYNAMO_TABLE_NAME: Name of the Dynamo table which stores YARA match results.
#   YARA_ALERTS_SNS_TOPIC_ARN: ARN of the SNS topic which should be alerted on a YARA match.
# Expects a binary YARA rules file to be at './compiled_yara_rules.bin'
import json
import os
from typing import Any, Dict, Generator, Tuple
import urllib.parse

from botocore.exceptions import ClientError

from lambda_functions.analyzer import analyzer_aws_lib, binary_info, yara_analyzer
from lambda_functions.analyzer.common import COMPILED_RULES_FILEPATH, LOGGER

# Build the YaraAnalyzer from the compiled rules file at import time (i.e. once per container).
# This saves 50-100+ ms per Lambda invocation, depending on the size of the rules file.
ANALYZER = yara_analyzer.YaraAnalyzer(COMPILED_RULES_FILEPATH)
# Due to a bug in yara-python, num_rules only be computed once. Thereafter, it will return 0.
# So we have to compute this here since multiple invocations may share the same analyzer.
NUM_YARA_RULES = ANALYZER.num_rules


def _objects_to_analyze(event: Dict[str, Any]) -> Generator[Tuple[str, str], None, None]:
    """Parse the invocation event into a list of objects to analyze.

    Args:
        event: Invocation event (SQS message whose message body is an S3 event notification)

    Yields:
        (bucket_name, object_key) string tuples to analyze
    """
    if 'BucketName' in event and 'ObjectKeys' in event:
        # Direct (simple) invocation
        for key in event['ObjectKeys']:
            yield event['BucketName'], urllib.parse.unquote_plus(key)
        return

    # SQS message invocation
    for sqs_message in event['Records']:
        try:
            s3_records = json.loads(sqs_message['body'])['Records']
        except (KeyError, TypeError, json.JSONDecodeError):
            LOGGER.exception('Skipping invalid SQS message %s', json.dumps(sqs_message))
            continue

        for s3_message in s3_records:
            yield (
                s3_message['s3']['bucket']['name'],
                urllib.parse.unquote_plus(s3_message['s3']['object']['key'])
            )


def analyze_lambda_handler(event: Dict[str, Any], lambda_context: Any) -> Dict[str, Any]:
    """Analyzer Lambda function entry point.

    Args:
        event: SQS message batch - each message body is a JSON-encoded S3 notification - {
            'Records': [
                {
                    'body': json.dumps({
                        'Records': [
                            {
                                's3': {
                                    'bucket': {
                                        'name': '...'
                                    },
                                    'object': {
                                        'key': '...'  # URL-encoded key
                                    }
                                },
                                ...
                            },
                            ...
                        ]
                    }),
                    ...
                }
            ]
        }

        Alternatively, direct invocation is supported with the following event - {
            'BucketName': '...',
            'EnableSNSAlerts': True,
            'ObjectKeys': ['key1', 'key2', ...],
        }

        lambda_context: LambdaContext object (with .function_version).

    Returns:
        A dict mapping S3 object identifier to a summary of file info and matched YARA rules.
        Example: {
            'S3:bucket:key': {
                'FileInfo': { ... },
                'MatchedRules': { ... },
                'NumMatchedRules': 1
            }
        }
    """
    # Executables in the root of the deployment package (upx, pdftotext, etc) are added to PATH.
    os.environ['PATH'] = '{}:{}'.format(os.environ['PATH'], os.environ['LAMBDA_TASK_ROOT'])
    os.environ['LD_LIBRARY_PATH'] = os.environ['LAMBDA_TASK_ROOT']

    result = {}
    binaries = []  # List of the BinaryInfo data.

    # The Lambda version must be an integer.
    try:
        lambda_version = int(lambda_context.function_version)
    except ValueError:
        LOGGER.warning('Invoked $LATEST instead of a versioned function')
        lambda_version = -1

    alerts_enabled = event.get('EnableSNSAlerts', True)

    for bucket_name, object_key in _objects_to_analyze(event):
        LOGGER.info('Analyzing "%s:%s"', bucket_name, object_key)

        try:
            with binary_info.BinaryInfo(bucket_name, object_key, ANALYZER) as binary:
                result[binary.s3_identifier] = binary.summary()
                binaries.append(binary)
        except analyzer_aws_lib.FileDownloadError:
            LOGGER.exception('Unable to download %s from %s', object_key, bucket_name)
            continue

        if binary.yara_matches:
            LOGGER.warning('%s matched YARA rules: %s', binary, binary.matched_rule_ids)
            binary.save_matches_and_alert(
                lambda_version, os.environ['YARA_MATCHES_DYNAMO_TABLE_NAME'],
                os.environ['YARA_ALERTS_SNS_TOPIC_ARN'],
                sns_enabled=alerts_enabled)
        else:
            LOGGER.info('%s did not match any YARA rules', binary)
            if alerts_enabled and os.environ['NO_MATCHES_SNS_TOPIC_ARN']:
                binary.publish_negative_match_result(os.environ['NO_MATCHES_SNS_TOPIC_ARN'])

    # Publish metrics.
    if binaries:
        try:
            analyzer_aws_lib.put_metric_data(NUM_YARA_RULES, binaries)
        except ClientError:
            LOGGER.exception('Error saving metric data')

    return result
