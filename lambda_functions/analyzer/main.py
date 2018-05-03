"""AWS Lambda function for testing a binary against a list of YARA rules."""
# Expects the following environment variables:
#   YARA_MATCHES_DYNAMO_TABLE_NAME: Name of the Dynamo table which stores YARA match results.
#   YARA_ALERTS_SNS_TOPIC_ARN: ARN of the SNS topic which should be alerted on a YARA match.
# Expects a binary YARA rules file to be at './compiled_yara_rules.bin'
import json
import os
from typing import Any, Dict, Generator, List, Tuple
import urllib.parse

from botocore.exceptions import ClientError

if __package__:
    # Imported by unit tests or other external code.
    from lambda_functions.analyzer import analyzer_aws_lib, binary_info, yara_analyzer
    from lambda_functions.analyzer.common import COMPILED_RULES_FILEPATH, LOGGER
else:
    # mypy complains about duplicate definitions
    import analyzer_aws_lib  # type: ignore
    import binary_info  # type: ignore
    from common import COMPILED_RULES_FILEPATH, LOGGER  # type: ignore
    import yara_analyzer  # type: ignore

# Build the YaraAnalyzer from the compiled rules file at import time (i.e. once per container).
# This saves 50-100+ ms per Lambda invocation, depending on the size of the rules file.
ANALYZER = yara_analyzer.YaraAnalyzer(COMPILED_RULES_FILEPATH)
# Due to a bug in yara-python, num_rules only be computed once. Thereafter, it will return 0.
# So we have to compute this here since multiple invocations may share the same analyzer.
NUM_YARA_RULES = ANALYZER.num_rules


def _s3_objects(s3_records: List[Dict[str, Any]]) -> Generator[Tuple[str, str], None, None]:
    """Build list of objects in the given S3 record.

    Args:
        s3_records: List of S3 event records: [
            {
                's3': {
                    'object': {
                        'key': (str)
                    },
                    'bucket': {
                        'name': (str)
                    }
                }
            },
            ...
        ]

    Yields:
        (bucket_name, object_key) string tuple
    """
    for record in s3_records:
        try:
            bucket_name = record['s3']['bucket']['name']
            object_key = urllib.parse.unquote_plus(record['s3']['object']['key'])
            yield bucket_name, object_key
        except (KeyError, TypeError):
            LOGGER.exception('Skipping invalid S3 record %s', record)


def _objects_to_analyze(event: Dict[str, Any]) -> Generator[Tuple[str, str], None, None]:
    """Parse the invocation event into a list of objects to analyze.

    Args:
        event: Invocation event, from either the dispatcher or an S3 bucket

    Yields:
        (bucket_name, object_key) string tuples to analyze
    """
    if set(event) == {'messages', 'queue_url'}:
        LOGGER.info('Invoked from dispatcher with %d messages', len(event['messages']))
        for sqs_record in event['messages']:
            try:
                s3_records = json.loads(sqs_record['body'])['Records']
            except (json.JSONDecodeError, KeyError, TypeError):
                LOGGER.exception('Skipping invalid SQS message %s', sqs_record)
                continue
            yield from _s3_objects(s3_records)
    else:
        LOGGER.info('Invoked with dictionary (S3 Event)')
        yield from _s3_objects(event['Records'])


def analyze_lambda_handler(event: Dict[str, Any], lambda_context: Any) -> Dict[str, Dict[str, Any]]:
    """Analyzer Lambda function entry point.

    Args:
        event: SQS message batch sent by the dispatcher: {
            'messages': [
                {
                    'body': (str) JSON-encoded S3 put event: {
                        'Records': [
                            {
                                's3': {
                                    'object': {
                                        'key': (str)
                                    },
                                    'bucket': {
                                        'name': (str)
                                    }
                                }
                            },
                            ...
                        ]
                    },
                    'receipt': (str) SQS message receipt handle,
                    'receive_count': (int) Approx. # of times this has been received
                },
                ...
            ],
            'queue_url': (str) SQS queue url from which the message originated
        }
            Alternatively, the event can be an S3 Put Event dictionary (with no sqs information).
            This allows the analyzer to be linked directly to an S3 bucket notification if needed.
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
                    os.environ['YARA_ALERTS_SNS_TOPIC_ARN'])
        else:
            LOGGER.info('%s did not match any YARA rules', binary)
            binary.safe_alert_only(
                lambda_version, 
                os.environ['SAFE_SNS_TOPIC_ARN'])
                
             
    # Delete all of the SQS receipts (mark them as completed).
    receipts_to_delete = [msg['receipt'] for msg in event.get('messages', [])]
    if receipts_to_delete:
        analyzer_aws_lib.delete_sqs_messages(event['queue_url'], receipts_to_delete)

    # Publish metrics.
    if binaries:
        try:
            analyzer_aws_lib.put_metric_data(NUM_YARA_RULES, binaries)
        except ClientError:
            LOGGER.exception('Error saving metric data')

    return result
