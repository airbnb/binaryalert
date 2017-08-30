"""AWS Lambda function for testing a binary against a list of YARA rules."""
# Expects the following environment variables:
#   S3_BUCKET_NAME: Name of the S3 bucket from which to download binaries.
#   SQS_QUEUE_URL: URL of the queue from which messages originated (needed for message deletion).
#   YARA_MATCHES_DYNAMO_TABLE_NAME: Name of the Dynamo table which stores YARA match results.
#   YARA_ALERTS_SNS_TOPIC_ARN: ARN of the SNS topic which should be alerted on a YARA match.
# Expects a binary YARA rules file to be at './compiled_yara_rules.bin'
import logging
import os
import urllib

from yara import Error as YaraError
from botocore.exceptions import ClientError as BotoError

if __package__:
    # Imported by unit tests or other external code.
    from lambda_functions.analyzer import analyzer_aws_lib, binary_info, yara_analyzer
else:
    import analyzer_aws_lib
    import binary_info
    import yara_analyzer

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)

THIS_DIRECTORY = os.path.dirname(os.path.realpath(__file__))  # Directory containing this file.
COMPILED_RULES_FILENAME = 'compiled_yara_rules.bin'  # Binary YARA rules file.
COMPILED_RULES_FILEPATH = os.path.join(THIS_DIRECTORY, COMPILED_RULES_FILENAME)

# Build the YaraAnalyzer from the compiled rules file at import time (i.e. once per container).
# This saves 50-100+ ms per Lambda invocation, depending on the size of the rules file.
# However, this breaks imports when the compiled rules file doesn't exist (e.g. unit tests).
# Fail-safe to computing the ANALYZER during the handler if we have to.
try:
    ANALYZER = yara_analyzer.YaraAnalyzer(COMPILED_RULES_FILEPATH)
    # Due to a bug in yara-python, num_rules only be computed once. Thereafter, it will return 0.
    # So we have to compute this here since multiple invocations may share the same analyzer.
    NUM_YARA_RULES = ANALYZER.num_rules
except YaraError:
    ANALYZER = None


def analyze_lambda_handler(event_data, lambda_context):
    """Lambda function entry point.

    Args:
        event_data: [dict] of the form: {
            'S3Objects': [...],  # S3 object keys.
            'SQSReceipts': [...]  # SQS receipt handles (to be deleted after processing).
        }
            There can be any number of S3objects, but no more than 10 SQS receipts.
        lambda_context: LambdaContext object (with .function_version).

    Returns:
        A dict mapping S3 object identifier [string] to a summary [dict] of file info and matched
        YARA rule information.
    """
    result = {}
    binaries = []  # List of the BinaryInfo data.

    # Build the YaraAnalyzer now if we could not do it when this file was imported.
    global ANALYZER, NUM_YARA_RULES  # pylint: disable=global-statement
    if not ANALYZER:
        ANALYZER = yara_analyzer.YaraAnalyzer(COMPILED_RULES_FILEPATH)
        NUM_YARA_RULES = ANALYZER.num_rules

    # The Lambda version must be an integer.
    try:
        lambda_version = int(lambda_context.function_version)
    except ValueError:
        lambda_version = -1

    LOGGER.info('Processing %d record(s)', len(event_data['S3Objects']))
    for s3_key in event_data['S3Objects']:
        # S3 keys in event notifications are url-encoded.
        s3_key = urllib.parse.unquote_plus(s3_key)
        LOGGER.info('Analyzing "%s"', s3_key)

        with binary_info.BinaryInfo(os.environ['S3_BUCKET_NAME'], s3_key, ANALYZER) as binary:
            result[binary.s3_identifier] = binary.summary()
            binaries.append(binary)

            if binary.yara_matches:
                LOGGER.warning('%s matched YARA rules: %s', binary, binary.matched_rule_ids)
                binary.save_matches_and_alert(
                    lambda_version, os.environ['YARA_MATCHES_DYNAMO_TABLE_NAME'],
                    os.environ['YARA_ALERTS_SNS_TOPIC_ARN'])
            else:
                LOGGER.info('%s did not match any YARA rules', binary)

    # Delete all of the SQS receipts (mark them as completed).
    analyzer_aws_lib.delete_sqs_messages(os.environ['SQS_QUEUE_URL'], event_data['SQSReceipts'])

    # Publish metrics.
    try:
        analyzer_aws_lib.put_metric_data(NUM_YARA_RULES, binaries)
    except BotoError:
        LOGGER.exception('Error saving metric data')

    return result
