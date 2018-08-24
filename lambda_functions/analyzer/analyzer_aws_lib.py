"""Collection of boto3 calls to AWS resources for the analyzer function."""
import json
from typing import Dict, List, Optional, Set, Tuple, Union

import boto3
from boto3.dynamodb.conditions import Key
from botocore.client import Config
from botocore.exceptions import ClientError

# BinaryInfo is imported here just for the type annotation - the cyclic import will resolve
from lambda_functions.analyzer.binary_info import BinaryInfo  # pylint: disable=cyclic-import
from lambda_functions.analyzer.common import LOGGER

SNS_PUBLISH_SUBJECT_MAX_SIZE = 99

# Build boto3 resources at import time so they can be cached between invocations.
CLOUDWATCH = boto3.client('cloudwatch')
DYNAMODB = boto3.resource('dynamodb')
S3 = boto3.resource('s3', config=Config(  # Force a retry after 3 seconds rather than 60
    connect_timeout=3, read_timeout=3, retries={'max_attempts': 2}))
SNS = boto3.resource('sns')


class FileDownloadError(Exception):
    """File can't be downloaded from S3 with a 4XX error code - do not retry."""


def download_from_s3(
        bucket_name: str, object_key: str, download_path: str) -> Tuple[str, Dict[str, str]]:
    """Download an object from S3 to the given download path.

    Args:
        bucket_name: S3 bucket name.
        object_key: S3 object key.
        download_path: Where to download the file locally.

    Returns:
        Last modified timestamp (i.e. object upload timestamp), object metadata.

    Raises:
        FileDownloadError: If the file couldn't be downloaded because
    """
    try:
        s3_object = S3.Object(bucket_name, object_key)
        s3_object.download_file(download_path)
        # UTC timestamp, e.g. '2017-09-04 04:49:06-00:00'
        last_modified = str(s3_object.last_modified)
        return last_modified, s3_object.metadata
    except ClientError as error:
        if 400 <= error.response['ResponseMetadata']['HTTPStatusCode'] < 500:
            raise FileDownloadError(error)
        else:
            raise


def _elide_string_middle(text: str, max_length: int) -> str:
    """Replace the middle of the text with ellipses to shorten text to the desired length.

    Args:
        text: Text to shorten.
        max_length: Maximum allowable length of the string.

    Returns:
        The elided text, e.g. "Some really long tex ... the end."
    """
    if len(text) <= max_length:
        return text

    half_len = (max_length - 5) // 2  # Length of text on either side.
    return '{} ... {}'.format(text[:half_len], text[-half_len:])


def publish_to_sns(binary: BinaryInfo, topic_arn: str, subject: str) -> None:
    """Publish a JSON SNS alert: a binary has matched one or more YARA rules.

    Args:
        binary: Instance containing information about the binary.
        topic_arn: Publish to this SNS topic ARN.
        subject: Message subject (for email subscriptions to the topic)
    """
    SNS.Topic(topic_arn).publish(
        Subject=_elide_string_middle(subject, SNS_PUBLISH_SUBJECT_MAX_SIZE),
        Message=(json.dumps(binary.summary(), indent=4, sort_keys=True))
    )


def _compute_statistics(values: List[Union[int, float]]) -> Dict[str, Union[int, float]]:
    """Compute summary statistics for a collection of values.

    Args:
        values: numeric values in the sample set.

    Returns:
        CloudWatch metric statistics dictionary.
    """
    return {
        'Minimum': min(values),
        'Maximum': max(values),
        'SampleCount': len(values),
        'Sum': sum(values)
    }


def put_metric_data(num_yara_rules: int, binaries: List[BinaryInfo]) -> None:
    """Publish custom metric data to CloudWatch.

    Args:
        num_yara_rules: Number of YARA rules in the analyzer.
        binaries: List of analyzed BinaryInfo()s.
    """
    LOGGER.debug('Sending metric data')
    metric_data = [
        {
            'MetricName': 'AnalyzedBinaries',
            'Value': len(binaries),
            'Unit': 'Count'
        },
        {
            'MetricName': 'MatchedBinaries',
            'Value': sum(1 for b in binaries if b.yara_matches),
            'Unit': 'Count'
        },
        {
            'MetricName': 'YaraRules',
            'Value': num_yara_rules,
            'Unit': 'Count'
        },
        {
            'MetricName': 'S3DownloadLatency',
            'StatisticValues': _compute_statistics([b.download_time_ms for b in binaries]),
            'Unit': 'Milliseconds'
        }
    ]
    CLOUDWATCH.put_metric_data(Namespace='BinaryAlert', MetricData=metric_data)


class DynamoMatchTable:
    """Saves YARA match information into a Dynamo table.

    The table uses a composite key:
        SHA256 (str): [hash key] SHA256 digest computed over the binary blob.
        AnalyzerVersion (int): [range key] Analyzer Lambda version that found the match.

    Additionally, items have the following attributes:
        MatchedRules (Set[str]): A nonempty set of matched YARA rule names.
        MD5 (str): MD5 digest computed over the binary blob.
        S3LastModified (str): When the S3 object was last modified.
            This shows when the file was uploaded (assuming no other modifications).
        S3Metadata (Dict[str, str]): S3 object metadata for the first matching S3 object.
            If the downloader is enabled, this will include CarbonBlack metadata (e.g. filename).
        S3Objects (Set[str]): A set of S3 keys containing the corresponding binary.
            Duplicate uploads (multiple binaries with the same SHA) are allowed.
    """
    def __init__(self, table_name: str) -> None:
        """Establish connection to Dynamo.

        Args:
            table_name: The name of the Dynamo table containing match information.
        """
        self._table = DYNAMODB.Table(table_name)

    def _most_recent_item(self, sha: str) -> Optional[Tuple[int, Set[str], Set[str], Set[str]]]:
        """Query the table for the most recent entry with the given SHA.

        Args:
            sha: SHA256 to query.

        Returns:
            4-tuple: (AnalyzerVersion, MatchedRules, S3Objects, PreviousS3Objects)
            Returns None if there is no matching item.
        """
        most_recent_items = self._table.query(
            Select='SPECIFIC_ATTRIBUTES',
            Limit=2,  # We only need the most recent analyses.
            ConsistentRead=True,
            ScanIndexForward=False,  # Sort by AnalyzerVersion descending (e.g. newest first).
            ProjectionExpression='AnalyzerVersion,MatchedRules,S3Objects',
            KeyConditionExpression=Key('SHA256').eq(sha)
        ).get('Items')

        if most_recent_items:
            analyzer_version = int(most_recent_items[0]['AnalyzerVersion'])
            matched_rules = set(most_recent_items[0]['MatchedRules'])
            s3_objects = set(most_recent_items[0]['S3Objects'])
            # When re-analyzing all binaries, only one S3 object will be added to the DB at a time.
            # In order to prevent spurious alerts about new S3 objects, we report S3 objects from
            # the previous Lambda version as well.
            previous_s3_objects: Set[str] = set()
            if len(most_recent_items) >= 2:
                previous_s3_objects = set(most_recent_items[1]['S3Objects'])
            return analyzer_version, matched_rules, s3_objects, previous_s3_objects

        return None

    @staticmethod
    def _replace_empty_strings(data: Dict[str, str]) -> Dict[str, str]:
        """Replace empty string values, which are not allowed in Dynamo."""
        for key, val in data.items():
            if val == '':
                data[key] = '(empty)'
        return data

    def _create_new_entry(self, binary: BinaryInfo, analyzer_version: int) -> None:
        """Create a new Dynamo entry with YARA match information."""
        LOGGER.info('Creating new entry (SHA256: %s, AnalyzerVersion: %d)',
                    binary.computed_sha, analyzer_version)
        item = {
            'SHA256': binary.computed_sha,
            'AnalyzerVersion': analyzer_version,
            'MatchedRules': binary.matched_rule_ids,
            'MD5': binary.computed_md5,
            'S3LastModified': binary.s3_last_modified,
            'S3Metadata': self._replace_empty_strings(binary.s3_metadata),
            'S3Objects': {binary.s3_identifier}
        }
        try:
            self._table.put_item(Item=item)
        except ClientError:
            LOGGER.error('Error saving item %s', item)
            raise

    def _add_s3_key(self, binary: BinaryInfo, analyzer_version: int) -> None:
        """Add S3 key to an existing entry. If the S3 key already exists, this is a no-op."""
        LOGGER.info('Adding %s to existing entry (SHA256: %s, AnalyzerVersion: %d)',
                    binary.s3_identifier, binary.computed_sha, analyzer_version)
        self._table.update_item(
            Key={'SHA256': binary.computed_sha, 'AnalyzerVersion': analyzer_version},
            UpdateExpression='ADD S3Objects :s3_string_set',
            ExpressionAttributeValues={':s3_string_set': {binary.s3_identifier}}
        )

    def save_matches(self, binary: BinaryInfo, analyzer_version: int) -> bool:
        """Save YARA match results to the Dynamo table.

        Args:
            binary: Instance containing information about the binary.
            analyzer_version: Version of the currently executing Lambda function.

        Returns:
            Whether an alert should be fired. Returns True if:
                The current Lambda version is >= the most recent analysis version AND
                (a) Any YARA rule is matched now that was not matched in the previous version, OR
                (b) A new S3 object appears which is identical to an already matched binary.
        """
        needs_alert = False

        # Grab the most recent match results for the given SHA.
        item_tuple = self._most_recent_item(binary.computed_sha)

        if item_tuple is not None:
            # An entry already exists for this SHA.
            item_lambda_version, item_matched_rules, item_s3_objects, previous_objects = item_tuple

            # Update the DB appropriately.
            if analyzer_version != item_lambda_version:
                # This binary has never been matched by this Lambda version.
                self._create_new_entry(binary, analyzer_version)
            elif binary.s3_identifier not in item_s3_objects:
                # A new S3 object is identical to a previously-matched binary.
                self._add_s3_key(binary, analyzer_version)

            # Decide whether we need to alert.
            if analyzer_version < item_lambda_version:
                LOGGER.warning('Current Lambda version %d is < version %d from previous analysis',
                               analyzer_version, item_lambda_version)
            elif bool(binary.matched_rule_ids - item_matched_rules):
                # A new YARA rule matched this binary.
                needs_alert = True
            elif binary.s3_identifier not in item_s3_objects.union(previous_objects):
                # A new S3 object matched (which did not match in the previous version).
                needs_alert = True
        else:
            # This binary has never been matched before.
            self._create_new_entry(binary, analyzer_version)
            needs_alert = True

        return needs_alert
