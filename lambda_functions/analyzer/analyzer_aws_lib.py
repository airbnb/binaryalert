"""Collection of boto3 calls to AWS resources for the analyzer function."""
import json
import logging

import boto3

LOGGER = logging.getLogger()
SNS_PUBLISH_SUBJECT_MAX_SIZE = 99


def download_from_s3(bucket_name, object_key, download_path):
    """Download an object from S3 into local /tmp storage.

    Args:
        bucket_name: [string] S3 bucket name.
        object_key: [string] S3 object key.
        download_path: [string] Where to download the file locally.

    Returns:
        [dict] S3 metadata.
    """
    response = boto3.client('s3').get_object(Bucket=bucket_name, Key=object_key)
    with open(download_path, 'wb') as file:
        file.write(response['Body'].read())

    return response['Metadata']


def _elide_string_middle(text, max_length):
    """Replace the middle of the text with ellipses to shorten text to the desired length.

    Args:
        text: [string] Text to shorten.
        max_length: [int] Maximum allowable length of the string.

    Returns:
        [string] The elided text, e.g. "Some really long tex ... the end."
    """
    if len(text) <= max_length:
        return text

    half_len = (max_length - 5) // 2  # Length of text on either side.
    return '{} ... {}'.format(text[:half_len], text[-half_len:])


def publish_alert_to_sns(binary, topic_arn):
    """Publish a JSON SNS alert: a binary has matched one or more YARA rules.

    Args:
        binary: [BinaryInfo] Instance containing information about the binary.
        topic_arn: [string] Publish to this SNS topic ARN.
    """
    subject = 'BinaryAlert: {} matches a YARA rule'.format(
        binary.observed_path or binary.reported_md5 or binary.computed_md5)
    boto3.client('sns').publish(
        TopicArn=topic_arn,
        Subject=_elide_string_middle(subject, SNS_PUBLISH_SUBJECT_MAX_SIZE),
        Message=(json.dumps(binary.summary(), indent=4, sort_keys=True))
    )


def delete_sqs_messages(queue_url, receipts):
    """Mark a batch of SQS receipts as completed (removing them from the queue).

    Args:
        queue_url: [string] The URL of the SQS queue containing the messages.
        receipts: [list<string>] List of SQS receipt handles.
    """
    LOGGER.info('Deleting %d SQS receipt(s) from %s', len(receipts), queue_url)
    boto3.client('sqs').delete_message_batch(
        QueueUrl=queue_url,
        Entries=[
            {'Id': str(index), 'ReceiptHandle': receipt} for index, receipt in enumerate(receipts)]
    )


def _compute_statistics(values):
    """Compute summary statistics for a collection of values.

    Args:
        values: [list] of numeric values in the sample set.

    Returns:
        [dict] designed to be published as CloudWatch metric statistics.
    """
    return {
        'SampleCount': len(values),
        'Sum': sum(values),
        'Minimum': min(values),
        'Maximum': max(values)
    }


def put_metric_data(num_yara_rules, binaries):
    """Publish custom metric data to CloudWatch.

    Args:
        num_yara_rules: [string] Number of YARA rules in the analyzer.
        binaries: [list of BinaryInfo()] List of analyzed BinaryInfo()s.
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
    boto3.client('cloudwatch').put_metric_data(Namespace='BinaryAlert', MetricData=metric_data)


class DynamoMatchTable(object):
    """Saves YARA match information into a Dynamo table.

    The table uses a composite key:
        SHA256: [string] [hash key] SHA256 digest computed over the binary blob.
        LambdaVersion: [int] [range key] Lambda version that found the match.

    Additionally, items have the following attributes:
        MD5_Computed: [string] MD5 digest computed over the binary blob.
        MD5_Reported: [string] (optional) User-specified MD5 in the S3 object metadata.
            Allows the user to upload a partial binary and still retain the original MD5, e.g. for
            lookup in other incident response tools.
        MatchedRules: [string set] A nonempty set of matched YARA rule names.
        SamplePath: [string] (optional) User-specified observed filepath in the S3 object metadata.
        S3Objects: [string set] A set of S3 keys containing the corresponding binary.
            Duplicate uploads (multiple binaries with the same SHA) are allowed.
    """
    def __init__(self, table_name):
        """Establish connection to Dynamo.

        Args:
            table_name: [string] The name of the Dynamo table containing match information.
        """
        self._table_name = table_name
        self._client = boto3.client('dynamodb')

    def _most_recent_item(self, sha):
        """Query the table for the most recent entry with the given SHA.

        Args:
            sha: [string] SHA256 to query.

        Returns:
            3-tuple: ([int] LambdaVersion, [set] MatchedRules, [set] S3Objects)
            Returns None if there is no matching item.
        """
        most_recent_item = self._client.query(
            TableName=self._table_name,
            Select='SPECIFIC_ATTRIBUTES',
            Limit=2,  # We only need the most recent analyses.
            ConsistentRead=True,
            ScanIndexForward=False,  # Sort by LambdaVersion descending (e.g. newest first).
            ProjectionExpression='LambdaVersion,MatchedRules,S3Objects',
            KeyConditionExpression='SHA256 = :sha',
            ExpressionAttributeValues={':sha': {'S': sha}}
        ).get('Items')

        if most_recent_item:
            lambda_version = int(most_recent_item[0]['LambdaVersion']['N'])
            matched_rules = set(most_recent_item[0]['MatchedRules']['SS'])
            s3_objects = set(most_recent_item[0]['S3Objects']['SS'])
            # When re-analyzing all binaries, only one S3 object will be added to the DB at a time.
            # In order to prevent spurious alerts about new S3 objects, we report S3 objects from
            # the previous two Lambda versions. #Hacktastic!
            if len(most_recent_item) >= 2:
                s3_objects = s3_objects.union(set(most_recent_item[1]['S3Objects']['SS']))
            return lambda_version, matched_rules, s3_objects
        else:
            return None

    def _create_new_entry(self, binary, lambda_version):
        """Create a new Dynamo entry with YARA match information."""
        LOGGER.info('Creating new entry (SHA256: %s, LambdaVersion: %d)',
                    binary.computed_sha, lambda_version)
        item = {
            'SHA256': {'S': binary.computed_sha},
            'LambdaVersion': {'N': str(lambda_version)},
            'MD5_Computed': {'S': binary.computed_md5},
            'MatchedRules': {'SS': binary.matched_rule_ids},
            'S3Objects': {'SS': [binary.s3_identifier]}
        }
        if binary.reported_md5:
            item['MD5_Reported'] = {'S': binary.reported_md5}
        if binary.observed_path:
            item['SamplePath'] = {'S': binary.observed_path}

        self._client.put_item(TableName=self._table_name, Item=item)

    def _add_s3_key(self, binary, lambda_version):
        """Add S3 key to an existing entry. If the S3 key already exists, this is a no-op."""
        LOGGER.info('Adding %s to existing entry (SHA256: %s, LambdaVersion: %d)',
                    binary.s3_identifier, binary.computed_sha, lambda_version)
        self._client.update_item(
            TableName=self._table_name,
            Key={'SHA256': {'S': binary.computed_sha}, 'LambdaVersion': {'N': str(lambda_version)}},
            UpdateExpression='ADD S3Objects :s3_string_set',
            ExpressionAttributeValues={':s3_string_set': {'SS': [binary.s3_identifier]}}
        )

    def save_matches(self, binary, lambda_version):
        """Save YARA match results to the Dynamo table.

        Args:
            binary: [BinaryInfo] Instance containing information about the binary.
            lambda_version: [int] Version of the currently executing Lambda function.

        Returns:
            [boolean] Whether an alert should be fired. Returns True if:
                The current Lambda version is >= the most recent analysis version AND
                (a) Any YARA rule is matched now that was not matched in the previous version, OR
                (b) A new S3 object appears which is identical to an already matched binary.
        """
        needs_alert = False

        # Grab the most recent match results for the given SHA.
        item_tuple = self._most_recent_item(binary.computed_sha)

        if item_tuple is not None:
            # An entry already exists for this SHA.
            item_lambda_version, item_matched_rules, item_s3_objects = item_tuple

            # Update the DB appropriately.
            if lambda_version != item_lambda_version:
                # This binary has never been matched by this Lambda version.
                self._create_new_entry(binary, lambda_version)
            elif binary.s3_identifier not in item_s3_objects:
                # A new S3 object is identical to a previously-matched binary.
                self._add_s3_key(binary, lambda_version)

            # Decide whether we need to alert.
            if lambda_version < item_lambda_version:
                LOGGER.warning('Current Lambda version %d is < version %d from previous analysis',
                               lambda_version, item_lambda_version)
            elif (bool(set(binary.matched_rule_ids) - item_matched_rules) or
                  binary.s3_identifier not in item_s3_objects):
                # Either a new YARA rule matched or a new S3 object was found.
                needs_alert = True
        else:
            # This binary has never been matched before.
            self._create_new_entry(binary, lambda_version)
            needs_alert = True

        return needs_alert
