"""Keeps track of all information associated with and computed about a binary."""
import os
import subprocess
import tempfile
import time
from typing import Any, Dict, List, Set
import uuid

from lambda_functions.analyzer import analyzer_aws_lib, file_hash
from lambda_functions.analyzer.common import LOGGER
from lambda_functions.analyzer.yara_analyzer import YaraAnalyzer, YaraMatch


class BinaryInfo:
    """Organizes the analysis of a single binary blob in S3."""

    def __init__(self, bucket_name: str, object_key: str, yara_analyzer: YaraAnalyzer) -> None:
        """Create a new BinaryInfo.

        Args:
            bucket_name: S3 bucket name.
            object_key: S3 object key.
            yara_analyzer: Analyzer built from a compiled rules file.
        """
        self.bucket_name = bucket_name
        self.object_key = object_key
        self.s3_identifier = 'S3:{}:{}'.format(bucket_name, object_key)

        self.download_path = os.path.join(
            tempfile.gettempdir(), 'binaryalert_{}'.format(uuid.uuid4()))
        self.yara_analyzer = yara_analyzer

        # Computed after file download and analysis.
        self.download_time_ms = 0.0
        self.s3_last_modified = ''
        self.s3_metadata: Dict[str, str] = dict()
        self.computed_md5 = ''
        self.computed_sha = ''
        self.yara_matches: List[YaraMatch] = list()

    def __str__(self) -> str:
        """Use the S3 identifier as the string representation of the binary."""
        return self.s3_identifier

    def _download_from_s3(self) -> None:
        """Download binary from S3 and measure elapsed time."""
        LOGGER.debug('Downloading %s to %s', self.object_key, self.download_path)

        start_time = time.time()
        self.s3_last_modified, self.s3_metadata = analyzer_aws_lib.download_from_s3(
            self.bucket_name, self.object_key, self.download_path)
        self.download_time_ms = (time.time() - start_time) * 1000

    def __enter__(self) -> Any:  # mypy/typing doesn't support recursive type yet
        """Download the binary from S3 and run YARA analysis."""
        self._download_from_s3()
        self.computed_sha, self.computed_md5 = file_hash.compute_hashes(self.download_path)

        LOGGER.debug('Running YARA analysis')
        self.yara_matches = self.yara_analyzer.analyze(
            self.download_path, original_target_path=self.filepath
        )

        return self

    def __exit__(self, exception_type: Any, exception_value: Any, traceback: Any) -> None:
        """Shred and delete all /tmp files (including the downloaded binary)."""
        # Note: This runs even during exception handling (it is the "with" context).
        # The only temp file we explicitly create is self.download_path, but others can be left
        # behind by subprocesses (e.g. pdftotext).
        for root, dirs, files in os.walk(tempfile.gettempdir(), topdown=False):
            for name in files:
                subprocess.check_call(['shred', '--force', '--remove', os.path.join(root, name)])
            for name in dirs:
                os.rmdir(os.path.join(root, name))

    @property
    def matched_rule_ids(self) -> Set[str]:
        """A set of 'yara_file:rule_name' for each YARA match."""
        return set('{}:{}'.format(match.rule_namespace, match.rule_name)
                   for match in self.yara_matches)

    @property
    def filepath(self) -> str:
        """The filepath from the S3 metadata, if present."""
        return self.s3_metadata.get('filepath', '')

    def save_matches_and_alert(
            self, analyzer_version: int, dynamo_table_name: str, sns_topic_arn: str,
            sns_enabled: bool = True) -> None:
        """Save match results to Dynamo and publish an alert to SNS if appropriate.

        Args:
            analyzer_version: The currently executing version of the Lambda function.
            dynamo_table_name: Save YARA match results to this Dynamo table.
            sns_topic_arn: Publish match alerts to this SNS topic ARN.
            sns_enabled: If True, match alerts are sent to SNS when applicable.
        """
        table = analyzer_aws_lib.DynamoMatchTable(dynamo_table_name)
        needs_alert = table.save_matches(self, analyzer_version)

        # Send alert if appropriate.
        if needs_alert and sns_enabled:
            LOGGER.info('Publishing a YARA match alert to %s', sns_topic_arn)
            subject = '[BinaryAlert] {} matches a YARA rule'.format(
                self.filepath or self.computed_sha)
            analyzer_aws_lib.publish_to_sns(self, sns_topic_arn, subject)

    def publish_negative_match_result(self, sns_topic_arn: str) -> None:
        """Publish a negative match result (no YARA matches found).

        Args:
            sns_topic_arn: Target topic ARN for negative match alerts.
        """
        LOGGER.info('Publishing a negative match result to %s', sns_topic_arn)
        subject = '[BinaryAlert] {} did not match any YARA rules'.format(
            self.filepath or self.computed_sha)
        analyzer_aws_lib.publish_to_sns(self, sns_topic_arn, subject)

    def summary(self) -> Dict[str, Any]:
        """Generate a summary dictionary of binary attributes."""
        matched_rules = {
            'Rule{}'.format(index): {
                'MatchedData': list(sorted(match.matched_data)),  # E.g. "HelloWorld"
                'MatchedStrings': list(sorted(match.matched_strings)),  # E.g. "$string1"
                'Meta': match.rule_metadata,
                'RuleFile': match.rule_namespace,
                'RuleName': match.rule_name
            }
            for index, match in enumerate(self.yara_matches, start=1)
        }

        return {
            'FileInfo': {
                # TODO: Include archive structure from yextend
                'MD5': self.computed_md5,
                'S3LastModified': self.s3_last_modified,
                'S3Location': self.s3_identifier,
                'S3Metadata': self.s3_metadata,
                'SHA256': self.computed_sha
            },
            'MatchedRules': matched_rules,
            'NumMatchedRules': len(self.yara_matches)
        }
