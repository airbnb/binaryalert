"""BinaryAlert management utility."""
from datetime import datetime, timedelta
import gzip
import inspect
import json
import os
import subprocess
import sys
from typing import Any, Callable, Dict, Generator, Iterable, Optional, Set
import unittest

import boto3
import cbapi
from cbapi.response.models import Binary

from cli.config import get_input, BinaryAlertConfig, TERRAFORM_DIR
from cli.exceptions import InvalidConfigError, TestFailureError
from lambda_functions.analyzer.common import COMPILED_RULES_FILENAME
from lambda_functions.build import build as lambda_build
from rules import compile_rules, clone_rules
from tests import live_test


class Manager:
    """BinaryAlert management utility."""
    def __init__(self) -> None:
        """Parse the terraform.tfvars config file."""
        self._config = BinaryAlertConfig()

    @property
    def commands(self) -> Set[str]:
        """Return set of available management commands."""
        return {'apply', 'build', 'cb_copy_all', 'clone_rules', 'compile_rules', 'configure',
                'deploy', 'destroy', 'live_test', 'purge_queue', 'retro_fast', 'retro_slow',
                'unit_test'}

    @property
    def help(self) -> str:
        """Return method docstring for each available command."""
        return '\n'.join(
            # Use the first line of each docstring for the CLI help output.
            '{:<15}{}'.format(command, inspect.getdoc(getattr(self, command)).split('\n')[0])
            for command in sorted(self.commands)
        )

    def run(self, command: str) -> None:
        """Execute one of the available commands.

        Args:
            command: Command in self.commands.
        """
        boto3.setup_default_session(region_name=self._config.aws_region)

        # Validate the configuration.
        try:
            if command not in {'clone_rules', 'compile_rules', 'configure', 'unit_test'}:
                self._config.validate()
            getattr(self, command)()  # Command validation already happened in the ArgumentParser.
        except InvalidConfigError as error:
            sys.exit('ERROR: {}\nPlease run "python3 manage.py configure"'.format(error))
        except TestFailureError as error:
            sys.exit('TEST FAILED: {}'.format(error))

    @staticmethod
    def _enqueue(queue_name: str,
                 collection: Iterable[Any],
                 key_func: Callable[[Any], str],
                 body_func: Callable[[str], Dict[str, Any]]) -> None:
        """Enumerate a collection of items onto an SQS queue."""
        queue = boto3.resource('sqs').get_queue_by_name(QueueName=queue_name)
        keys = []

        for index, element in enumerate(collection):
            element_key = key_func(element)  # MD5 or object key
            print('\r{} {:<120}'.format(index, element_key), flush=True, end='')
            keys.append(element_key)

            if len(keys) == 10:
                response = queue.send_messages(
                    Entries=[
                        {'Id': str(i), 'MessageBody': json.dumps(body_func(key))}
                        for i, key in enumerate(keys)
                    ]
                )
                # If there were any failures sending to SQS, put those back in the md5s list.
                keys = [keys[int(failure['Id'])] for failure in response.get('Failed', [])]

        print()  # Print final newline when finished

    @staticmethod
    def apply() -> None:
        """Apply any configuration/package changes with Terraform"""
        # Validate and format the terraform files.
        os.chdir(TERRAFORM_DIR)

        # Setup the backend if needed and reload modules.
        subprocess.check_call(['terraform', 'init'])

        subprocess.check_call(['terraform', 'fmt'])

        # Apply changes (requires interactive approval)
        subprocess.check_call(['terraform', 'apply', '-auto-approve=false'])

    def build(self) -> None:
        """Build Lambda packages (saves *.zip files in terraform/)"""
        lambda_build(TERRAFORM_DIR, self._config.enable_carbon_black_downloader == 1)

    def cb_copy_all(self) -> None:
        """Copy all binaries from CarbonBlack Response into BinaryAlert

        Raises:
            InvalidConfigError: If the CarbonBlack downloader is not enabled.
        """
        if not self._config.enable_carbon_black_downloader:
            raise InvalidConfigError('CarbonBlack downloader is not enabled.')

        print('Connecting to CarbonBlack server {} ...'.format(self._config.carbon_black_url))
        carbon_black = cbapi.CbResponseAPI(
            url=self._config.carbon_black_url, token=self._config.plaintext_carbon_black_api_token)

        self._enqueue(
            self._config.binaryalert_downloader_queue_name,
            carbon_black.select(Binary).all(),
            lambda binary: binary.md5,
            lambda md5: {'md5': md5}
        )

    @staticmethod
    def clone_rules() -> None:
        """Clone YARA rules from other open-source projects"""
        clone_rules.clone_remote_rules()

    @staticmethod
    def compile_rules() -> None:
        """Compile all of the YARA rules into a single binary file"""
        compile_rules.compile_rules(COMPILED_RULES_FILENAME)
        print('Compiled rules saved to {}'.format(COMPILED_RULES_FILENAME))

    def configure(self) -> None:
        """Update basic configuration, including region, prefix, and downloader settings"""
        self._config.configure()
        print('Updated configuration successfully saved to terraform/terraform.tfvars!')

    def deploy(self) -> None:
        """Deploy BinaryAlert (equivalent to unit_test + build + apply)"""
        self.unit_test()
        self.build()
        self.apply()

    def destroy(self) -> None:
        """Teardown all of the BinaryAlert infrastructure"""
        os.chdir(TERRAFORM_DIR)

        if not self._config.force_destroy:
            result = get_input('Delete all S3 objects as well?', 'no')

            if result not in {'yes', 'no'}:
                sys.exit('Please answer exactly "yes" or "no"')

            if result == 'yes':
                print('Enabling force_destroy on the BinaryAlert S3 buckets...')
                subprocess.check_call([
                    'terraform', 'apply', '-auto-approve=true', '-refresh=false',
                    '-var', 'force_destroy=true',
                    '-target', 'aws_s3_bucket.binaryalert_binaries',
                    '-target', 'aws_s3_bucket.binaryalert_log_bucket'
                ])

        subprocess.call(['terraform', 'destroy'])

    def live_test(self) -> None:
        """Upload test files to BinaryAlert which should trigger YARA matches

        Raises:
            TestFailureError: If the live test failed (YARA matches not found).
        """
        if not live_test.run(self._config.binaryalert_s3_bucket_name,
                             self._config.binaryalert_analyzer_name,
                             self._config.binaryalert_dynamo_table_name):
            raise TestFailureError(
                '\nLive test failed! See https://binaryalert.io/troubleshooting-faq.html')

    def purge_queue(self) -> None:
        """Purge the analysis SQS queue (e.g. to stop a retroactive scan)"""
        queue = boto3.resource('sqs').get_queue_by_name(
            QueueName=self._config.binaryalert_analyzer_queue_name)
        queue.purge()

    @staticmethod
    def _most_recent_manifest(bucket: boto3.resource) -> Optional[str]:
        """Find the most recent S3 inventory manifest."""
        today = datetime.today()
        inv_prefix = 'inventory/{}/EntireBucketDaily'.format(bucket.name)

        # Check for each day, starting today, up to 8 days ago
        for days_ago in range(0, 9):
            date = today - timedelta(days=days_ago)
            prefix = '{}/{}-{:02}-{:02}'.format(inv_prefix, date.year, date.month, date.day)
            for object_summary in bucket.objects.filter(Prefix=prefix):
                if object_summary.key.endswith('/manifest.json'):
                    return object_summary.key
        return None

    @staticmethod
    def _enumerate_inventory(
            bucket: boto3.resource, manifest_path: str) -> Generator[str, None, None]:
        """Yield lines from the S3 inventory."""
        response = bucket.Object(manifest_path).get()
        manifest = json.loads(response['Body'].read())

        # The manifest contains a list of .csv.gz files, each with a list of object keys
        for record in manifest['files']:
            response = bucket.Object(record['key']).get()
            csv_data = gzip.decompress(response['Body'].read()).decode('utf-8')
            yield from csv_data.strip().split('\n')

    def _sqs_body(self, object_key: str) -> Dict[str, Any]:
        """Convert an S3 object key to an SQS message body."""
        return {
            'Records': [
                {
                    's3': {
                        'bucket': {
                            'name': self._config.binaryalert_s3_bucket_name
                        },
                        'object': {
                            'key': object_key
                        }
                    }
                }
            ]
        }

    def retro_fast(self) -> None:
        """Enumerate the most recent S3 inventory for fast retroactive analysis"""
        bucket = boto3.resource('s3').Bucket(self._config.binaryalert_s3_bucket_name)

        manifest_path = self._most_recent_manifest(bucket)
        if not manifest_path:
            print('ERROR: No inventory manifest found in the last week')
            print('You can run "./manage.py retro_slow" to manually enumerate the bucket')
            return

        print('Reading {}'.format(manifest_path))
        self._enqueue(
            self._config.binaryalert_analyzer_queue_name,
            self._enumerate_inventory(bucket, manifest_path),
            lambda line: line.split(',')[1].strip('"'),
            self._sqs_body
        )

    def retro_slow(self) -> None:
        """Enumerate the entire S3 bucket for slow retroactive analysis"""
        bucket = boto3.resource('s3').Bucket(self._config.binaryalert_s3_bucket_name)
        self._enqueue(
            self._config.binaryalert_analyzer_queue_name,
            bucket.objects.all(),
            lambda summary: summary.key,
            self._sqs_body
        )

    @staticmethod
    def unit_test() -> None:
        """Run unit tests (*_test.py)

        Raises:
            TestFailureError: If any of the unit tests failed.
        """
        repo_root = os.path.join(TERRAFORM_DIR, '..')
        suite = unittest.TestLoader().discover(repo_root, pattern='*_test.py')
        test_result = unittest.TextTestRunner(verbosity=1).run(suite)
        if not test_result.wasSuccessful():
            raise TestFailureError('Unit tests failed')
