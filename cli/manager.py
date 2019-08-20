"""BinaryAlert management utility."""
from datetime import datetime, timedelta
import gzip
import inspect
import json
import multiprocessing
from multiprocessing import JoinableQueue
import os
import subprocess
import sys
from typing import Any, Callable, Dict, Generator, Iterable, Optional, Set, Tuple
import unittest

import boto3
import cbapi
from cbapi.response.models import Binary

from cli.config import get_input, BinaryAlertConfig, TERRAFORM_DIR
from cli.enqueue_task import EnqueueTask, Worker
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
    def _enqueue(
            queue_name: str, messages: Iterable[Dict[str, Any]],
            summary_func: Callable[[Dict[str, Any]], Tuple[int, str]]) -> None:
        """Use multiple worker processes to enqueue messages onto an SQS queue in batches.

        Args:
            queue_name: Name of the target SQS queue
            messages: Iterable of dictionaries, each representing a single SQS message body
            summary_func: Function from message to (item_count, summary) to show progress
        """
        num_workers = multiprocessing.cpu_count() * 4
        tasks: JoinableQueue = JoinableQueue(num_workers * 10)  # Max tasks waiting in queue

        # Create and start worker processes
        workers = [Worker(queue_name, tasks) for _ in range(num_workers)]
        for worker in workers:
            worker.start()

        # Create an EnqueueTask for each batch of 10 messages (max allowed by SQS)
        message_batch = []
        progress = 0  # Total number of relevant "items" processed so far
        for message_body in messages:
            count, summary = summary_func(message_body)
            progress += count
            print('\r{}: {:<90}'.format(progress, summary), end='', flush=True)

            message_batch.append(json.dumps(message_body, separators=(',', ':')))

            if len(message_batch) == 10:
                tasks.put(EnqueueTask(message_batch))
                message_batch = []

        # Add final batch of messages
        if message_batch:
            tasks.put(EnqueueTask(message_batch))

        # Add "poison pill" to mark the end of the task queue
        for _ in range(num_workers):
            tasks.put(None)

        tasks.join()
        print('\nDone!')

    @staticmethod
    def apply() -> None:
        """Apply any configuration/package changes with Terraform"""
        os.chdir(TERRAFORM_DIR)
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
            url=self._config.carbon_black_url,
            timeout=self._config.carbon_black_timeout,
            token=self._config.plaintext_carbon_black_api_token
        )

        self._enqueue(
            self._config.binaryalert_downloader_queue_name,
            ({'md5': binary.md5} for binary in carbon_black.select(Binary).all()),
            lambda msg: (1, msg['md5'])
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
        """Find the most recent S3 inventory manifest.

        Args:
            bucket: BinaryAlert S3 bucket resource

        Returns:
            Object key for the most recent inventory manifest.
            Returns None if no inventory report was found from the last 8 days
        """
        today = datetime.today()
        inv_prefix = 'inventory/{}/EntireBucketDaily'.format(bucket.name)

        # Check for each day, starting today, up to 3 days ago
        for days_ago in range(4):
            date = today - timedelta(days=days_ago)
            prefix = '{}/{}-{:02}-{:02}'.format(inv_prefix, date.year, date.month, date.day)
            for object_summary in bucket.objects.filter(Prefix=prefix):
                if object_summary.key.endswith('/manifest.json'):
                    return object_summary.key
        return None

    @staticmethod
    def _inventory_object_iterator(
            bucket: boto3.resource, manifest_path: str) -> Generator[str, None, None]:
        """Yield S3 object keys listed in the inventory.

        Args:
            bucket: BinaryAlert S3 bucket resource
            manifest_path: S3 object key for an inventory manifest.json

        Yields:
            Object keys listed in the inventory
        """
        response = bucket.Object(manifest_path).get()
        manifest = json.loads(response['Body'].read())

        # The manifest contains a list of .csv.gz files, each with a list of object keys
        for record in manifest['files']:
            response = bucket.Object(record['key']).get()
            csv_data = gzip.decompress(response['Body'].read()).decode('utf-8')
            for line in csv_data.strip().split('\n'):
                yield line.split(',')[1].strip('"')

    def _s3_batch_iterator(
            self, object_keys: Iterable[str]) -> Generator[Dict[str, Any], None, None]:
        """Group multiple S3 objects into a single SQS message.

        Args:
            object_keys: Generator of S3 object keys

        Yields:
            A dictionary representing an SQS message
        """
        records = []

        for key in object_keys:
            records.append({
                's3': {
                    'bucket': {
                        'name': self._config.binaryalert_s3_bucket_name
                    },
                    'object': {
                        'key': key
                    }
                }
            })

            if len(records) == self._config.retro_batch_size:
                yield {'Records': records}
                records = []

        if records:  # Final batch
            yield {'Records': records}

    @staticmethod
    def _s3_msg_summary(sqs_message: Dict[str, Any]) -> Tuple[int, str]:
        """Return a short summary string about this SQS message"""
        last_key = sqs_message['Records'][-1]['s3']['object']['key']
        summary = last_key if len(last_key) <= 80 else '...{}'.format(last_key[-80:])
        return len(sqs_message['Records']), summary

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
            self._s3_batch_iterator(self._inventory_object_iterator(bucket, manifest_path)),
            self._s3_msg_summary
        )

    def retro_slow(self) -> None:
        """Enumerate the entire S3 bucket for slow retroactive analysis"""
        bucket = boto3.resource('s3').Bucket(self._config.binaryalert_s3_bucket_name)
        key_iterator = (summary.key for summary in bucket.objects.all())

        self._enqueue(
            self._config.binaryalert_analyzer_queue_name,
            self._s3_batch_iterator(key_iterator),
            self._s3_msg_summary
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
