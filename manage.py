"""Command-line tool for easily managing BinaryAlert."""
# Usage: python3 manage.py [--help] [command]
import argparse
import hashlib
import inspect
import os
import pprint
import subprocess
import sys
import time
import unittest
import uuid

import boto3
from boto3.dynamodb.conditions import Attr, Key
import hcl

from lambda_functions.build import build as lambda_build
from rules.update_rules import update_github_rules
from tests import boto3_mocks
from tests.rules.eicar_rule_test import EICAR_STRING

PROJECT_DIR = os.path.dirname(os.path.realpath(__file__))  # Directory containing this file.
TERRAFORM_DIR = os.path.join(PROJECT_DIR, 'terraform')
CONFIG_FILE = os.path.join(TERRAFORM_DIR, 'terraform.tfvars')

# Lambda alias terraform targets, to be updated separately.
LAMBDA_ALIASES_TERRAFORM_TARGETS = [
    '-target=module.binaryalert_{}.aws_lambda_alias.production_alias'.format(name)
    for name in ['analyzer', 'batcher', 'dispatcher']
]


class Manager(object):
    """BinaryAlert management utility."""

    def __init__(self, config_file):
        """Parse config and setup boto3.

        Args:
            config_file: [String] path to the terraform.tfvars configuration file.
        """
        with open(config_file) as f:
            self._config = hcl.load(f)

        boto3.setup_default_session(region_name=self._config['aws_region'])

    @property
    def commands(self):
        """Return set of available commands."""
        return {'apply', 'analyze_all', 'build', 'deploy', 'live_test', 'update_rules', 'test'}

    @property
    def help(self):
        """Return method docstring for each available command."""
        return '\n'.join(
            '{:<15}{}'.format(command, inspect.getdoc(getattr(self, command)))
            for command in sorted(self.commands)
        )

    def run(self, command):
        """Execute one of the available commands.

        Args:
            command: [String] Command in self.commands.
        """
        getattr(self, command)()  # Validation already happened in the ArgumentParser.

    @staticmethod
    def apply():
        """Terraform validate and apply any configuration/package changes."""
        # Validate and format the terraform files.
        os.chdir(TERRAFORM_DIR)
        subprocess.check_call(['terraform', 'validate'])
        subprocess.check_call(['terraform', 'fmt'])

        # Setup the backend if needed and reload modules.
        subprocess.check_call(['terraform', 'init'])

        # Apply changes.
        subprocess.check_call(['terraform', 'apply'])

        # A second apply is unfortunately necessary to update the Lambda aliases.
        print('\nRe-applying to update Lambda aliases...')
        subprocess.check_call(
            ['terraform', 'apply', '-refresh=false'] + LAMBDA_ALIASES_TERRAFORM_TARGETS)

    def analyze_all(self):
        """Start a batcher to asynchronously re-analyze the entire S3 bucket."""
        function_name = '{}_binaryalert_batcher'.format(self._config['name_prefix'])

        print('Asynchronously invoking {}...'.format(function_name))
        boto3.client('lambda').invoke(
            FunctionName=function_name,
            InvocationType='Event',  # Asynchronous invocation.
            Qualifier='Production'
        )
        print('Batcher invocation successful!')

    @staticmethod
    def build():
        """Build Lambda packages (saves *.zip files in terraform/)."""
        lambda_build(TERRAFORM_DIR)

    def deploy(self):
        """Deploy BinaryAlert. Equivalent to test + build + apply + analyze_all."""
        self.test()
        self.build()
        self.apply()
        self.analyze_all()

    def live_test(self):
        """Upload an EICAR test file to BinaryAlert which should trigger a YARA match alert."""
        bucket_name = '{}.binaryalert-binaries.{}'.format(
            self._config['name_prefix'].replace('_', '.'), self._config['aws_region'])
        test_filename = 'eicar_test_{}.txt'.format(uuid.uuid4())
        s3_identifier = 'S3:{}:{}'.format(bucket_name, test_filename)

        print('Uploading {}...'.format(s3_identifier))
        bucket = boto3.resource('s3').Bucket(bucket_name)
        bucket.put_object(
            Body=EICAR_STRING.encode('UTF-8'),
            Key=test_filename,
            Metadata={'observed_path': test_filename}
        )

        print('File uploaded! Waiting for new Dynamo entry to appear...')
        table_name = '{}_binaryalert_matches'.format(self._config['name_prefix'])
        table = boto3.resource('dynamodb').Table(table_name)
        eicar_sha256 = hashlib.sha256(EICAR_STRING.encode('UTF-8')).hexdigest()
        dynamo_record_found = False
        lambda_version = 0

        for attempt in range(1, 11):
            time.sleep(5)
            print('\t[{}/10] Scanning DynamoDB:{}...'.format(attempt, table_name))
            items = table.query(
                Select='ALL_ATTRIBUTES',
                Limit=1,
                ConsistentRead=True,
                ScanIndexForward=False,  # Sort by LambdaVersion descending (e.g. newest first).
                KeyConditionExpression=Key('SHA256').eq(eicar_sha256),
                FilterExpression=Attr('S3Objects').contains(s3_identifier)
            ).get('Items')
            if items:
                print('\tSUCCESS: Dynamo entry found!\n')
                dynamo_record_found = True
                lambda_version = items[0]['LambdaVersion']
                pprint.pprint(items[0])
                break
            elif attempt == 10:
                print('\nFAIL: Entry not found')

        print('\nRemoving EICAR test file from S3...')
        bucket.delete_objects(Delete={'Objects': [{'Key': test_filename}]})

        print('Removing Dynamo EICAR entry...')
        table.delete_item(Key={'SHA256': eicar_sha256, 'LambdaVersion': lambda_version})

        if dynamo_record_found:
            print('\nLive test succeeded! Verify the alert was sent to your SNS subscription(s).')
        else:
            sys.exit('\nLive test failed!')

    @staticmethod
    def update_rules():
        """Update YARA rules cloned from other open-source projects."""
        update_github_rules()

    @staticmethod
    @boto3_mocks.restore_http_adapter
    def test():
        """Run unit tests (*_test.py)."""
        suite = unittest.TestLoader().discover(PROJECT_DIR, pattern='*_test.py')
        test_result = unittest.TextTestRunner(verbosity=1).run(suite)
        if not test_result.wasSuccessful():
            sys.exit('Unit tests failed')  # Exit code 1


def main():
    """Main command dispatcher."""
    manager = Manager(CONFIG_FILE)

    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('command', choices=sorted(manager.commands), help=manager.help)
    args = parser.parse_args()

    manager.run(args.command)


if __name__ == '__main__':
    main()
