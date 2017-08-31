"""Command-line tool for easily managing BinaryAlert."""
# Usage: python3 manage.py [--help] [command]
import argparse
import base64
import getpass
import hashlib
import inspect
import os
import pprint
import re
import subprocess
import sys
import time
from typing import Set
import unittest
import uuid

import boto3
from boto3.dynamodb.conditions import Attr, Key
import hcl

from lambda_functions.build import build as lambda_build
from rules.update_rules import update_github_rules
from tests import boto3_mocks
from tests.rules.eicar_rule_test import EICAR_STRING

# File locations.
PROJECT_DIR = os.path.dirname(os.path.realpath(__file__))  # Directory containing this file.
TERRAFORM_DIR = os.path.join(PROJECT_DIR, 'terraform')
CONFIG_FILE = os.path.join(TERRAFORM_DIR, 'terraform.tfvars')
VARIABLES_FILE = os.path.join(TERRAFORM_DIR, 'variables.tf')

# Terraform identifiers.
CB_KMS_ALIAS_TERRAFORM_ID = 'aws_kms_alias.encrypt_credentials_alias'
LAMBDA_ALIASES_TERRAFORM_IDS = [
    'module.binaryalert_{}.aws_lambda_alias.production_alias'.format(name)
    for name in ['analyzer', 'batcher', 'dispatcher', 'downloader']
]

CB_KEY_ALIAS_NAME_TEMPLATE = 'alias/{}_binaryalert_carbonblack_credentials'


class ManagerError(Exception):
    """Top-level exception for Manager errors."""
    pass


class InvalidConfigError(ManagerError):
    """BinaryAlert config is not valid."""
    pass


class TestFailureError(ManagerError):
    """Exception raised when a BinaryAlert test fails."""
    pass


class BinaryAlertConfig(object):
    """Wrapper around reading, validating, and updating the terraform.tfvars config file."""
    # Expected configuration value formats.
    VALID_AWS_REGION_FORMAT = r'[a-z]{2}-[a-z]{2,15}-\d'
    VALID_NAME_PREFIX_FORMAT = r'[a-z][a-z0-9_]{3,50}'
    VALID_CB_API_TOKEN_FORMAT = r'[a-f0-9]{40}'  # CarbonBlack API token.
    VALID_CB_ENCRYPTED_TOKEN_FORMAT = r'\S{50,500}'
    VALID_CB_URL_FORMAT = r'https?://\S+'

    def __init__(self):
        """Parse the terraform.tfvars config file and make sure it contains every variable.

        Raises:
            InvalidConfigError: If any variable is defined in variables.tf but not terraform.tfvars.
        """
        with open(CONFIG_FILE) as f:
            self._config = hcl.load(f)  # Dict[str, Union[int, str]]

        with open(VARIABLES_FILE) as f:
            variable_names = hcl.load(f)['variable'].keys()

        for variable in variable_names:
            # Verify that the variable is defined.
            if variable not in self._config:
                raise InvalidConfigError(
                    'variable "{}" is not defined in {}'.format(variable, CONFIG_FILE)
                )

    @property
    def aws_region(self) -> str:
        return self._config['aws_region']

    @aws_region.setter
    def aws_region(self, value: str):
        if not re.fullmatch(self.VALID_AWS_REGION_FORMAT, value, re.ASCII):
            raise InvalidConfigError(
                'aws_region "{}" does not match format {}'.format(
                    value, self.VALID_AWS_REGION_FORMAT)
            )
        self._config['aws_region'] = value

    @property
    def name_prefix(self) -> str:
        return self._config['name_prefix']

    @name_prefix.setter
    def name_prefix(self, value: str):
        if not re.fullmatch(self.VALID_NAME_PREFIX_FORMAT, value, re.ASCII):
            raise InvalidConfigError(
                'name_prefix "{}" does not match format {}'.format(
                    value, self.VALID_NAME_PREFIX_FORMAT)
            )
        self._config['name_prefix'] = value

    @property
    def enable_carbon_black_downloader(self) -> int:
        return self._config['enable_carbon_black_downloader']

    @enable_carbon_black_downloader.setter
    def enable_carbon_black_downloader(self, value: int):
        if value not in {0, 1}:
            raise InvalidConfigError(
                'enable_carbon_black_downloader "{}" must be either 0 or 1.'.format(value)
            )
        self._config['enable_carbon_black_downloader'] = value

    @property
    def carbon_black_url(self) -> str:
        return self._config['carbon_black_url']

    @carbon_black_url.setter
    def carbon_black_url(self, value: str):
        if not re.fullmatch(self.VALID_CB_URL_FORMAT, value, re.ASCII):
            raise InvalidConfigError(
                'carbon_black_url "{}" does not match format {}'.format(
                    value, self.VALID_CB_URL_FORMAT)
            )
        self._config['carbon_black_url'] = value

    @property
    def encrypted_carbon_black_api_token(self) -> str:
        return self._config['encrypted_carbon_black_api_token']

    @encrypted_carbon_black_api_token.setter
    def encrypted_carbon_black_api_token(self, value: str):
        if not re.fullmatch(self.VALID_CB_ENCRYPTED_TOKEN_FORMAT, value, re.ASCII):
            raise InvalidConfigError(
                'encrypted_carbon_black_url "{}" does not match format {}'.format(
                    value, self.VALID_CB_ENCRYPTED_TOKEN_FORMAT
                )
            )
        self._config['encrypted_carbon_black_api_token'] = value

    @property
    def binaryalert_batcher_name(self) -> str:
        return '{}_binaryalert_batcher'.format(self.name_prefix)

    @property
    def binaryalert_s3_bucket_name(self) -> str:
        return '{}.binaryalert-binaries.{}'.format(
            self.name_prefix.replace('_', '.'), self.aws_region
        )

    @staticmethod
    def _get_input(prompt: str, default_value: str) -> str:
        """Wrapper around input() which shows the current (default value)."""
        if default_value:
            prompt = '{} ({}): '.format(prompt, default_value)
        else:
            prompt = '{}: '.format(prompt)
        return input(prompt).strip().lower() or default_value

    def _encrypt_cb_api_token(self) -> None:
        """Save an encrypted CarbonBlack API token.

        This Terraforms the KMS keys required to encrypt the token.
        """
        # Request API token using password-style input (will not be displayed on screen).
        while True:
            api_token = getpass.getpass(
                'CarbonBlack API token (only needs binary read access): ').strip().lower()
            if re.fullmatch(self.VALID_CB_API_TOKEN_FORMAT, api_token, re.ASCII):
                break
            else:
                print('ERROR: {}-character input does not match expected token format {}'.format(
                    len(api_token), self.VALID_CB_API_TOKEN_FORMAT
                ))

        # We need the KMS key to encrypt the API token.
        # The same key will be used by the downloader to decrypt the API token at runtime.
        print('Terraforming KMS key...')
        os.chdir(TERRAFORM_DIR)
        subprocess.check_call(
            ['terraform', 'apply', '-target={}'.format(CB_KMS_ALIAS_TERRAFORM_ID)]
        )

        print('Encrypting API token...')
        response = boto3.client('kms').encrypt(
            KeyId=CB_KEY_ALIAS_NAME_TEMPLATE.format(self.name_prefix), Plaintext=api_token
        )
        self.encrypted_carbon_black_api_token = base64.b64encode(
            response['CiphertextBlob']).decode('utf-8')

    def configure(self) -> None:
        """Request basic configuration settings from the user.

        Each request will be retried until the answer is in the correct format.
        """
        while True:  # Get AWS region.
            try:
                self.aws_region = self._get_input('AWS Region', self.aws_region)
                break
            except InvalidConfigError as error:
                print('ERROR: {}'.format(error))

        while True:  # Get name prefix.
            try:
                self.name_prefix = self._get_input(
                    'Unique name prefix, e.g. "company_team"', self.name_prefix
                )
                break
            except InvalidConfigError as error:
                print('ERROR: {}'.format(error))

        while True:  # Enable downloader?
            enable_downloader = self._get_input(
                'Enable the CarbonBlack downloader [yes/no]?',
                'yes' if self.enable_carbon_black_downloader else 'no'
            )
            if enable_downloader in {'yes', 'no'}:
                break
            else:
                print('ERROR: Please enter exactly "yes" or "no"')
        self.enable_carbon_black_downloader = 1 if enable_downloader == 'yes' else 0

        if self.enable_carbon_black_downloader:
            while True:  # CarbonBlack URL
                try:
                    self.carbon_black_url = self._get_input(
                        'CarbonBlack URL', self.carbon_black_url
                    )
                    break
                except InvalidConfigError as error:
                    print('ERROR: {}'.format(error))

            update_api_token = 'yes'
            if self.encrypted_carbon_black_api_token:
                # API token already exists - ask if they want to update it.
                while True:
                    update_api_token = self._get_input(
                        'Change the CarbonBlack API token [yes/no]?', 'no'
                    )
                    if update_api_token in {'yes', 'no'}:
                        break
                    else:
                        print('ERROR: Please enter exactly "yes" or "no"')

            if update_api_token == 'yes':
                self.save()  # Save updates so far to enable the downloader for terraform.
                self._encrypt_cb_api_token()

        # Save the updated configuration.
        self.save()

    def validate(self) -> None:
        """Validate config values against their expected formats.

        Terraform and AWS have their own validation, but this simple up-front check
        saves the user some headache compared to waiting for a deploy to fail.
        We only explicitly validate variables which the user can change through the CLI:
            aws_region, name_prefix, *carbon_black*

        Raises:
            InvalidConfigError: If any config variable has an invalid value.
        """
        # Go through the internal setters which have the validation logic.
        self.aws_region = self.aws_region
        self.name_prefix = self.name_prefix
        self.enable_carbon_black_downloader = self.enable_carbon_black_downloader
        if self.enable_carbon_black_downloader:
            # Validate CarbonBlack variables if applicable.
            self.carbon_black_url = self.carbon_black_url
            self.encrypted_carbon_black_api_token = self.encrypted_carbon_black_api_token

    def save(self) -> None:
        """Save the current configuration to the terraform.tfvars config file."""
        # In order to preserve comments, we overwrite each individual variable instead of re-writing
        # the entire configuration file.
        with open(CONFIG_FILE) as config_file:
            raw_config = config_file.read()

        for variable_name, value in self._config.items():
            raw_config = re.sub(
                r'{}\s*=\s*\S+'.format(variable_name),
                '{} = {}'.format(variable_name,
                                 value if isinstance(value, int) else '"' + value + '"'),
                raw_config
            )

        with open(CONFIG_FILE, 'w') as config_file:
            config_file.write(raw_config)


class Manager(object):
    """BinaryAlert management utility."""

    def __init__(self):
        """Parse the terraform.tfvars config file."""
        self._config = BinaryAlertConfig()

    @property
    def commands(self) -> Set[str]:
        """Return set of available management commands."""
        return {'analyze_all', 'apply', 'build', 'cb_copy_all', 'clone_rules', 'configure',
                'deploy', 'live_test', 'unit_test'}

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
            if command not in {'configure', 'unit_test'}:
                self._config.validate()
            getattr(self, command)()  # Command validation already happened in the ArgumentParser.
        except InvalidConfigError as error:
            sys.exit('ERROR: {}\nPlease run "python3 manage.py configure"'.format(error))
        except TestFailureError as error:
            sys.exit('TEST FAILED: {}'.format(error))

    def analyze_all(self) -> None:
        """Start a batcher to asynchronously re-analyze the entire S3 bucket."""
        function_name = self._config.binaryalert_batcher_name
        print('Asynchronously invoking {}...'.format(function_name))
        boto3.client('lambda').invoke(
            FunctionName=function_name,
            InvocationType='Event',  # Asynchronous invocation.
            Qualifier='Production'
        )
        print('Batcher invocation successful!')

    @staticmethod
    def apply() -> None:
        """Terraform validate and apply any configuration/package changes."""
        # Validate and format the terraform files.
        os.chdir(TERRAFORM_DIR)
        # TODO: In Terraform 0.10.3, the -var-file flag won't be necessary here
        subprocess.check_call(['terraform', 'validate', '-var-file', CONFIG_FILE])
        subprocess.check_call(['terraform', 'fmt'])

        # Setup the backend if needed and reload modules.
        subprocess.check_call(['terraform', 'init'])

        # Apply changes (requires interactive approval)
        subprocess.check_call(['terraform', 'apply', '-auto-approve=false'])

        # A second apply is unfortunately necessary to update the Lambda aliases.
        print('\nRe-applying to update Lambda aliases...')
        subprocess.check_call(
            ['terraform', 'apply', '-auto-approve=true', '-refresh=false'] +
            LAMBDA_ALIASES_TERRAFORM_TARGETS
        )

    def build(self) -> None:
        """Build Lambda packages (saves *.zip files in terraform/)."""
        lambda_build(TERRAFORM_DIR, self._config.enable_carbon_black_downloader == '1')

    def cb_copy_all(self) -> None:
        """Copy all binaries from CarbonBlack into BinaryAlert.

        Raises:
            InvalidConfigError: If the CarbonBlack downloader is not enabled.
        """
        if not self._config.enable_carbon_black_downloader:
            raise InvalidConfigError('CarbonBlack downloader is not enabled.')
        os.environ['CARBON_BLACK_URL'] = self._config.carbon_black_url
        os.environ['ENCRYPTED_CARBON_BLACK_API_TOKEN'] = (
            self._config.encrypted_carbon_black_api_token
        )
        os.environ['TARGET_S3_BUCKET'] = self._config.binaryalert_s3_bucket_name

        # Downloader must be imported here because the cb_api is configured at import time.
        from lambda_functions.downloader import copy_all
        copy_all.copy_all_binaries()

    @staticmethod
    def clone_rules() -> None:
        """Clone YARA rules from other open-source projects."""
        update_github_rules()

    def configure(self) -> None:
        """Update basic configuration, including region, prefix, and downloader settings."""
        self._config.configure()
        print('Updated configuration successfully saved to terraform/terraform.tfvars!')

    def deploy(self) -> None:
        """Deploy BinaryAlert. Equivalent to unit_test + build + apply + analyze_all."""
        self.unit_test()
        self.build()
        self.apply()
        self.analyze_all()

    def live_test(self) -> None:
        """Upload an EICAR test file to BinaryAlert which should trigger a YARA match alert.

        Raises:
            TestFailureError: If the live test failed (YARA match not found).
        """
        bucket_name = self._config.binaryalert_s3_bucket_name
        test_filename = 'eicar_test_{}.txt'.format(uuid.uuid4())
        s3_identifier = 'S3:{}:{}'.format(bucket_name, test_filename)

        print('Uploading EICAR test file {}...'.format(s3_identifier))
        bucket = boto3.resource('s3').Bucket(bucket_name)
        bucket.put_object(
            Body=EICAR_STRING.encode('UTF-8'),
            Key=test_filename,
            Metadata={'observed_path': test_filename}
        )

        table_name = '{}_binaryalert_matches'.format(self._config.name_prefix)
        print('EICAR test file uploaded! Connecting to table DynamoDB:{}...'.format(table_name))
        table = boto3.resource('dynamodb').Table(table_name)
        eicar_sha256 = hashlib.sha256(EICAR_STRING.encode('UTF-8')).hexdigest()
        dynamo_record_found = False

        for attempt in range(1, 11):
            time.sleep(5)
            print('\t[{}/10] Querying DynamoDB table for the expected YARA match entry...'.format(
                attempt))
            items = table.query(
                Select='ALL_ATTRIBUTES',
                Limit=1,
                ConsistentRead=True,
                ScanIndexForward=False,  # Sort by LambdaVersion descending (e.g. newest first).
                KeyConditionExpression=Key('SHA256').eq(eicar_sha256),
                FilterExpression=Attr('S3Objects').contains(s3_identifier)
            ).get('Items')

            if items:
                print('\nSUCCESS: Expected DynamoDB entry for the EICAR file was found!\n')
                dynamo_record_found = True
                pprint.pprint(items[0])

                print('\nRemoving DynamoDB EICAR entry...')
                lambda_version = items[0]['LambdaVersion']
                table.delete_item(Key={'SHA256': eicar_sha256, 'LambdaVersion': lambda_version})
                break
            elif attempt == 10:
                print('\nFAIL: Expected DynamoDB entry for the EICAR file was *not* found!\n')

        print('Removing EICAR test file from S3...')
        bucket.delete_objects(Delete={'Objects': [{'Key': test_filename}]})

        if dynamo_record_found:
            print('\nLive test succeeded! Verify the alert was sent to your SNS subscription(s).')
        else:
            # TODO: Link to troubleshooting documentation
            raise TestFailureError('\nLive test failed!')

    @staticmethod
    @boto3_mocks.restore_http_adapter
    def unit_test() -> None:
        """Run unit tests (*_test.py).

        Raises:
            TestFailureError: If any of the unit tests failed.
        """
        suite = unittest.TestLoader().discover(PROJECT_DIR, pattern='*_test.py')
        test_result = unittest.TextTestRunner(verbosity=1).run(suite)
        if not test_result.wasSuccessful():
            raise TestFailureError('Unit tests failed')


def main() -> None:
    """Main command dispatcher."""
    manager = Manager()

    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('command', choices=sorted(manager.commands), help=manager.help)
    args = parser.parse_args()

    manager.run(args.command)


if __name__ == '__main__':
    main()
