#!/usr/bin/env python3
"""Command-line tool for easily managing BinaryAlert."""
# Usage: python3 manage.py [--help] [command]
import argparse
import base64
import getpass
import inspect
import os
import re
import subprocess
import sys
from typing import Set
import unittest

import boto3
import hcl

from lambda_functions.analyzer.common import COMPILED_RULES_FILENAME
from lambda_functions.build import build as lambda_build
from rules import compile_rules, clone_rules
from tests import live_test

# BinaryAlert version.
VERSION = '1.1.0'

# File locations.
PROJECT_DIR = os.path.dirname(os.path.realpath(__file__))  # Directory containing this file.
TERRAFORM_DIR = os.path.join(PROJECT_DIR, 'terraform')
CONFIG_FILE = os.path.join(TERRAFORM_DIR, 'terraform.tfvars')
VARIABLES_FILE = os.path.join(TERRAFORM_DIR, 'variables.tf')
TEST_FILES = os.path.join(PROJECT_DIR, 'tests', 'files')

# Terraform identifiers.
CB_KMS_ALIAS_TERRAFORM_ID = 'aws_kms_alias.encrypt_credentials_alias'
BINARY_BUCKET_TERRAFORM_ID = 'aws_s3_bucket.binaryalert_binaries'
LOG_BUCKET_TERRAFORM_ID = 'aws_s3_bucket.binaryalert_log_bucket'

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


def _get_input(prompt: str, default_value: str) -> str:
    """Wrapper around input() which shows the current (default value)."""
    if default_value:
        prompt = '{} ({}): '.format(prompt, default_value)
    else:
        prompt = '{}: '.format(prompt)
    return input(prompt).strip().lower() or default_value


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
                'encrypted_carbon_black_api_token "{}" does not match format {}'.format(
                    value, self.VALID_CB_ENCRYPTED_TOKEN_FORMAT
                )
            )
        self._config['encrypted_carbon_black_api_token'] = value

    @property
    def force_destroy(self) -> str:
        return self._config['force_destroy']

    @property
    def binaryalert_analyzer_name(self) -> str:
        return '{}_binaryalert_analyzer'.format(self.name_prefix)

    @property
    def binaryalert_batcher_name(self) -> str:
        return '{}_binaryalert_batcher'.format(self.name_prefix)

    @property
    def binaryalert_dynamo_table_name(self) -> str:
        return '{}_binaryalert_matches'.format(self.name_prefix)

    @property
    def binaryalert_s3_bucket_name(self) -> str:
        return '{}.binaryalert-binaries.{}'.format(
            self.name_prefix.replace('_', '.'), self.aws_region
        )

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
        subprocess.check_call(['terraform', 'get'])
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
                self.aws_region = _get_input('AWS Region', self.aws_region)
                break
            except InvalidConfigError as error:
                print('ERROR: {}'.format(error))

        while True:  # Get name prefix.
            try:
                self.name_prefix = _get_input(
                    'Unique name prefix, e.g. "company_team"', self.name_prefix
                )
                break
            except InvalidConfigError as error:
                print('ERROR: {}'.format(error))

        while True:  # Enable downloader?
            enable_downloader = _get_input(
                'Enable the CarbonBlack downloader?',
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
                    self.carbon_black_url = _get_input('CarbonBlack URL', self.carbon_black_url)
                    break
                except InvalidConfigError as error:
                    print('ERROR: {}'.format(error))

            update_api_token = 'yes'
            if self.encrypted_carbon_black_api_token:
                # API token already exists - ask if they want to update it.
                while True:
                    update_api_token = _get_input('Change the CarbonBlack API token?', 'no')
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
            if isinstance(value, str):
                formatted_value = '"{}"'.format(value)
            elif isinstance(value, bool):
                formatted_value = str(value).lower()
            else:
                formatted_value = value

            raw_config = re.sub(
                r'{}\s*=\s*\S+'.format(variable_name),
                '{} = {}'.format(variable_name, formatted_value),
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
        return {'analyze_all', 'apply', 'build', 'cb_copy_all', 'clone_rules', 'compile_rules',
                'configure', 'deploy', 'destroy', 'live_test', 'unit_test'}

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
            if command not in {'compile_rules', 'configure', 'unit_test'}:
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

        # Setup the backend if needed and reload modules.
        subprocess.check_call(['terraform', 'init'])

        subprocess.check_call(['terraform', 'fmt'])

        # Apply changes (requires interactive approval)
        subprocess.check_call(['terraform', 'apply', '-auto-approve=false'])

    def build(self) -> None:
        """Build Lambda packages (saves *.zip files in terraform/)."""
        lambda_build(TERRAFORM_DIR, self._config.enable_carbon_black_downloader == 1)

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
        clone_rules.clone_remote_rules()

    @staticmethod
    def compile_rules() -> None:
        """Compile all of the YARA rules into a single binary file."""
        compile_rules.compile_rules(COMPILED_RULES_FILENAME)
        print('Compiled rules saved to {}'.format(COMPILED_RULES_FILENAME))

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

    def destroy(self) -> None:
        """Teardown all of the BinaryAlert infrastructure."""
        os.chdir(TERRAFORM_DIR)

        if not self._config.force_destroy:
            result = _get_input('Delete all S3 objects as well?', 'no')

            if result not in {'yes', 'no'}:
                sys.exit('Please answer exactly "yes" or "no"')

            if result == 'yes':
                print('Enabling force_destroy on the BinaryAlert S3 buckets...')
                subprocess.check_call([
                    'terraform', 'apply', '-auto-approve=true', '-refresh=false',
                    '-var', 'force_destroy=true',
                    '-target', BINARY_BUCKET_TERRAFORM_ID, '-target', LOG_BUCKET_TERRAFORM_ID
                ])

        subprocess.call(['terraform', 'destroy'])

    def live_test(self) -> None:
        """Upload test files to BinaryAlert which should trigger YARA matches.

        Raises:
            TestFailureError: If the live test failed (YARA matches not found).
        """
        if not live_test.run(self._config.binaryalert_s3_bucket_name,
                             self._config.binaryalert_analyzer_name,
                             self._config.binaryalert_dynamo_table_name):
            raise TestFailureError(
                '\nLive test failed! See https://binaryalert.io/troubleshooting-faq.html')

    @staticmethod
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
    parser.add_argument(
        'command', choices=sorted(manager.commands), help=manager.help, metavar='command')
    parser.add_argument('--version', action='version', version='BinaryAlert v{}'.format(VERSION))
    args = parser.parse_args()

    manager.run(args.command)


if __name__ == '__main__':
    main()
