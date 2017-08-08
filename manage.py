"""Command-line tool for easily managing BinaryAlert."""
# Usage: python3 manage.py [--help] [command]
import argparse
import inspect
import os
import subprocess
import sys
import unittest

import boto3
import hcl

from lambda_functions.build import build as lambda_build
from rules.update_rules import update_github_rules
from tests import boto3_mocks

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
        print('Reading config file {}...'.format(config_file))
        with open(config_file) as f:
            self._config = hcl.load(f)

        boto3.setup_default_session(region_name=self._config['aws_region'])

    @property
    def commands(self):
        """Return set of available commands."""
        return {'apply', 'analyze_all', 'build', 'deploy', 'update_rules', 'test'}

    @property
    def help(self):
        """Return help string about each available command (built from docstrings)."""
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
    def update_rules():
        """Update YARA rules cloned from other open-source projects."""
        update_github_rules()

    def deploy(self):
        """Deploy BinaryAlert. Equivalent to test + build + apply + analyze_all."""
        self.test()
        self.build()
        self.apply()
        self.analyze_all()

    @staticmethod
    @boto3_mocks.restore_http_adapter
    def test():
        """Run unit tests (*_test.py)."""
        suite = unittest.TestLoader().discover(PROJECT_DIR, pattern='*_test.py')
        test_result = unittest.TextTestRunner(verbosity=1).run(suite)
        if not test_result.wasSuccessful():
            sys.exit('Unit tests failed')  # Exit code 1

    @staticmethod
    def build():
        """Build Lambda packages (saves *.zip files in terraform/)."""
        lambda_build(TERRAFORM_DIR)

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


def main():
    """Main command dispatcher."""
    manager = Manager(CONFIG_FILE)

    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('command', choices=sorted(manager.commands), help=manager.help)
    args = parser.parse_args()

    manager.run(args.command)


if __name__ == '__main__':
    main()
