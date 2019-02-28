"""Shared utilities for CLI test methods."""
import os
import sys

from pyfakefs import fake_filesystem_unittest

from cli.config import CONFIG_FILE, VARIABLES_FILE


def mock_input(prompt: str) -> str:
    """Mock for the user input() function to automatically respond with valid answers."""
    # pylint: disable=too-many-return-statements
    if prompt.startswith('AWS Account'):
        return '111122223333'
    if prompt.startswith('AWS Region'):
        return 'us-west-2'
    if prompt.startswith('Unique name prefix'):
        return ' NEW_NAME_PREFIX '  # Spaces and case shouldn't matter.
    if prompt.startswith('Enable the CarbonBlack downloader'):
        return 'yes'
    if prompt.startswith('CarbonBlack URL'):
        return 'https://new-example.com'
    if prompt.startswith('Change the CarbonBlack API token'):
        return 'yes'
    if prompt.startswith('Delete all S3 objects'):
        return 'yes'
    return 'UNKNOWN'


class FakeFilesystemBase(fake_filesystem_unittest.TestCase):
    """Base class sets up a fake filesystem for other test classes."""

    @staticmethod
    def _write_config(
            account_id: str = '123412341234',
            region: str = 'us-test-1',
            prefix: str = 'test_prefix',
            enable_downloader: bool = True,
            cb_url: str = 'https://cb-example.com',
            encrypted_api_token: str = 'A'*100):
        """Create terraform.tfvars file with the given configuration values."""
        with open(CONFIG_FILE, 'w') as config_file:
            config_file.write('\n'.join([
                '// comment1',
                'aws_account_id = "{}"'.format(account_id),
                'aws_region = "{}" // comment2'.format(region),
                'name_prefix = "{}" // comment3'.format(prefix),
                'enable_carbon_black_downloader = {}'.format(str(enable_downloader).lower()),
                'carbon_black_url = "{}" //comment4'.format(cb_url),
                'encrypted_carbon_black_api_token = "{}"'.format(encrypted_api_token),
                'force_destroy = false',
                'objects_per_retro_message = 5',
                '// comment5'
            ]))

    def setUp(self):
        """Enable pyfakefs and write out Terraform config files."""
        # pylint: disable=no-member
        self.setUpPyfakefs()

        # pyhcl automatically writes "parsetab.dat" in its site-package path.
        for path in sys.path:
            if path.endswith('site-packages'):
                self.fs.makedirs(os.path.join(path, 'hcl'))

        # Create variables.tf file (and terraform/ directory).
        self.fs.create_file(
            VARIABLES_FILE,
            contents='\n'.join([
                'variable "aws_account_id" {}',
                'variable "aws_region" {}',
                'variable "name_prefix" {}',
                'variable "enable_carbon_black_downloader" {}',
                'variable "carbon_black_url" {}',
                'variable "encrypted_carbon_black_api_token" {}'
            ])
        )

        # Create terraform.tfvars file.
        self._write_config()
