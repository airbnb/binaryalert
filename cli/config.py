"""BinaryAlert configuration management."""
import base64
import getpass
import os
import re
import subprocess
from typing import Any

import boto3
import hcl

from cli.exceptions import InvalidConfigError

# File locations
PARENT_DIR = os.path.dirname(os.path.realpath(__file__))  # Directory containing this file.
TERRAFORM_DIR = os.path.realpath(os.path.join(PARENT_DIR, '..', 'terraform'))
CONFIG_FILE = os.path.join(TERRAFORM_DIR, 'terraform.tfvars')
VARIABLES_FILE = os.path.join(TERRAFORM_DIR, 'variables.tf')


def get_input(prompt: str, default_value: str,
              config: Any = None, property_name: str = None) -> str:
    """Request user input, updating the underlying config if applicable.

    Args:
        prompt: On-screen prompt before user input
        default_value: The default (existing) value
        config: BinaryAlertConfig instance, if updating the underlying configuration
            If None, the valid values are assumed to be 'yes' and 'no'
        property_name: Name of the config property to update (applicable only if config != None)

    Returns:
        Lowercase user input, stripped of extra spaces, or the default value if no input was given
    """
    if default_value:
        prompt = '{} ({}): '.format(prompt, default_value)
    else:
        prompt = '{}: '.format(prompt)

    # Keep requesting user input until it is valid
    while True:
        user_input = input(prompt).strip().lower() or default_value
        if config and property_name:
            try:
                setattr(config, property_name, user_input)
                break
            except InvalidConfigError as error:
                print('ERROR: {}'.format(error))
        elif user_input in {'yes', 'no'}:
            break
        else:
            print('ERROR: Please enter exactly "yes" or "no"')

    return user_input


class BinaryAlertConfig:
    """Wrapper around reading, validating, and updating the terraform.tfvars config file."""
    # Expected configuration value formats.
    VALID_AWS_ACCOUNT_ID_FORMAT = r'\d{12}'
    VALID_AWS_REGION_FORMAT = r'[a-z]{2}-[a-z]{2,15}-\d'
    VALID_NAME_PREFIX_FORMAT = r'[a-z][a-z0-9_]{3,50}'
    VALID_CB_API_TOKEN_FORMAT = r'[a-f0-9]{40}'  # CarbonBlack API token.
    VALID_CB_ENCRYPTED_TOKEN_FORMAT = r'\S{50,500}'
    VALID_CB_URL_FORMAT = r'https?://\S+'

    def __init__(self) -> None:
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
    def aws_account_id(self) -> str:
        return self._config['aws_account_id']

    @aws_account_id.setter
    def aws_account_id(self, value: str) -> None:
        if not re.fullmatch(self.VALID_AWS_ACCOUNT_ID_FORMAT, value, re.ASCII):
            raise InvalidConfigError(
                'aws_account_id "{}" does not match format {}'.format(
                    value, self.VALID_AWS_ACCOUNT_ID_FORMAT)
            )
        self._config['aws_account_id'] = value

    @property
    def aws_region(self) -> str:
        return self._config['aws_region']

    @aws_region.setter
    def aws_region(self, value: str) -> None:
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
    def name_prefix(self, value: str) -> None:
        if not re.fullmatch(self.VALID_NAME_PREFIX_FORMAT, value, re.ASCII):
            raise InvalidConfigError(
                'name_prefix "{}" does not match format {}'.format(
                    value, self.VALID_NAME_PREFIX_FORMAT)
            )
        self._config['name_prefix'] = value

    @property
    def enable_carbon_black_downloader(self) -> bool:
        return self._config['enable_carbon_black_downloader']

    @enable_carbon_black_downloader.setter
    def enable_carbon_black_downloader(self, value: bool) -> None:
        if not isinstance(value, bool):
            raise InvalidConfigError(
                'enable_carbon_black_downloader "{}" must be a boolean.'.format(value)
            )
        self._config['enable_carbon_black_downloader'] = value

    @property
    def carbon_black_url(self) -> str:
        return self._config['carbon_black_url']

    @carbon_black_url.setter
    def carbon_black_url(self, value: str) -> None:
        if not re.fullmatch(self.VALID_CB_URL_FORMAT, value, re.ASCII):
            raise InvalidConfigError(
                'carbon_black_url "{}" does not match format {}'.format(
                    value, self.VALID_CB_URL_FORMAT)
            )
        self._config['carbon_black_url'] = value

    @property
    def carbon_black_timeout(self) -> str:
        return self._config['carbon_black_timeout']

    @carbon_black_timeout.setter
    def carbon_black_timeout(self, value: str) -> None:
        try:
            int_value = int(value)
        except ValueError:
            raise InvalidConfigError('carbon_black_timeout "{}" is not an integer'.format(value))
        self._config['carbon_black_timeout'] = int_value

    @property
    def encrypted_carbon_black_api_token(self) -> str:
        return self._config['encrypted_carbon_black_api_token']

    @encrypted_carbon_black_api_token.setter
    def encrypted_carbon_black_api_token(self, value: str) -> None:
        if not re.fullmatch(self.VALID_CB_ENCRYPTED_TOKEN_FORMAT, value, re.ASCII):
            raise InvalidConfigError(
                'encrypted_carbon_black_api_token "{}" does not match format {}'.format(
                    value, self.VALID_CB_ENCRYPTED_TOKEN_FORMAT
                )
            )
        self._config['encrypted_carbon_black_api_token'] = value

    @property
    def plaintext_carbon_black_api_token(self) -> str:
        return boto3.client('kms').decrypt(
            CiphertextBlob=base64.b64decode(self.encrypted_carbon_black_api_token))['Plaintext']

    @property
    def force_destroy(self) -> str:
        return self._config['force_destroy']

    @property
    def binaryalert_analyzer_name(self) -> str:
        return '{}_binaryalert_analyzer'.format(self.name_prefix)

    @property
    def binaryalert_analyzer_queue_name(self) -> str:
        return '{}_binaryalert_analyzer_queue'.format(self.name_prefix)

    @property
    def binaryalert_downloader_queue_name(self) -> str:
        return '{}_binaryalert_downloader_queue'.format(self.name_prefix)

    @property
    def binaryalert_dynamo_table_name(self) -> str:
        return '{}_binaryalert_matches'.format(self.name_prefix)

    @property
    def binaryalert_s3_bucket_name(self) -> str:
        return '{}.binaryalert-binaries.{}'.format(
            self.name_prefix.replace('_', '.'), self.aws_region
        )

    @property
    def retro_batch_size(self) -> int:
        return self._config['objects_per_retro_message']

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
        subprocess.check_call(['terraform', 'init'])
        subprocess.check_call(
            ['terraform', 'apply', '-target=aws_kms_alias.encrypt_credentials_alias']
        )

        print('Encrypting API token...')
        response = boto3.client('kms').encrypt(
            KeyId='alias/{}_binaryalert_carbonblack_credentials'.format(self.name_prefix),
            Plaintext=api_token
        )
        self.encrypted_carbon_black_api_token = base64.b64encode(
            response['CiphertextBlob']).decode('utf-8')

    def _configure_carbon_black(self) -> None:
        """If CarbonBlack downloader is enabled, request URL and credentials"""
        get_input('CarbonBlack URL', self.carbon_black_url, self, 'carbon_black_url')

        update_api_token = 'yes'
        if self.encrypted_carbon_black_api_token:
            # API token already exists - ask if they want to update it.
            update_api_token = get_input('Change the CarbonBlack API token?', 'no')

        if update_api_token == 'yes':
            self.save()  # Save updates so far to enable the downloader for terraform.
            self._encrypt_cb_api_token()

    def configure(self) -> None:
        """Request basic configuration settings from the user.

        Each request will be retried until the answer is in the correct format.
        """
        get_input('AWS Account ID', self.aws_account_id, self, 'aws_account_id')
        get_input('AWS Region', self.aws_region, self, 'aws_region')
        get_input('Unique name prefix, e.g. "company_team"', self.name_prefix, self, 'name_prefix')
        enable_downloader = get_input('Enable the CarbonBlack downloader?',
                                      'yes' if self.enable_carbon_black_downloader else 'no')
        self.enable_carbon_black_downloader = (enable_downloader == 'yes')

        if self.enable_carbon_black_downloader:
            self._configure_carbon_black()

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
        self.aws_account_id = self.aws_account_id
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
