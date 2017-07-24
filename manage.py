"""Command-line tool for easily managing BinaryAlert."""
# Usage: python3 manage.py [--help] [command]
import argparse
import glob
import os
import shutil
import subprocess
import sys
import unittest
import tempfile
import zipfile

import boto3
import hcl

from lambda_functions.analyzer.main import COMPILED_RULES_FILENAME
from rules.compile_rules import compile_rules
from rules.update_rules import update_github_rules

PROJECT_DIR = os.path.dirname(os.path.realpath(__file__))  # Directory containing this file.
TERRAFORM_DIR = os.path.join(PROJECT_DIR, 'terraform')
CONFIG_FILE = os.path.join(TERRAFORM_DIR, 'terraform.tfvars')

ANALYZE_LAMBDA_SOURCE = os.path.join(PROJECT_DIR, 'lambda_functions', 'analyzer')
ANALYZE_LAMBDA_DEPENDENCIES = os.path.join(ANALYZE_LAMBDA_SOURCE, 'yara_python_3.6.3.zip')
ANALYZE_LAMBDA_PACKAGE = os.path.join(TERRAFORM_DIR, 'lambda_analyzer')  # ".zip" added later.

BATCH_LAMBDA_SOURCE = os.path.join(PROJECT_DIR, 'lambda_functions', 'batcher', 'main.py')
BATCH_LAMBDA_PACKAGE = os.path.join(TERRAFORM_DIR, 'lambda_batcher.zip')

DISPATCH_LAMBDA_SOURCE = os.path.join(PROJECT_DIR, 'lambda_functions', 'dispatcher', 'main.py')
DISPATCH_LAMBDA_PACKAGE = os.path.join(TERRAFORM_DIR, 'lambda_dispatcher.zip')

# Lambda alias terraform targets, to be updated separately.
LAMBDA_ALIASES_TERRAFORM_TARGETS = [
    '-target=module.binaryalert_{}.aws_lambda_alias.production_alias'.format(name)
    for name in ['analyzer', 'batcher', 'dispatcher']
]


def _parse_config_data():
    """Parse the BinaryAlert config file and return the configuration as a dict."""
    print('Reading config file {}...'.format(CONFIG_FILE))
    with open(CONFIG_FILE) as config_file:
        return hcl.load(config_file)


def update_rules():
    """Update YARA rules cloned from github.com."""
    update_github_rules()


def deploy():
    """Build the Lambda deployment packages and terraform apply."""
    test()
    build()
    apply()
    analyze_all()


def test():
    """Run all *_test.py unittests and exit 1 if tests failed."""
    suite = unittest.TestLoader().discover(PROJECT_DIR, pattern='*_test.py')
    test_result = unittest.TextTestRunner(verbosity=1).run(suite)
    if not test_result.wasSuccessful():
        sys.exit("Unit tests failed")  # Exit code 1


def _build_analyzer():
    """Build the YARA analyzer Lambda deployment package."""
    # Create a new copy of the core lambda directory to avoid cluttering the original.
    temp_package_dir = os.path.join(tempfile.gettempdir(), 'tmp_yara_analyzer.pkg')
    if os.path.exists(temp_package_dir):
        shutil.rmtree(temp_package_dir)
    os.mkdir(temp_package_dir)
    for py_file in glob.glob(os.path.join(ANALYZE_LAMBDA_SOURCE, '*.py')):
        shutil.copy(py_file, temp_package_dir)

    # Clone the YARA-rules repo and compile the YARA rules.
    compile_rules(os.path.join(temp_package_dir, COMPILED_RULES_FILENAME))

    # Extract the AWS-native Python deps into the package.
    print('Creating analyzer deploy package...')
    with zipfile.ZipFile(ANALYZE_LAMBDA_DEPENDENCIES, 'r') as deps:
        deps.extractall(temp_package_dir)

    # Zip up the package and remove temporary directory.
    shutil.make_archive(ANALYZE_LAMBDA_PACKAGE, 'zip', temp_package_dir)
    shutil.rmtree(temp_package_dir)


def _build_batcher():
    """Build the batcher Lambda deployment package."""
    print('Creating batcher deploy package...')
    with zipfile.ZipFile(BATCH_LAMBDA_PACKAGE, 'w') as pkg:
        pkg.write(BATCH_LAMBDA_SOURCE, os.path.basename(BATCH_LAMBDA_SOURCE))


def _build_dispatcher():
    """Build the dispatcher Lambda deployment package."""
    print('Creating dispatcher deploy package...')
    with zipfile.ZipFile(DISPATCH_LAMBDA_PACKAGE, 'w') as pkg:
        pkg.write(DISPATCH_LAMBDA_SOURCE, os.path.basename(DISPATCH_LAMBDA_SOURCE))


def build():
    """Build Lambda deployment packages."""
    _build_analyzer()
    _build_batcher()
    _build_dispatcher()


def apply():
    """Run terraform apply. Raises an exception if the Terraform is invalid."""
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


def analyze_all():
    """Run the batcher to asynchronously re-analyze the entire S3 bucket."""
    config_data = _parse_config_data()  # TODO: Avoid parsing config data twice
    function_name = '{}_binaryalert_batcher'.format(config_data['name_prefix'])

    print('Asynchronously invoking {}...'.format(function_name))
    boto3.client('lambda').invoke(
        FunctionName=function_name,
        InvocationType='Event',  # Asynchronous invocation.
        Qualifier='Production'
    )
    print('Batcher invocation successful!')


def main():
    """Main command dispatcher."""
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument(
        'command',
        choices=['update_rules', 'deploy', 'test', 'build', 'apply', 'analyze_all'],
        help='update_rules  Update YARA rules cloned from other open-source projects.\n'
             'deploy        Deploy BinaryAlert. Equivalent to test + build + apply + analyze_all.\n'
             'test          Run unit tests (*_test.py).\n'
             'build         Build Lambda packages (saves *.zip files in terraform/).\n'
             'apply         Terraform validate and apply any configuration/package changes.\n'
             'analyze_all   Start a batcher to asynchronously re-analyze the entire S3 bucket.')
    args = parser.parse_args()

    # Set boto3 region.
    config_data = _parse_config_data()
    boto3.setup_default_session(region_name=config_data['aws_region'])

    # Dispatch to the appropriate function.
    globals()[args.command]()


if __name__ == '__main__':
    main()
