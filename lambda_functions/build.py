"""Builds the deployment packages for all of the Lambda functions."""
import glob
import os
import shutil
import tempfile
import zipfile

from lambda_functions.analyzer.main import COMPILED_RULES_FILENAME
from rules.compile_rules import compile_rules

LAMBDA_DIR = os.path.dirname(os.path.realpath(__file__))

ANALYZE_SOURCE = os.path.join(LAMBDA_DIR, 'analyzer')
ANALYZE_DEPENDENCIES = os.path.join(ANALYZE_SOURCE, 'yara_python_3.6.3.zip')
ANALYZE_ZIPFILE = 'lambda_analyzer'  # ".zip" will be added later

BATCH_SOURCE = os.path.join(LAMBDA_DIR, 'batcher', 'main.py')
BATCH_ZIPFILE = 'lambda_batcher.zip'

DISPATCH_SOURCE = os.path.join(LAMBDA_DIR, 'dispatcher', 'main.py')
DISPATCH_ZIPFILE = 'lambda_dispatcher.zip'


def _build_analyzer(target_directory):
    """Build the YARA analyzer Lambda deployment package."""
    print('Creating analyzer deploy package...')

    # Create a new copy of the core lambda directory to avoid cluttering the original.
    temp_package_dir = os.path.join(tempfile.gettempdir(), 'tmp_yara_analyzer.pkg')
    if os.path.exists(temp_package_dir):
        shutil.rmtree(temp_package_dir)
    os.mkdir(temp_package_dir)
    for py_file in glob.glob(os.path.join(ANALYZE_SOURCE, '*.py')):
        shutil.copy(py_file, temp_package_dir)

    # Compile the YARA rules.
    compile_rules(os.path.join(temp_package_dir, COMPILED_RULES_FILENAME))

    # Extract the AWS-native Python deps into the package.
    with zipfile.ZipFile(ANALYZE_DEPENDENCIES, 'r') as deps:
        deps.extractall(temp_package_dir)

    # Zip up the package and remove temporary directory.
    shutil.make_archive(os.path.join(target_directory, ANALYZE_ZIPFILE), 'zip', temp_package_dir)
    shutil.rmtree(temp_package_dir)


def _build_batcher(target_directory):
    """Build the batcher Lambda deployment package."""
    print('Creating batcher deploy package...')
    with zipfile.ZipFile(os.path.join(target_directory, BATCH_ZIPFILE), 'w') as pkg:
        pkg.write(BATCH_SOURCE, os.path.basename(BATCH_SOURCE))


def _build_dispatcher(target_directory):
    """Build the dispatcher Lambda deployment package."""
    print('Creating dispatcher deploy package...')
    with zipfile.ZipFile(os.path.join(target_directory, DISPATCH_ZIPFILE), 'w') as pkg:
        pkg.write(DISPATCH_SOURCE, os.path.basename(DISPATCH_SOURCE))


def build(target_directory):
    """Build Lambda deployment packages.

    Args:
        target_directory: [String] Path to folder which will store generated zipfiles.
    """
    _build_analyzer(target_directory)
    _build_batcher(target_directory)
    _build_dispatcher(target_directory)
