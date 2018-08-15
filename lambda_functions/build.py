"""Builds the deployment packages for all of the Lambda functions."""
import glob
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Callable
import zipfile

from lambda_functions.analyzer.common import COMPILED_RULES_FILENAME
from rules.compile_rules import compile_rules

LAMBDA_DIR = os.path.dirname(os.path.realpath(__file__))


def _build_function(function_name: str, target_directory: str,
                    pre_zip_func: Callable[[str], None] = None) -> None:
    """Build a Lambda deployment package (.zip file)

    Libraries are installed in the package root and source code is installed to mirror the repo
    structure (lambda_functions/name/*.py)

    Args:
        function_name: Directory under lambda_functions/ corresponding to the function source
        target_directory: Path to folder which will store generated zipfiles
        pre_zip_func: Optional custom code to run before zipping up the final package
            The function will be given a single argument: the package root in /tmp
    """
    print('Creating {} deploy package...'.format(function_name))

    # Create a temporary directory for building the Lambda function.
    temp_package_dir = os.path.join(
        tempfile.gettempdir(), 'binaryalert_{}.pkg'.format(function_name))
    if os.path.exists(temp_package_dir):
        shutil.rmtree(temp_package_dir)

    # Create lambda_functions/name directory structure.
    temp_lambda_dir = os.path.join(temp_package_dir, 'lambda_functions', function_name)
    os.makedirs(os.path.join(temp_package_dir, 'lambda_functions', function_name))
    pathlib.Path(os.path.join(temp_package_dir, 'lambda_functions', '__init__.py')).touch()

    # Copy Python source files.
    source_root = os.path.join(LAMBDA_DIR, function_name)
    for py_file in glob.glob(os.path.join(source_root, '*.py')):
        shutil.copy(py_file, temp_lambda_dir)

    # Extract pre-compiled dependencies.
    dependencies = os.path.join(source_root, 'dependencies.zip')
    if os.path.exists(dependencies):
        with zipfile.ZipFile(dependencies, 'r') as deps:
            deps.extractall(temp_package_dir)

    # Install other requirements.
    requirements = os.path.join(source_root, 'requirements.txt')
    if os.path.exists(requirements):
        subprocess.check_call([
            sys.executable, '-m', 'pip', 'install',
            '--quiet', '--target', temp_package_dir, '-r', requirements
        ])

    # Run custom code (if applicable).
    if pre_zip_func:
        pre_zip_func(temp_package_dir)

    # Zip up the final package.
    shutil.make_archive(os.path.join(target_directory, 'lambda_' + function_name),
                        'zip', temp_package_dir)


def _build_analyzer_callback(temp_package_dir: str) -> None:
    """Custom routine to execute before zipping up the analyzer package."""
    compile_rules(
        os.path.join(temp_package_dir, 'lambda_functions', 'analyzer', COMPILED_RULES_FILENAME))

    # Make UPX and yextend executable for everyone.
    for executable in ['pdftotext', 'upx', 'yextend']:
        path = os.path.join(temp_package_dir, executable)
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def build(target_directory: str, downloader: bool = False) -> None:
    """Build Lambda deployment packages.

    Args:
        target_directory: Path to folder which will store generated zipfiles.
        downloader: Whether the downloader should be built.
    """
    _build_function('analyzer', target_directory, _build_analyzer_callback)
    if downloader:
        _build_function('downloader', target_directory)
