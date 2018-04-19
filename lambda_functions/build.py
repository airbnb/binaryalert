"""Builds the deployment packages for all of the Lambda functions."""
import glob
import os
import pathlib
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile

from lambda_functions.analyzer.common import COMPILED_RULES_FILENAME
from rules.compile_rules import compile_rules

LAMBDA_DIR = os.path.dirname(os.path.realpath(__file__))

ANALYZE_SOURCE = os.path.join(LAMBDA_DIR, 'analyzer')
ANALYZE_DEPENDENCIES = os.path.join(ANALYZE_SOURCE, 'dependencies.zip')
ANALYZE_ZIPFILE = 'lambda_analyzer'

BATCH_SOURCE = os.path.join(LAMBDA_DIR, 'batcher', 'main.py')
BATCH_ZIPFILE = 'lambda_batcher'

DISPATCH_SOURCE = os.path.join(LAMBDA_DIR, 'dispatcher', 'main.py')
DISPATCH_ZIPFILE = 'lambda_dispatcher'

DOWNLOAD_SOURCE = os.path.join(LAMBDA_DIR, 'downloader', 'main.py')
DOWNLOAD_ZIPFILE = 'lambda_downloader'


def _build_analyzer(target_directory: str) -> None:
    """Build the YARA analyzer Lambda deployment package."""
    print('Creating analyzer deploy package...')
    pathlib.Path(os.path.join(ANALYZE_SOURCE, 'main.py')).touch()

    # Create a new copy of the core lambda directory to avoid cluttering the original.
    temp_package_dir = os.path.join(tempfile.gettempdir(), 'tmp_yara_analyzer.pkg')
    if os.path.exists(temp_package_dir):
        shutil.rmtree(temp_package_dir)
    os.mkdir(temp_package_dir)
    for py_file in glob.glob(os.path.join(ANALYZE_SOURCE, '*.py')):
        shutil.copy(py_file, temp_package_dir)

    # Compile the YARA rules.
    compile_rules(os.path.join(temp_package_dir, COMPILED_RULES_FILENAME))

    # Extract the AWS-native dependencies into the package.
    with zipfile.ZipFile(ANALYZE_DEPENDENCIES, 'r') as deps:
        deps.extractall(temp_package_dir)

    # Make UPX and yextend executable for everyone.
    for executable in ['pdftotext', 'upx', 'yextend']:
        path = os.path.join(temp_package_dir, executable)
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    # Zip up the package and remove temporary directory.
    shutil.make_archive(os.path.join(target_directory, ANALYZE_ZIPFILE), 'zip', temp_package_dir)
    shutil.rmtree(temp_package_dir)


def _build_batcher(target_directory: str) -> None:
    """Build the batcher Lambda deployment package."""
    print('Creating batcher deploy package...')
    pathlib.Path(BATCH_SOURCE).touch()  # Change last modified time to force new Lambda deploy
    with zipfile.ZipFile(os.path.join(target_directory, BATCH_ZIPFILE + '.zip'), 'w') as pkg:
        pkg.write(BATCH_SOURCE, os.path.basename(BATCH_SOURCE))


def _build_dispatcher(target_directory: str) -> None:
    """Build the dispatcher Lambda deployment package."""
    print('Creating dispatcher deploy package...')
    pathlib.Path(DISPATCH_SOURCE).touch()
    with zipfile.ZipFile(os.path.join(target_directory, DISPATCH_ZIPFILE + '.zip'), 'w') as pkg:
        pkg.write(DISPATCH_SOURCE, os.path.basename(DISPATCH_SOURCE))


def _build_downloader(target_directory: str) -> None:
    """Build the downloader Lambda deployment package."""
    print('Creating downloader deploy package...')
    pathlib.Path(DOWNLOAD_SOURCE).touch()

    temp_package_dir = os.path.join(tempfile.gettempdir(), 'tmp_yara_downloader.pkg')
    if os.path.exists(temp_package_dir):
        shutil.rmtree(temp_package_dir)

    # Pip install cbapi library (has no native dependencies).
    subprocess.check_call([
        sys.executable, '-m', 'pip', 'install',
        '--quiet', '--target', temp_package_dir, 'cbapi==1.3.6'
    ])

    # Copy Lambda code into the package.
    shutil.copy(DOWNLOAD_SOURCE, temp_package_dir)

    # Zip up the package and remove temporary directory.
    shutil.make_archive(os.path.join(target_directory, DOWNLOAD_ZIPFILE), 'zip', temp_package_dir)
    shutil.rmtree(temp_package_dir)


def build(target_directory: str, downloader: bool = False) -> None:
    """Build Lambda deployment packages.

    Args:
        target_directory: [String] Path to folder which will store generated zipfiles.
        downloader: [bool] Whether the downloader should be built.
    """
    _build_analyzer(target_directory)
    _build_batcher(target_directory)
    _build_dispatcher(target_directory)
    if downloader:
        _build_downloader(target_directory)
