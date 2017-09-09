"""Test lambda_functions/build.py."""
import os
import pip
import tempfile
from typing import List, Set
import unittest
from unittest import mock
import zipfile

from lambda_functions import build


def _mock_pip_main(args_list: List[str]) -> None:
    """Mock pip install just creates the target directory."""
    directory = args_list[-2]
    package = args_list[-1]
    os.makedirs(os.path.join(directory, package))


@mock.patch.object(build, 'print')
class BuildTest(unittest.TestCase):
    """Test top-level build command."""
    # pylint: disable=protected-access

    def setUp(self):
        """Find temp directory in which to build packages."""
        self.maxDiff = None  # pylint: disable=invalid-name
        self._tempdir = tempfile.gettempdir()

    def _verify_filenames(self, archive_path: str, expected_filenames: Set[str],
                          subset: bool = False):
        """Verify the set of filenames in the zip archive matches the expected list."""
        with zipfile.ZipFile(archive_path, 'r') as archive:
            filenames = set(zip_info.filename for zip_info in archive.filelist)  # type: ignore
        if subset:
            self.assertTrue(expected_filenames.issubset(filenames))
        else:
            self.assertEqual(expected_filenames, filenames)

    def test_build_analyzer(self, mock_print: mock.MagicMock):
        """Verify that a valid zipfile is generated for analyzer Lambda function."""
        build._build_analyzer(self._tempdir)
        self._verify_filenames(
            os.path.join(self._tempdir, build.ANALYZE_ZIPFILE + '.zip'),
            {
                'yara_python-3.6.3.egg-info/',
                '__init__.py',
                'analyzer_aws_lib.py',
                'binary_info.py',
                'common.py',
                'compiled_yara_rules.bin',
                'file_hash.py',
                'libpython3.5m.so.1.0',
                'main.py',
                'yara.so',
                'yara_analyzer.py',
                'yara_python-3.6.3.egg-info/dependency_links.txt',
                'yara_python-3.6.3.egg-info/installed-files.txt',
                'yara_python-3.6.3.egg-info/not-zip-safe',
                'yara_python-3.6.3.egg-info/PKG-INFO',
                'yara_python-3.6.3.egg-info/SOURCES.txt',
                'yara_python-3.6.3.egg-info/top_level.txt'
            }
        )
        mock_print.assert_called_once()

    def test_build_batcher(self, mock_print: mock.MagicMock):
        """Verify that a valid zipfile is generated for the batcher Lambda function."""
        build._build_batcher(self._tempdir)
        self._verify_filenames(
            os.path.join(self._tempdir, build.BATCH_ZIPFILE + '.zip'), {'main.py'}
        )
        mock_print.assert_called_once()

    def test_build_dispatcher(self, mock_print: mock.MagicMock):
        """Verify that a valid zipfile is generated for the dispatcher Lambda function."""
        build._build_dispatcher(self._tempdir)
        self._verify_filenames(
            os.path.join(self._tempdir, build.DISPATCH_ZIPFILE + '.zip'), {'main.py'}
        )
        mock_print.assert_called_once()

    @mock.patch.object(pip, 'main', side_effect=_mock_pip_main)
    def test_build_downloader(self, mock_pip: mock.MagicMock, mock_print: mock.MagicMock):
        """Verify list of bundled files for the downloader."""
        build._build_downloader(self._tempdir)
        self._verify_filenames(
            os.path.join(self._tempdir, build.DOWNLOAD_ZIPFILE + '.zip'),
            {'backoff/', 'cbapi/', 'main.py'},
            subset=True
        )
        mock_pip.assert_called_once()
        mock_print.assert_called_once()

    @mock.patch.object(pip, 'main', side_effect=_mock_pip_main)
    def test_build_all(self, mock_pip: mock.MagicMock, mock_print: mock.MagicMock):
        """Verify that the top-level build function executes without error."""
        build.build(self._tempdir, downloader=True)
        mock_pip.assert_called_once()
        self.assertEqual(4, mock_print.call_count)
