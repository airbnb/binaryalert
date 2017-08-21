"""Test lambda_functions/build.py."""
import os
import tempfile
import unittest
from unittest import mock
import zipfile

from lambda_functions import build


@mock.patch.object(build, 'print')
class BuildTest(unittest.TestCase):
    """Test top-level build command."""
    # pylint: disable=protected-access

    def setUp(self):
        """Find temp directory in which to build packages."""
        self.maxDiff = None  # pylint: disable=invalid-name
        self._tempdir = tempfile.gettempdir()

    def _verify_filenames(self, archive_path, expected_filenames, subset=False):
        """Verify the set of filenames in the zip archive matches the expected list."""
        with zipfile.ZipFile(archive_path, 'r') as archive:
            filenames = set(zip_info.filename for zip_info in archive.filelist)
        if subset:
            self.assertTrue(expected_filenames.issubset(filenames))
        else:
            self.assertEqual(expected_filenames, filenames)

    def test_build_analyzer(self, mock_print):
        """Verify that a valid zipfile is generated for analyzer Lambda function."""
        build._build_analyzer(self._tempdir)
        self._verify_filenames(
            os.path.join(self._tempdir, build.ANALYZE_ZIPFILE + '.zip'),
            {
                'yara_python-3.6.3.egg-info/',
                '__init__.py',
                'analyzer_aws_lib.py',
                'binary_info.py',
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

    def test_build_batcher(self, mock_print):
        """Verify that a valid zipfile is generated for the batcher Lambda function."""
        build._build_batcher(self._tempdir)
        self._verify_filenames(
            os.path.join(self._tempdir, build.BATCH_ZIPFILE + '.zip'), {'main.py'}
        )
        mock_print.assert_called_once()

    def test_build_dispatcher(self, mock_print):
        """Verify that a valid zipfile is generated for the dispatcher Lambda function."""
        build._build_dispatcher(self._tempdir)
        self._verify_filenames(
            os.path.join(self._tempdir, build.DISPATCH_ZIPFILE + '.zip'), {'main.py'}
        )
        mock_print.assert_called_once()

    def test_build_downloader(self, mock_print):
        """Verify list of bundled files for the downloader."""
        build._build_downloader(self._tempdir)
        self._verify_filenames(
            os.path.join(self._tempdir, build.DOWNLOAD_ZIPFILE + '.zip'),
            {'backoff/', 'cbapi/', 'main.py'},
            subset=True
        )
        mock_print.assert_called_once()

    def test_build_all(self, mock_print):
        """Verify that the top-level build function executes without error."""
        build.build(self._tempdir)
        self.assertEqual(4, mock_print.call_count)
