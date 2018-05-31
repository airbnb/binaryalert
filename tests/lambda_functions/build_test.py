"""Test lambda_functions/build.py."""
import os
import tempfile
from typing import List, Set
import unittest
from unittest import mock
import zipfile

from lambda_functions import build


def _mock_pip_main(args_list: List[str]) -> None:
    """Mock pip install just creates the target directory."""
    directory = args_list[6]
    packages = args_list[7:]
    for pkg in packages:
        os.makedirs(os.path.join(directory, pkg.split('==')[0]))


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
            filenames = set(zip_info.filename for zip_info in archive.filelist)
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
                # Python source files
                '__init__.py',
                'analyzer_aws_lib.py',
                'binary_info.py',
                'common.py',
                'file_hash.py',
                'main.py',
                'yara_analyzer.py',

                # Compiled rules file
                'compiled_yara_rules.bin',

                # Natively compiled binaries
                'libarchive.so.13',
                'libs/',
                'libs/bayshore_file_type_detect.o',
                'libs/bayshore_file_type_detect.yara',
                'libs/bayshore_yara_wrapper.o',
                'libs/bzl.o',
                'libs/pdf_parser.o',
                'libs/zl.o',
                'libfontconfig.so.1',
                'libfreetype.so.6',
                'libjbig.so.2.0',
                'libjpeg.so.62',
                'liblcms2.so.2',
                'liblzma.so.5',
                'liblzo2.so.2',
                'libopenjpeg.so.2',
                'libpcrecpp.so.0',
                'libpoppler.so.46',
                'libpng12.so.0',
                'libstdc++.so.6',
                'libtiff.so.5',
                'libyara.so.3',
                'libxml2.so.2',
                'pdftotext',
                'upx',
                'yara.so',
                'yextend',

                # Licenses
                'UPX_LICENSE',
                'YARA_LICENSE',
                'YARA_PYTHON_LICENSE',
                'YEXTEND_LICENSE'
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

    @mock.patch.object(build.subprocess, 'check_call', side_effect=_mock_pip_main)
    def test_build_downloader(self, mock_pip: mock.MagicMock, mock_print: mock.MagicMock):
        """Verify list of bundled files for the downloader."""
        build._build_downloader(self._tempdir)
        self._verify_filenames(
            os.path.join(self._tempdir, build.DOWNLOAD_ZIPFILE + '.zip'),
            {'cbapi/', 'main.py'},
            subset=True
        )
        mock_pip.assert_called_once()
        mock_print.assert_called_once()

    @mock.patch.object(build, '_build_analyzer')
    @mock.patch.object(build, '_build_batcher')
    @mock.patch.object(build, '_build_dispatcher')
    @mock.patch.object(build, '_build_downloader')
    def test_build_all(self, build_downloader: mock.MagicMock, build_dispatcher: mock.MagicMock,
                       build_batcher: mock.MagicMock, build_analyzer: mock.MagicMock,
                       mock_print: mock.MagicMock):
        """Verify that the top-level build function executes each individual builder."""
        build.build(self._tempdir, downloader=True)
        build_analyzer.assert_called_once()
        build_batcher.assert_called_once()
        build_dispatcher.assert_called_once()
        build_downloader.assert_called_once()
        mock_print.assert_not_called()
