"""Unit tests for the CarbonBlack downloading Lambda function."""
# pylint: disable=protected-access
import base64
import io
import os
import tempfile
from unittest import mock

import boto3
import cbapi
from pyfakefs import fake_filesystem_unittest


class MockBinary(object):
    """Mock for cbapi.response.models.Binary."""

    class MockVirusTotal(object):
        """Mock for cbapi.response.models.VirusTotal."""

        def __init__(self, score: int = 0) -> None:
            self.score = score

    def __init__(self, contents: bytes, **kwargs) -> None:
        self.contents = contents
        self.properties = dict(kwargs)

    def __getattr__(self, attr: str):
        if attr == 'file':
            return io.BytesIO(self.contents)
        return self.properties[attr]


class MainTest(fake_filesystem_unittest.TestCase):
    """Test each function in downloader/main.py"""

    def setUp(self):
        """Mock out CarbonBlack and boto3 before importing the module."""
        os.environ['CARBON_BLACK_URL'] = 'test-carbon-black-url'
        os.environ['ENCRYPTED_CARBON_BLACK_API_TOKEN'] = base64.b64encode(
            b'super-secret').decode('ascii')
        os.environ['TARGET_S3_BUCKET'] = 'test-s3-bucket'

        # Setup fake filesystem.
        temp_dir = tempfile.gettempdir()  # Get real temp directory before starting fake filesystem.
        self.setUpPyfakefs()
        os.makedirs(temp_dir)

        # Create a mock binary.
        self._binary = MockBinary(
            b'hello world',
            group=['Production', 'Laptops'],
            host_count=2,
            last_seen='sometime-recently',
            md5='ABC123',
            observed_filenames=['/Users/name/file.txt'],
            os_type='Linux',
            virustotal=MockBinary.MockVirusTotal(),
            webui_link='example.com'
        )

        # Mock out cbapi and import the file under test.
        with mock.patch.object(boto3, 'client'), mock.patch.object(boto3, 'resource'), \
                mock.patch.object(cbapi, 'CbEnterpriseResponseAPI'):
            from lambda_functions.downloader import main
            self.download_main = main

    def test_download_from_carbon_black(self):
        """Verify that a CarbonBlack binary is uploaded correctly to S3."""
        with mock.patch.object(self.download_main.CARBON_BLACK, 'select') as mock_select, \
                mock.patch.object(self.download_main.LOGGER, 'info') as mock_info_logger, \
                mock.patch.object(self.download_main.os, 'remove'):
            mock_select.return_value = self._binary

            upload_s3_key = self.download_main.download_lambda_handler({'md5': 'ABC123'}, None)

            # Check return value.
            self.assertEqual('carbonblack/ABC123', upload_s3_key)

            expected_metadata = {
                'carbon_black_group': 'Production,Laptops',
                'carbon_black_host_count': '2',
                'carbon_black_md5': 'ABC123',
                'carbon_black_os_type': 'Linux',
                'carbon_black_virustotal_score': '0',
                'filepath': '/Users/name/file.txt'
            }

            self.download_main.S3_BUCKET.assert_has_calls([
                mock.call.put_object(
                    Body=mock.ANY, Key='carbonblack/ABC123', Metadata=expected_metadata
                )
            ])

            # Verify the log statements.
            mock_info_logger.assert_has_calls([
                mock.call('Invoked with event %s', {'md5': 'ABC123'}),
                mock.call(
                    'Downloading %s to %s', self._binary.webui_link, mock.ANY),
                mock.call('Retrieving binary metadata'),
                mock.call('Uploading to S3 with key %s', upload_s3_key)
            ])
