"""Lambda function to copy a binary from CarbonBlack into the BinaryAlert input S3 bucket."""
# Expects the following environment variables:
#   CARBON_BLACK_URL: URL of the CarbonBlack server.
#   ENCRYPTED_CARBON_BLACK_API_TOKEN: API token, encrypted with KMS.
#   TARGET_S3_BUCKET: Name of the S3 bucket in which to save the copied binary.
import base64
import logging
import os
import shutil
from typing import Any, Dict
import zipfile

import backoff
import boto3
from botocore.exceptions import BotoCoreError
import cbapi
from cbapi.errors import ObjectNotFoundError
from cbapi.response.models import Binary

LOGGER = logging.getLogger()
LOGGER.setLevel(logging.INFO)
logging.getLogger('backoff').addHandler(logging.StreamHandler())  # Enable backoff logger.

ENCRYPTED_TOKEN = os.environ['ENCRYPTED_CARBON_BLACK_API_TOKEN']
DECRYPTED_TOKEN = boto3.client('kms').decrypt(
    CiphertextBlob=base64.b64decode(ENCRYPTED_TOKEN)
)['Plaintext']

# Establish boto3 and S3 clients at import time so Lambda can cache them for re-use.
CARBON_BLACK = cbapi.CbEnterpriseResponseAPI(
    url=os.environ['CARBON_BLACK_URL'], token=DECRYPTED_TOKEN)
S3_BUCKET = boto3.resource('s3').Bucket(os.environ['TARGET_S3_BUCKET'])


@backoff.on_exception(backoff.expo, ObjectNotFoundError, max_tries=8, jitter=backoff.full_jitter)
def _download_from_carbon_black(binary: Binary) -> str:
    """Download the binary from CarbonBlack into /tmp.

    WARNING: CarbonBlack truncates binaries to 25MB. The MD5 will cover the entire file, but only
    the first 25MB of the binary will be downloaded.

    Args:
        binary: CarbonBlack binary instance.

    Returns:
        Path where file was downloaded.
    """
    download_path = '/tmp/carbonblack_{}'.format(binary.md5)
    LOGGER.info('Downloading %s to %s', binary.webui_link, download_path)
    with binary.file as cb_file, open(download_path, 'wb') as target_file:
        shutil.copyfileobj(cb_file, target_file)
    return download_path


@backoff.on_exception(backoff.expo, (ObjectNotFoundError, zipfile.BadZipFile), max_tries=8,
                      jitter=backoff.full_jitter)
def _build_metadata(binary: Binary) -> Dict[str, str]:
    """Return basic CarbonBlack metadata to make it easier to triage YARA match alerts."""
    LOGGER.info('Retrieving binary metadata')
    return {
        'carbon_black_group': ','.join(binary.group),
        'carbon_black_host_count': str(binary.host_count),
        'carbon_black_last_seen': binary.last_seen,
        'carbon_black_md5': binary.md5,
        'carbon_black_observed_filename': (
            # Throw out any non-ascii characters (S3 metadata must be ascii).
            binary.observed_filenames[0].encode('ascii', 'ignore').decode('ascii')
        ),
        'carbon_black_os_type': binary.os_type,
        'carbon_black_virustotal_score': str(binary.virustotal.score)
    }


@backoff.on_exception(backoff.expo, BotoCoreError, max_tries=3, jitter=backoff.full_jitter)
def _upload_to_s3(md5: str, local_file_path: str, metadata: Dict[str, str]) -> str:
    """Upload the binary contents to S3 along with the given object metadata.

    Args:
        md5: CarbonBlack MD5 key (used as the S3 object key).
        local_file_path: Path to the file to upload.
        metadata: Binary metadata to attach to the S3 object.

    Returns:
        The newly added S3 object key (based on CarbonBlack's MD5).
    """
    s3_object_key = 'carbonblack/{}'.format(md5)
    LOGGER.info('Uploading to S3 with key %s', s3_object_key)
    with open(local_file_path, 'rb') as target_file:
        S3_BUCKET.put_object(Body=target_file, Key=s3_object_key, Metadata=metadata)
    return s3_object_key


def download_lambda_handler(event: Dict[str, Any], _) -> str:
    """Lambda function entry point - copy a binary from CarbonBlack into the BinaryAlert S3 bucket.

    Args:
        event: Invocation event, containing at least {'md5': '<carbon-black-md5>'}.
        _: Unused Lambda context object.

    Returns:
        The newly added S3 object key for the uploaded binary.
    """
    LOGGER.info('Invoked with event %s', event)

    binary = CARBON_BLACK.select(Binary, event['md5'])
    download_path = _download_from_carbon_black(binary)
    metadata = _build_metadata(binary)
    s3_object_key = _upload_to_s3(binary.md5, download_path, metadata)

    # Truncate and remove the downloaded file (os.remove does not work as expected in Lambda).
    with open(download_path, 'w') as file:
        file.truncate()
    os.remove(download_path)

    return s3_object_key
