"""Lambda function to copy a binary from CarbonBlack into the BinaryAlert input S3 bucket."""
# Expects the following environment variables:
#   CARBON_BLACK_URL: URL of the CarbonBlack server.
#   ENCRYPTED_CARBON_BLACK_API_TOKEN: API token, encrypted with KMS.
#   TARGET_S3_BUCKET: Name of the S3 bucket in which to save the copied binary.
import base64
import collections
import json
import logging
import os
import shutil
import subprocess
import tempfile
from typing import Any, Dict, Generator, List
import zipfile

import boto3
from botocore.exceptions import BotoCoreError
import cbapi
from cbapi.errors import ObjectNotFoundError, ServerError
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
CLOUDWATCH = boto3.client('cloudwatch')
S3_BUCKET = boto3.resource('s3').Bucket(os.environ['TARGET_S3_BUCKET'])
SQS = boto3.resource('sqs')

# The download invocation event is parsed into a tuple with MD5 and a Receipt
DownloadRecord = collections.namedtuple('DownloadRecord', ['md5', 'sqs_receipt', 'receive_count'])


def _iter_download_records(event: Any) -> Generator[DownloadRecord, None, None]:
    """Generate DownloadRecords from the invocation event."""
    for message in event['messages']:
        try:
            md5 = json.loads(message['body'])['md5']
            yield DownloadRecord(md5, message['receipt'], message['receive_count'])
        except (json.JSONDecodeError, KeyError, TypeError):
            LOGGER.exception('Skipping invalid SQS record: %s', message)
            continue


def _download_from_carbon_black(binary: Binary) -> str:
    """Download the binary from CarbonBlack into /tmp.

    WARNING: CarbonBlack truncates binaries to 25MB. The MD5 will cover the entire file, but only
    the first 25MB of the binary will be downloaded.

    Args:
        binary: CarbonBlack binary instance.

    Returns:
        Path where file was downloaded.
    """
    download_path = os.path.join(tempfile.gettempdir(), 'carbonblack_{}'.format(binary.md5))
    LOGGER.info('Downloading %s to %s', binary.webui_link, download_path)
    with binary.file as cb_file, open(download_path, 'wb') as target_file:
        shutil.copyfileobj(cb_file, target_file)
    return download_path


def _build_metadata(binary: Binary) -> Dict[str, str]:
    """Return basic metadata to make it easier to triage YARA match alerts."""
    return {
        'carbon_black_group': (
            ','.join(binary.group) if isinstance(binary.group, list) else binary.group),
        'carbon_black_last_seen': binary.last_seen,
        'carbon_black_md5': binary.md5,
        'carbon_black_os_type': binary.os_type,
        'carbon_black_virustotal_score': str(binary.virustotal.score),
        'carbon_black_webui_link': binary.webui_link,
        'filepath': (
            # Throw out any non-ascii characters (S3 metadata must be ascii).
            binary.observed_filenames[0].encode('ascii', 'ignore').decode('ascii')
            if binary.observed_filenames else '(unknown)'
        )
    }


def _upload_to_s3(md5: str, local_file_path: str, metadata: Dict[str, str]) -> None:
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


def _process_md5(md5: str) -> bool:
    """Download the given file from CarbonBlack and upload to S3, returning True if successful."""
    download_path = None
    try:
        binary = CARBON_BLACK.select(Binary, md5)
        download_path = _download_from_carbon_black(binary)
        metadata = _build_metadata(binary)
        _upload_to_s3(binary.md5, download_path, metadata)
        return True
    except (BotoCoreError, ObjectNotFoundError, ServerError, zipfile.BadZipFile):
        LOGGER.exception('Error downloading %s', md5)
        return False
    finally:
        if download_path:
            # Shred downloaded file before exiting.
            subprocess.check_call(['shred', '--remove', download_path])


def _delete_sqs_messages(queue_url: str, receipts: List[str], ) -> None:
    """Mark a batch of SQS receipts as completed (removing them from the queue)."""
    LOGGER.info('Deleting %d SQS receipt(s)', len(receipts))
    SQS.Queue(queue_url).delete_messages(
        Entries=[
            {'Id': str(index), 'ReceiptHandle': receipt} for index, receipt in enumerate(receipts)
        ]
    )


def _publish_metrics(receive_counts: List[int]) -> None:
    """Send a statistic summary of receive counts."""
    LOGGER.info('Sending ReceiveCount metrics')
    CLOUDWATCH.put_metric_data(
        Namespace='BinaryAlert', MetricData=[{
            'MetricName': 'DownloadQueueReceiveCount',
            'StatisticValues': {
                'Minimum': min(receive_counts),
                'Maximum': max(receive_counts),
                'SampleCount': len(receive_counts),
                'Sum': sum(receive_counts)
            },
            'Unit': 'Count'
        }]
    )


def download_lambda_handler(event: Dict[str, Any], _: Any) -> None:
    """Lambda function entry point - copy a binary from CarbonBlack into the BinaryAlert S3 bucket.

    Args:
        event: SQS message batch sent by the dispatcher: {
            'messages': [
                {
                    'body': (str) '{"md5": "FILE_MD5"}',
                    'receipt': (str) SQS message receipt handle,
                    'receive_count': (int) Approximate number of times this has been received
                },
                ...
            ],
            'queue_url': (str) SQS queue url from which the message originated
        }
        _: Unused Lambda context
    """
    receipts_to_delete = []  # SQS receipts which can be deleted.
    receive_counts = []  # A list of message receive counts.

    for record in _iter_download_records(event):
        if _process_md5(record.md5):
            # File was copied successfully - the receipt can be deleted
            receipts_to_delete.append(record.sqs_receipt)
            receive_counts.append(record.receive_count)

    if receipts_to_delete:
        _delete_sqs_messages(event['queue_url'], receipts_to_delete)

    if receive_counts:
        _publish_metrics(receive_counts)
