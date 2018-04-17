"""Upload test files to S3 and see if the expected matches appear in Dynamo."""
import hashlib
import json
import os
import time
from typing import Dict, List
import uuid

import boto3

TEST_DIR = os.path.dirname(os.path.realpath(__file__))
TEST_FILES = ['eicar.txt', 'eicar.tar.gz.bz2', 'eicar_packed.py.upx', 'eicar_text.pdf']


def _upload_test_files_to_s3(bucket_name: str) -> Dict[str, str]:
    """Upload test files to S3 and returns a map from SHA256 to S3 identifier."""
    bucket = boto3.resource('s3').Bucket(bucket_name)
    random_suffix = str(uuid.uuid4()).split('-')[-1]

    result = {}
    for filename in TEST_FILES:
        filepath = os.path.join(TEST_DIR, 'files', filename)
        s3_object_key = '{}_{}'.format(filename, random_suffix)
        s3_full_identifier = 'S3:{}:{}'.format(bucket_name, s3_object_key)

        with open(filepath, 'rb') as f:
            sha256 = hashlib.sha256(f.read()).hexdigest()
        result[sha256] = s3_full_identifier

        print('Uploading {} to {}...'.format(filename, s3_full_identifier))
        bucket.upload_file(filepath, s3_object_key, ExtraArgs={'Metadata': {'filepath': filename}})

    return result


def _lambda_production_version(function_name: str) -> int:
    """Find the version associated with the Production alias of a Lambda function."""
    print('Looking up version of {}:Production...'.format(function_name))
    response = boto3.client('lambda').list_aliases(FunctionName=function_name)
    for alias in response['Aliases']:
        if alias['Name'] == 'Production':
            return int(alias['FunctionVersion'])
    return -1


def _query_dynamo_for_test_files(
        table_name: str, file_info: Dict[str, str], analyzer_version: int,
        max_attempts: int = 15) -> Dict[str, List[str]]:
    """Repeatedly query DynamoDB to look for the expected YARA matches.

    Args:
        table_name: Name of the DynamoDB match table.
        file_info: Dictionary from _upload_test_files_to_s3.
        analyzer_version: The underlying Lambda version for the Production alias of the analyzer.
        max_attempts: Max number of times to query for results (with 5 seconds between each).

    Returns:
        dict: Map from test filename (str) to list of matched YARA rules.
    """
    client = boto3.client('dynamodb')

    results = {}  # Map filename to list of matched rules.
    for attempt in range(1, max_attempts + 1):
        if attempt > 1:
            time.sleep(5)
        print('\t[{}/{}] Querying DynamoDB table for the expected YARA match entries...'.format(
            attempt, max_attempts))

        response = client.batch_get_item(
            RequestItems={
                table_name: {
                    'Keys': [
                        {
                            'SHA256': {'S': sha},
                            'AnalyzerVersion': {'N': str(analyzer_version)}
                        }
                        for sha in file_info
                    ]
                }
            }
        )['Responses'][table_name]

        for match in response:
            results[match['S3Metadata']['M']['filepath']['S']] = match['MatchedRules']['SS']

        if len(results) == len(file_info):
            break

    return results


def _cleanup(
        bucket_name: str, file_info: Dict[str, str], table_name: str,
        analyzer_version: int) -> None:
    """Remove test files and match information."""
    print('Removing test files from S3...')
    bucket = boto3.resource('s3').Bucket(bucket_name)
    bucket.delete_objects(
        Delete={
            'Objects': [
                {'Key': s3_identifier.split(':')[-1]}
                for s3_identifier in file_info.values()
            ]
        }
    )

    print('Removing DynamoDB match entries...')
    client = boto3.resource('dynamodb')

    client.batch_write_item(
        RequestItems={
            table_name: [
                {
                    'DeleteRequest': {
                        'Key': {
                            'SHA256': sha,
                            'AnalyzerVersion': analyzer_version
                        }
                    }
                }
                for sha in file_info
            ]
        }
    )


def run(bucket_name: str, analyzer_function_name: str, table_name: str) -> bool:
    """Upload an EICAR test file to BinaryAlert which should trigger a YARA match alert.

    Args:
        bucket_name: Name of the S3 bucket containing binaries.
        analyzer_function_name: Name of the YARA analyzer Lambda function.
        table_name: Name of the Dynamo table storing YARA match information.

    Returns:
        True if the test was successful, False otherwise.
    """
    test_file_info = _upload_test_files_to_s3(bucket_name)
    analyzer_version = _lambda_production_version(analyzer_function_name)
    results = _query_dynamo_for_test_files(table_name, test_file_info, analyzer_version)

    expected = {
        'eicar.txt': [
            'public/eicar.yara:eicar_av_test',
            'public/eicar.yara:eicar_substring_test',
            'yextend:eicar_av_test',
            'yextend:eicar_substring_test'
        ],
        'eicar.tar.gz.bz2': [
            'yextend:eicar_av_test',
            'yextend:eicar_substring_test'
        ],
        'eicar_packed.py.upx': [
            'public/eicar.yara:eicar_substring_test',
            'yextend:eicar_substring_test'
        ],
        'eicar_text.pdf': [
            'yextend:eicar_substring_test'
        ]
    }

    if results == expected:
        print('\nSUCCESS: Expected DynamoDB entries for the test files were found!')
        print(json.dumps(results, sort_keys=True, indent=4))
    else:
        print('\nFAIL: Expected DynamoDB entries for the test files were *not* found :(\n')
        print('Expected Results:')
        print(json.dumps(expected, sort_keys=True, indent=4))
        print('Actual Results:')
        print(json.dumps(results, sort_keys=True, indent=4))

    _cleanup(bucket_name, test_file_info, table_name, analyzer_version)
    print('Done!')
    return bool(results)
