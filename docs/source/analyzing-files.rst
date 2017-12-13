Analyzing Files
===============
Files uploaded to the BinaryAlert S3 bucket will be automatically queued for analysis. You can also
use the analyzer to scan files from other buckets directly or in response to event notifications.

Uploading Files
---------------

To upload files for analysis, you need only upload them to the BinaryAlert S3 bucket. The S3 bucket name is of the form

.. code-block:: none

  YOUR.NAME.PREFIX.binaryalert-binaries.REGION

When uploading to S3, any object metadata you set will be included in all match alerts. In addition, if there is a ``filepath`` metadata key, BinaryAlert will make the filepath :ref:`external variables <external-variables>` available to the YARA rules.

Uploaded files are persisted indefinitely so that BinaryAlert can retroactively analyze all files with every rule update. The S3 bucket has both `access logging <http://docs.aws.amazon.com/AmazonS3/latest/dev/ServerLogs.html>`_ and `object versioning <http://docs.aws.amazon.com/AmazonS3/latest/dev/ObjectVersioning.html>`_ enabled.


.. _cb_downloader:

CarbonBlack Downloader
----------------------
If you use CarbonBlack Enterprise Response, you can enable BinaryAlert's optional downloader Lambda function. The downloader copies files (and some metadata) from CarbonBlack into BinaryAlert's S3 bucket. To enable it:

.. code-block:: none

  $ ./manage.py configure
  AWS Region (us-east-1):
  Unique name prefix, e.g. "company_team": your_unique_prefix
  Enable the CarbonBlack downloader? (no): yes
  CarbonBlack URL: https://your.carbonblack.url
  CarbonBlack API token (only needs binary read access):

.. warning:: The API token only needs access to read binaries. Do not use a token with admin privileges, do not allow other users to share the same token, and be sure to regularly rotate the token.

.. note:: The API token will not be shown on screen and BinaryAlert will create a new KMS key to encrypt the credentials before saving them to the ``terraform.tfvars`` configuration file. The downloader (and no other component) is authorized to decrypt the credentials with the generated key.

Binaries downloaded from CarbonBlack are saved to the BinaryAlert S3 bucket with the key ``carbonblack/MD5`` and with the following metadata:

.. code-block:: python

  [
      'carbon_black_group',
      'carbon_black_host_count',
      'carbon_black_last_seen',
      'carbon_black_md5',
      'carbon_black_os_type',
      'carbon_black_virustotal_score',
      'carbon_black_webui_link',
      'filepath'  # from the "observed_filenames" CarbonBlack metadata
  ]

Once the downloader is enabled, you can either copy everything from CarbonBlack in one go, or you can `deploy <deploying.html>`_ the downloader components and setup real-time invocations for every new binary.


Copy All Files
..............
If you want to run a one-time job to copy every file from CarbonBlack into BinaryAlert:

.. code-block:: bash

  $ ./manage.py cb_copy_all

This runs *locally*, using multiple threads to enumerate the files in CarbonBlack and copy them over to BinaryAlert. The downloader *code* is used, but there are no Lambda invocations. This means you can copy all of the files from CarbonBlack without actually deploying the downloader components.


Real-Time Invocations
.....................
To ensure real-time file analysis, we recommend invoking the downloader every time CarbonBlack logs a ``binarystore.file.added`` event. If you use `StreamAlert <https://streamalert.io/>`_ to process CarbonBlack logs, the following `rule <https://streamalert.io/rules.html>`_ will invoke the BinaryAlert downloader for every new binary (assuming BinaryAlert is a properly configured Lambda `output <https://streamalert.io/outputs.html>`_):

.. code-block:: python

  @rule(logs=['carbonblack:binarystore.file.added'],
        matchers=[],
        outputs=['aws-lambda:binaryalert'])
  def cb_binarystore_file_added(rec):
      """
      description: CarbonBlack found a new binary: forward to BinaryAlert for YARA analysis.
      """
      return True

If you don't use StreamAlert, you can invoke the downloader yourself:

.. code-block:: python

  import boto3, json
  boto3.client('lambda').invoke(
      FunctionName='your_prefix_binaryalert_downloader',
      InvocationType='Event',  # Asynchronous invocation
      Qualifier='Production',  # Invoke production alias
      Payload=json.dumps({'md5': 'FILE_MD5'}).encode('utf-8')
  )


Analyzing Existing Buckets
--------------------------
As of v1.1, the BinaryAlert YARA analyzer is no longer restricted to just its own S3 bucket - it can
read other existing buckets as well. To grant access to other buckets, modify the analyzer's
IAM policy in `lambda_iam.tf <https://github.com/airbnb/binaryalert/blob/master/terraform/lambda_iam.tf>`_.

Direct Invocation
.................
You can directly invoke the BinaryAlert analyzer to scan any S3 object it has access to:

.. code-block:: python

  import boto3, json

  response = boto3.client('lambda').invoke(
      FunctionName='your_prefix_binaryalert_analyzer',
      InvocationType='RequestResponse',
      Qualifier='Production',
      Payload=json.dumps({
          'Records': [
              {
                  's3': {
                      'bucket': {'name': 'BUCKET-NAME'},
                      'object': {'key': 'KEY1'}
                  }
              },
              {
                  's3': {
                      'bucket': {'name': 'BUCKET-NAME'},
                      'object': {'key': 'KEY2'}
                  }
              }
          ]
      })
  )

  decoded = json.loads(response['Payload'].read().decode('utf-8'))
  print(decoded)

  {
      'S3:BUCKET-NAME:KEY1': {
          'FileInfo': {
              'MD5': '...',
              'S3LastModified': '...',
              'S3Metadata': {},
              'SHA256': '...'
          },
          'MatchedRules': {
              'Rule1':
                  'MatchedStrings': ['$a'],
                  'Meta': {
                      'description': 'Test YARA rule'
                  },
                  'RuleFile': 'rules.yara',
                  'RuleName': 'test_dummy_true'
           },
           'NumMatchedRules': 1
      }
      'S3:BUCKET-NAME:KEY2': {
          'FileInfo': {
              'MD5': '...',
              'S3LastModified': '...',
              'S3Metadata': {},
              'SHA256': '...'
          },
          'MatchedRules': {},
          'NumMatchedRules': 0
      }
  }

.. note:: The analyzer will always save YARA matches to Dynamo and send alerts to the SNS topic, even when invoked directly or when analyzing other buckets.

Configuring Event Notifications
...............................
You can configure other buckets to send S3 event notifications to the BinaryAlert SQS queue
(recommended) or to the analyzer directly. In either case, once configured, BinaryAlert will be
automatically analyzing your existing buckets in addition to its own.
See `AWS: Enable Event Notifications <http://docs.aws.amazon.com/AmazonS3/latest/user-guide/enable-event-notifications.html>`_
and a `terraform example <https://www.terraform.io/docs/providers/aws/r/s3_bucket_notification.html#add-notification-configuration-to-sqs-queue>`_ to get started.