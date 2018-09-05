Analyzing Files
===============
Files uploaded to the BinaryAlert S3 bucket will be automatically queued for analysis. You can also
invoke the analyzer directly, scan files in other buckets, or download files from CarbonBlack.

Uploading Files
---------------

All files uploaded to the BinaryAlert S3 bucket will be immediately queued for analysis. The S3 bucket name is of the form

.. code-block:: none

  YOUR.NAME.PREFIX.binaryalert-binaries.REGION

When uploading to S3, any object metadata you set will be included in all match alerts. In addition, if there is a ``filepath`` metadata key, BinaryAlert will make the filepath :ref:`external variables <external-variables>` available to the YARA rules.

Uploaded files are persisted indefinitely so that BinaryAlert can retroactively analyze all files.
The S3 bucket has `access logging <http://docs.aws.amazon.com/AmazonS3/latest/dev/ServerLogs.html>`_, `object versioning <http://docs.aws.amazon.com/AmazonS3/latest/dev/ObjectVersioning.html>`_, `inventory <https://docs.aws.amazon.com/AmazonS3/latest/dev/storage-inventory.html>`_, and `server-side encryption <https://docs.aws.amazon.com/AmazonS3/latest/dev/serv-side-encryption.html>`_ enabled.


Analyzing Existing Buckets
--------------------------
To scan files in other S3 buckets, you first need to grant BinaryAlert permission to access them. Modify the S3 section of your `terraform.tfvars <https://github.com/airbnb/binaryalert/blob/master/terraform/terraform.tfvars>`_ file and `deploy <deploying.html>`_ the changes:

.. code-block:: terraform

  # ##### S3 #####

  # If using BinaryAlert to scan existing S3 buckets, add the S3 and KMS resource ARNs here
  # (KMS if the objects are server-side encrypted)
  external_s3_bucket_resources = ["arn:aws:s3:::bucket-name/*"]
  external_kms_key_resources = ["arn:aws:kms:REGION:ACCOUNT:key/KEY-UUID"]


Direct Invocation
.................
You can directly invoke the BinaryAlert analyzer to scan any S3 object it has access to. The match
results will always be saved to Dynamo, but you can configure whether each request should also trigger
the normal SNS alerts:

.. code-block:: python

  import boto3, json

  response = boto3.client('lambda').invoke(
      FunctionName='your_prefix_binaryalert_analyzer',
      InvocationType='RequestResponse',
      Payload=json.dumps({
          'BucketName': 'your-bucket-name',  # S3 bucket name
          'EnableSNSAlerts': False,          # Toggle SNS alerts
          'ObjectKeys': ['key1', 'key2']     # List of S3 object keys
      }),
      Qualifier='Production'
  )

  results = json.loads(response['Payload'].read().decode('utf-8'))
  print(json.dumps(results, sort_keys=True, indent=4))

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
                  'MatchedData': ['abc'],
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

Configuring Event Notifications
...............................
You can configure other buckets to send S3 event notifications to the BinaryAlert SQS queue.
To do so, create an `event notification <http://docs.aws.amazon.com/AmazonS3/latest/user-guide/enable-event-notifications.html>`_ on your existing bucket
and then modify the `BinaryAlert SQS permissions <https://github.com/airbnb/binaryalert/blob/ea5c31ee55a483e5216296e3e0598e3318b7eb24/terraform/sqs.tf#L28-L33>`_ accordingly.
Once configured, BinaryAlert will be automatically analyzing new objects in your existing buckets in addition to its own.


.. _retro_scan:

Retroactive Analysis
--------------------
When adding new YARA rules to your collection, you can easily re-scan all of your files in the BinaryAlert bucket to see if any of them match the new rules:

.. code-block:: bash

  $ ./manage.py retro_fast

This will enumerate the most recent `S3 inventory manifest <https://docs.aws.amazon.com/AmazonS3/latest/dev/storage-inventory.html>`_, adding all object keys to the analysis SQS queue.
However, if your bucket is less than 48 hours old, it may not yet have an inventory manifest. In that case, you can list the objects yourself:

.. code-block:: bash

  $ ./manage.py retro_slow

As its name suggests, enumerating the bucket directly will generally be much slower than reading the inventory, particularly for buckets with thousands of objects or more.

.. note:: Because the inventory may be up to 24 hours old, a ``retro_fast`` scan may miss the newest objects in the bucket. If you need to scan *all* files immediately, use ``retro_slow``.

In either case, once all of the objects are in the analyzer SQS queue, it will take some time for BinaryAlert to finish scanning all of them (depending on how many objects you have).
`YARA matches <yara-matches.html>`_ found during a retroactive scan are treated like any other - the matches are saved to Dynamo and reported via SNS.

Stopping a Retro Scan
.....................
Sometimes, a new YARA rule you thought would be great turns out to be super noisy, flooding you with false positive alerts.
Unfortunately, if you have millions of objects in your BinaryAlert bucket, a retro scan can take hours to finish.
To stop a retro scan dead in its tracks, you can drop all messages from the analysis queue:

.. code-block:: bash

  $ ./manage.py purge_queue

.. warning:: This will also drop any event notifications from newly added objects that arrived after the retro scan started. These objects won't be scanned again until either (a) the next ``retro_slow`` scan or (b) the next ``retro_fast`` after 24 hours when the new object is in the inventory.


.. _cb_downloader:

CarbonBlack Downloader
----------------------
If you use CarbonBlack Enterprise Response, you can enable BinaryAlert's optional downloader SQS queue and Lambda function.
The downloader copies files (and some metadata) from CarbonBlack into BinaryAlert's S3 bucket. To enable it:

.. code-block:: none

  $ ./manage.py configure
  AWS Region (us-east-1):
  Unique name prefix, e.g. "company_team": your_unique_prefix
  Enable the CarbonBlack downloader? (no): yes
  CarbonBlack URL: https://your.carbonblack.url
  CarbonBlack API token (only needs binary read access):

  $ ./manage.py deploy

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


Copy All Files
..............
If you want to run a one-time job to copy every file from CarbonBlack into BinaryAlert:

.. code-block:: bash

  $ ./manage.py cb_copy_all

This runs locally, using multiple threads to enumerate the files in CarbonBlack into the BinaryAlert downloader SQS queue.


Real-Time Invocations
.....................
For real-time file analysis, we recommend publishing to the downloader SQS queue every time CarbonBlack logs a ``binarystore.file.added`` event. If you use `StreamAlert <https://streamalert.io/>`_ to process CarbonBlack logs, the following `rule <https://streamalert.io/rules.html>`_ will publish a message for every new binary (assuming the SQS queue is a properly configured StreamAlert `output <https://streamalert.io/outputs.html>`_):

.. code-block:: python

  @rule(logs=['carbonblack:binarystore.file.added'], outputs=['aws-sqs:binaryalert'])
  def cb_binarystore_file_added(rec):
      """
      description: CarbonBlack found a new binary: forward to BinaryAlert for YARA analysis.
      """
      return True

You can also directly publish messages to the downloader SQS queue. Messages are expected to be in the very simple format ``{'md5': 'ABCDE....'}``
