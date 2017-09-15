Uploading Files
===============
To upload files for analysis, you need only upload them to the BinaryAlert S3 bucket. The S3 bucket name is of the form

.. code-block:: none

  YOUR.NAME.PREFIX.binaryalert-binaries.REGION

When uploading to S3, any object metadata you set will be included in all match alerts. In addition, if there is a ``filepath`` metadata key, BinaryAlert will make the filepath :ref:`external-variables` available to the YARA rules.

Uploaded files are persisted indefinitely so that BinaryAlert can retroactively analyze all files with every rule update. The S3 bucket has both `access logs <http://docs.aws.amazon.com/AmazonS3/latest/dev/ServerLogs.html>`_ and `object versioning <http://docs.aws.amazon.com/AmazonS3/latest/dev/ObjectVersioning.html>`_ enabled.


CarbonBlack Downloader
----------------------
If you use CarbonBlack Enterprise Response, you can enable BinaryAlert's optional downloader Lambda function. The downloader takes an MD5 as input and copies the file from CarbonBlack into BinaryAlert's S3 bucket (with the appropriate metadata). To enable it:

.. code-block:: none

  $ ./manage.py configure
  AWS Region (us-east-1):
  Unique name prefix, e.g. "company_team": your_unique_prefix
  Enable the CarbonBlack downloader? (no): yes
  CarbonBlack URL: https://your.carbonblack.url
  CarbonBlack API token (only needs binary read access):

.. warning:: The API token only needs access to read binaries; do not use a token with admin privileges, do not allow other users to share the same token, and be sure to regularly rotate the token.

.. note:: The API token will not be shown on screen and BinaryAlert will create a new KMS key to encrypt the credentials before saving them to the ``terraform.tfvars`` configuration file. The downloader (and no other component) is authorized to decrypt the credentials with the generated key.

Once BinaryAlert is deployed with the new configuration, invoking the downloader is as simple as:

.. code-block:: python

  import boto3, json
  boto3.client('lambda').invoke(
      FunctionName='your_prefix_binaryalert_downloader',
      InvocationType='Event',  # Asynchronous invocation
      Qualifier='Production',  # Invoke production alias
      Payload=json.dumps({'md5': 'FILE_MD5'}).encode('utf-8')
  )

Binaries downloaded from CarbonBlack are saved to the BinaryAlert S3 bucket with the key ``carbonblack/MD5`` and with the following metadata keys:

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
