YARA Matches
============
When BinaryAlert finds a file that matches at least one YARA rule, it will save the match information to a DynamoDB table and send an alert to the ``NAME_PREFIX_binaryalert_yara_matches`` SNS topic (if it hasn't already).

You can also opt to notify a different SNS topic for files which did *not* match any YARA rules.


DynamoDB Records
----------------
All YARA matches are saved to a DynamoDB table. The table has two primary keys, ``AnalyzerVersion`` and ``SHA256``. This makes it easy to find every match associated with a given file or, conversely, to find all matches from a specific :ref:`version <lambda_versioning>` of your BinaryAlert deployment.

A ``manage.py live_test`` will show you an example of the match record stored in the DynamoDB table:

.. code-block:: python

  {
      'AnalyzerVersion': Decimal('1'),
      'MD5': 'FILE_MD5',
      'MatchedRules': {'public/eicar.yara:eicar_av_test'},
      'S3LastModified': '2017-09-16 00:25:37+00:00',
      'S3Metadata': {'filepath': 'eicar_test_UUID.txt'},
      'S3Objects': {'S3:NAME.PREFIX.binaryalert-binaries.REGION:eicar_test_UUID.txt'},
      'SHA256': 'FILE_SHA256'
  }


SNS Match Alerts
----------------
In addition to saving the DynamoDB record, an alert is sent to the ``NAME_PREFIX_binaryalert_yara_matches`` SNS topic when one of the following conditions apply:

1. The file matches a YARA rule that was not matched in the previous version of the BinaryAlert analyzers, OR
2. A new S3 object appears which is identical to an already matched binary.

Without these conditions, an alert would trigger for every match in every :ref:`retroactive analysis<retro_scan>`. Instead, an alert triggers only when there is a **new** match.

.. note:: You must :ref:`add an SNS subscription <add_sns_subscriptions>` in order to receive YARA match alerts.


SNS Non-Match Alerts
--------------------
If you'd like to be notified in real time when a scanned file did *not* match any YARA rules, enable the corresponding config option in `terrform.tfvars <https://git.musta.ch/csirt/binaryalert/blob/14b48a868d0d858d98f1bfae60d030eb72c010a7/terraform/terraform.tfvars#L102-L104>`_ and `redeploy <deploying.html>`_:

.. code-block:: terraform

  ##### SNS #####
  # Create a separate SNS topic which reports files that do NOT match any YARA rules.
  enable_negative_match_alerts = true
