Metrics and Monitoring
======================
BinaryAlert automatically generates logs, custom metrics, alarms, and a dashboard to help you visualize its performance. These are all part of the `AWS CloudWatch <https://aws.amazon.com/cloudwatch/>`_ service.


.. _cloudwatch_logs:

Logging
-------
Each BinaryAlert Lambda function logs information about its execution; logs are saved for 14 days (by default) and are accessible from AWS CloudWatch.


Custom Metrics
--------------
In addition to the wide array of `metrics provided automatically AWS <http://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CW_Support_For_AWS.html>`_, BinaryAlert publishes the following custom metrics in the ``BinaryAlert`` namespace:

====================  ============  =============================================
**Metric Name**       **Unit**      **Description**
--------------------  ------------  ---------------------------------------------
AnalyzedBinaries      Count         Number of binaries analyzed
MatchedBinaries       Count         Number of binaries which matched a YARA rule
S3DownloadLatency     Milliseconds  Time to download binaries from S3
YaraRules             Count         Number of compiled YARA rules
====================  ============  =============================================


.. _metric_alarms:

Metric Alarms
-------------
BinaryAlert creates metric alarms which trigger if BinaryAlert behavior is abnormal. Similar to :ref:`adding SNS subscriptions for YARA match alerts <add_sns_subscriptions>`, you will need to configure subscriptions for the ``NAME_PREFIX_binaryalert_metric_alarms`` SNS topic if you want to be notified about metric alarms.

Alarms can be configured from the ``terraform/terraform.tfvars`` configuration file, or else by directly modifying ``terraform/cloudwatch_metric_alarm.tf``. The alarm defaults are as follows:

=============  =============================  ======================================
**Namespace**  **Metric Name**                **Alarm Condition**
-------------  -----------------------------  --------------------------------------
AWS/DynamoDB   ThrottledRequests              > 0
AWS/Lambda     Errors                         > 0 (for each Lambda function)
AWS/SQS        ApproximateAgeOfOldestMessage  >= 75% of max age (for each SQS queue)
BinaryAlert    AnalyzedBinaries               == 0 for an hour
BinaryAlert    YaraRules                      < 5
=============  =============================  ======================================

The description for each alarm includes context and troubleshooting information.


.. _cloudwatch_dashboard:

Dashboard
---------
The aforementioned metrics (and many others) are aggregated into a single BinaryAlert dashboard at the following URL (substitute your region for ``us-east-1``): `https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#dashboards:name=BinaryAlert <https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#dashboards:name=BinaryAlert>`_.
