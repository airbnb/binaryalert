Troubleshooting / FAQ
=====================


How long does it take a file to be analyzed?
--------------------------------------------
Under normal operation, the analysis is usually finished within 1-2 minutes after being uploaded to the S3 bucket.


What's the filesize limit?
--------------------------
The limiting factor is the `space Lambda allocates for "/tmp" <http://docs.aws.amazon.com/lambda/latest/dg/limits.html#limits-list>`_, i.e. **512 MB**. If you use the :ref:`downloader <cb_downloader>`, note that CarbonBlack automatically truncates files to 25 MB.


YARA rules with "hash" or "imphash" fail to compile
---------------------------------------------------
If the openssl development libraries aren't on your system when installing YARA, the ``hash`` module
won't work (`example <https://github.com/airbnb/binaryalert/issues/74>`_).
Be sure to follow instructions for :ref:`Installing Dependencies <dependencies>`.


How much does BinaryAlert cost?
-------------------------------
The two biggest costs are the S3 storage and Lambda invocations, so it will depend on how many files you have and how often you re-analyze all of them, but generally no more than a few hundred dollars per month for several TB worth of files.


Does BinaryAlert automatically test YARA rules?
------------------------------------------------
BinaryAlert ensures that the YARA rules compile correctly before every deploy, but it does not verify that YARA rules match any particular files. However, you can :ref:`test your rules locally <testing_yara_rules>`.


Why did my live test fail?
--------------------------
Check the :ref:`Lambda execution logs <cloudwatch_logs>` and the :ref:`BinaryAlert dashboard <cloudwatch_dashboard>` for abnormalities.
A common problem is that the BinaryAlert analyzers don't understand the compiled YARA rules file.
Make sure your `virtual environment <getting-started.html>`_ is set up correctly with the same YARA version and that your YARA rules only use the :ref:`supported modules <supported_yara_modules>`.

It may take 1-3 minutes after a deploy before the Lambda functions are ready to go. If a live test fails immediately after a deploy, wait a few minutes and try again.

Finally, if BinaryAlert is in the middle of a :ref:`retroactive scan <retro_scan>`, the analysis queue may be backlogged.


How do I setup YARA match / metric alarm alerts?
------------------------------------------------
You have to :ref:`add a subscription <add_sns_subscriptions>` to the generated SNS topic.


Analyzer timeouts
-----------------
Analyzers can sometimes time out while downloading files from S3. If the analyzers are timing out during a :ref:`retroactive scan <retro_scan>`, you can lower the ``objects_per_retro_message`` configuration option in ``terraform/terraform.tfvars``.


Terraform destroy fails because "bucket is not empty"
-----------------------------------------------------
By default, BinaryAlert S3 buckets can't be deleted until they are empty. ``./manage.py destroy``
will ask if you want to override this setting. See the :ref:`teardown <teardown>` documentation for more information.


Contact Us
----------
If your question wasn't answered here, feel free to `open an issue <https://github.com/airbnb/binaryalert/issues>`_ or `ping us on Slack <https://binaryalert.herokuapp.com/>`_!
