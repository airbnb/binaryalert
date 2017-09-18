Troubleshooting / FAQ
=====================


How long does it take a file to be analyzed?
--------------------------------------------
Under normal operation, the analysis is usually finished within 1-2 minutes after being uploaded to the S3 bucket.


What's the filesize limit?
--------------------------
The limiting factor is the `space Lambda allocates for "/tmp" <http://docs.aws.amazon.com/lambda/latest/dg/limits.html#limits-list>`_, i.e. **512 MB**. If you use the :ref:`downloader <cb_downloader>`, note that CarbonBlack automatically truncates files to 25 MB.


How much does BinaryAlert cost?
-------------------------------
The two biggest costs are the S3 storage and Lambda invocations, so it will depend on how many files you have and how often you re-analyze all of them. A rough estimate at current rates is `$0.057 / GB / month <https://medium.com/@austinbyers/good-question-693200ef5830>`_.


Does BinaryAlert automatically test YARA rules?
------------------------------------------------
BinaryAlert ensures that the YARA rules compile correctly before every deploy, but it does not verify that YARA rules match any particular files. However, you can :ref:`test your rules locally <testing_yara_rules>`.


Why did my live test fail?
--------------------------
Check the :ref:`Lambda execution logs <cloudwatch_logs>` and the :ref:`BinaryAlert dashboard <cloudwatch_dashboard>` for abnormalities. A common problem is that the BinaryAlert analyzers don't understand the compiled YARA rules file. Make sure your `virtual environment <getting-started.html>`_ is set up correctly and that your YARA rules only use the :ref:`supported modules <supported_yara_modules>`. It is also possible that one or more AWS components might be down.


How do I setup YARA match / metric alarm alerts?
------------------------------------------------
You have to :ref:`add a subscription <add_sns_subscriptions>` to the generated SNS topic.


Analyzer timeouts
-----------------
Analyzers can sometimes time out while downloading files from S3. If the analyzers are timing out during a retroactive (batch) analysis, you can lower the ``lambda_batch_objects_per_message`` configuration option in ``terraform/terraform.tfvars``.


Why are there regular downloader errors?
----------------------------------------
The CarbonBlack server can sometimes take several minutes before binaries and their metadata are available.


Terraform destroy fails because "bucket is not empty"
-----------------------------------------------------
The ``force_destroy`` configuration option must be applied before destroying; see the :ref:`terraform destroy <terraform_destroy>` documentation.


Contact Us
----------
If your question wasn't answered here, feel free to `open an issue <https://github.com/airbnb/binaryalert/issues>`_ or `ping us on Slack <https://binaryalert.herokuapp.com/>`_!
