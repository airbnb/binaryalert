Deploying
=========
After you've `setup your environment <getting-started.html>`_, deploying BinaryAlert is as easy as:

.. code-block:: bash

  $ ./manage.py deploy

A ``deploy`` is equivalent to the following 3 operations executed in sequence:

.. code-block:: bash

  $ ./manage.py unit_test  # Unit tests ensure YARA rules compile correctly
  $ ./manage.py build      # Build the Lambda ".zip" deployment package(s)
  $ ./manage.py apply      # Update the infrastructure and deploy Lambda functions


.. _lambda_versioning:

Lambda Versions and Aliases
---------------------------
Each BinaryAlert Lambda function has a ``Production`` alias which points to the most recent version of that function. Every time a deploy changes one of the Lambda deployment packages, a new version is published and the ``Production`` alias is updated accordingly. For more information, see `AWS Lambda Function Versioning and Aliases <http://docs.aws.amazon.com/lambda/latest/dg/versioning-aliases.html>`_.


.. _add_sns_subscriptions:

Add SNS Subscriptions
---------------------
BinaryAlert sends YARA match alerts to an `SNS <https://aws.amazon.com/sns/>`_ topic. In order to receive these alerts, you must manually `add a subscription <http://docs.aws.amazon.com/sns/latest/dg/SubscribeTopic.html>`_ to the generated ``NAME_PREFIX_binaryalert_yara_match_alerts`` topic. SNS supports a variety of subscription endpoints, including email, SMS, and other Lambda functions. Email/SMS subscriptions must be confirmed by the destination, which is why this step can't be automated with Terraform.

For example, since `StreamAlert <https://streamalert.io>`_ supports `SNS datasources <https://streamalert.io/datasources.html#aws-sns>`_, you could use StreamAlert to forward the YARA match alert to PagerDuty, Slack, etc.


Terraform State
---------------
By default, Terraform will save the state of the infrastructure locally in ``terraform/terraform.tfstate``. If you are deploying BinaryAlert in an enterprise environment, we recommend configuring `Terraform remote state <https://www.terraform.io/docs/state/remote.html>`_. For example, you can store the Terraform state in a versioned `S3 bucket <https://www.terraform.io/docs/backends/types/s3.html>`_.


Terraform Commands
------------------
We recommend using the ``manage.py`` wrapper script for most BinaryAlert management, but you can also run ``terraform`` commands directly from the ``terraform/`` directory:

.. code-block:: bash

  $ cd terraform/
  $ terraform plan  # Show pending changes
  $ terraform show  # Print the current state of the infrastructure


.. _teardown:

Teardown
--------
To teardown all of the BinaryAlert infrastructure:

.. code-block:: bash

  $ ./manage.py destroy

Terraform will build a destroy plan which you must approve before the delete will proceed.

By default, the BinaryAlert S3 buckets can't be deleted until they are empty. You will be asked
if you want to override this setting and delete all objects as well. If so, the new setting will
be applied before building the destroy plan.

.. note:: You can set ``force_destroy = true`` in the ``terraform/terraform.tfvars`` config file and ``apply`` the change if you want to manually disable S3 delete protections.
