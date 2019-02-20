Getting Started
===============
All you need is an AWS account to get BinaryAlert up and running in just a few minutes!


.. _dependencies:

Install Dependencies
--------------------
BinaryAlert can be deployed from any MacOS/Linux environment (and likely Windows as well, though we haven't tried).

1. Install `Python 3.6 <https://www.python.org/downloads/release/python-364/>`_:

.. code-block:: bash

  # MacOS Homebrew
  brew install python3
  python3 --version

  # Ubuntu16 - Python 3.6 is only available in third-party repositories
  sudo add-apt-repository ppa:deadsnakes/ppa
  sudo apt-get update
  sudo apt-get install python3.6 python3.6-dev python3-pip
  sudo -H pip3 install --upgrade pip
  python3.6 --version

.. warning:: Python 3.5 is installed by default on some systems, but AWS Lambda requires Python 3.6 or 3.7.

2. Install `Terraform <https://www.terraform.io/downloads.html>`_ v0.11.X:

.. code-block:: bash

  $ brew install terraform  # MacOS Homebrew
  $ terraform --version  # Must be v0.11.X

3. Install the OpenSSL development library if it isn't already (OS X should have it).
This is required for YARA's `hash module <http://yara.readthedocs.io/en/stable/modules/hash.html>`_
and must be installed *before* installing the BinaryAlert requirements.

.. code-block:: bash

  $ sudo apt-get install libssl-dev  # Ubuntu
  $ sudo yum install openssl-devel   # Amazon Linux


Download BinaryAlert
--------------------
1. Clone the latest official release of BinaryAlert:

.. code-block:: bash

  $ git clone --branch v1.2.0 https://github.com/airbnb/binaryalert

2. Create and activate a virtual environment:

.. code-block:: bash

  $ cd binaryalert
  $ python3.6 -m venv venv
  $ source venv/bin/activate

3. Install the BinaryAlert requirements:

.. code-block:: bash

  $ pip3 install -r requirements.txt

.. note:: If there is an error finding ``openssl.h``, try ``export CFLAGS='-I/usr/local/opt/openssl/include'`` before the install.

4. Run unit tests to make sure everything is installed correctly:

.. code-block:: bash

  $ ./manage.py unit_test

Set AWS Credentials
-------------------
1. Create an AWS account and an IAM user with permissions for at least the following services:

  * CloudWatch
  * DynamoDB
  * IAM
  * KMS
  * Lambda
  * S3
  * SNS
  * SQS

.. note:: See `Creating an IAM group <iam-group.html>`_ for a least-privilege policy that allows users to deploy BinaryAlert.

2. Set your AWS credentials using `any method supported by Terraform <https://www.terraform.io/docs/providers/aws/#authentication>`_.
For example, using the AWS CLI:

.. code-block:: bash

  $ pip3 install awscli
  $ aws configure

Deploy!
-------
1. Configure BinaryAlert settings:

.. code-block:: bash

  $ ./manage.py configure
  AWS Region (us-east-1):
  Unique name prefix, e.g. "company_team": your_unique_prefix
  Enable the CarbonBlack downloader? (no):

2. Deploy!

.. code-block:: bash

  $ ./manage.py deploy
  # Terraform will generate a plan and request approval before applying

3. BinaryAlert is live! Test it by uploading a harmless `EICAR test string <http://www.eicar.org/86-0-Intended-use.html>`_:

.. code-block:: bash

  $ ./manage.py live_test

.. note:: You must :ref:`add an SNS subscription <add_sns_subscriptions>` in order to receive YARA match alerts.
