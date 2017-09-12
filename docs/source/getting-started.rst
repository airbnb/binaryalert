Getting Started
===============

All you need is a computer and an AWS account to get BinaryAlert up and running in just a few minutes!


Install Dependencies
--------------------
BinaryAlert can be deployed from any MacOS/Linux environment (and likely Windows as well).

1. Install `Python 3.6 <https://www.python.org/downloads/release/python-362>`_:

.. code-block:: bash

  $ brew install python3  # MacOS Homebrew
  $ sudo apt-get install python3.6  # Ubuntu 16+
  $ python3 --version  # Should show 3.6.x

2. Install the latest version of `Terraform <https://www.terraform.io/downloads.html>`_:

.. code-block:: bash

  $ brew install terraform  # MacOS Homebrew
  $ terraform --version  # Must be v0.10.4+

3. Install `virtualenv <https://virtualenv.pypa.io/en/stable/installation>`_:

.. code-block:: bash

  $ pip3 install virtualenv
  $ virtualenv --version


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

2. Set your AWS credentials using `any method supported by Terraform <https://www.terraform.io/docs/providers/aws/#authentication>`_.
For example, using the AWS CLI:

.. code-block:: bash

  $ pip3 install awscli
  $ aws configure


Download BinaryAlert
--------------------
1. Clone the latest official release of BinaryAlert:

.. code-block:: bash

  $ git clone --branch 0.10 --depth 1 https://github.com/airbnb/binaryalert

2. Create and activate a virtual environment:

.. code-block:: bash

  $ cd binaryalert
  $ virtualenv -p python3 venv
  $ source venv/bin/activate

3. Install the BinaryAlert requirements:

.. code-block:: bash

  $ pip3 install -r requirements.txt

.. note:: If there is an error finding ``openssl.h``, try ``export CFLAGS='-I/usr/local/opt/openssl/include'`` before the install.

4. Run unit tests to make sure everything is installed correctly:

.. code-block:: bash

  $ python3 manage.py unit_test


Deploy!
-------
1. Configure BinaryAlert settings:

.. code-block:: bash

  $ python3 manage.py configure
  AWS Region (us-east-1): us-east-1
  Unique name prefix, e.g. "company_team": your_unique_prefix
  Enable the CarbonBlack downloader [yes/no]? (no): no

2. Deploy!

.. code-block:: bash

  $ python3 manage.py deploy
  # Terraform will generate a plan and request approval

3. BinaryAlert is live! Test it by uploading a harmless `EICAR test string <http://www.eicar.org/86-0-Intended-use.html>`_:

.. code-block:: bash

  $ python3 manage.py live_test
