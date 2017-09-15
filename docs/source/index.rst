BinaryAlert
===========

.. image:: ../images/logo.png
  :align: center
  :scale: 75%
  :alt: BinaryAlert Logo


BinaryAlert is a serverless, real-time framework for detecting malicious files. BinaryAlert can efficiently analyze millions of files a day with a configurable set of `YARA <http://virustotal.github.io/yara/>`_ rules and will trigger an alert as soon as anything malicious is discovered! Organizations can deploy BinaryAlert to their private AWS account in a matter of minutes, allowing them to analyze internal files and documents within the confines of their own environment.


Features
--------

* **Built with Amazon Web Services (AWS):** An AWS account is all you need to deploy BinaryAlert.
* **Broad YARA support:** BinaryAlert includes dozens of YARA rules out-of-the-box and makes it easy to add your own rules or clone them from other open-source repositories.
* **Real-Time:** Files uploaded to BinaryAlert (S3 bucket) are immediately queued for analysis.
* **Serverless:** All computation is handled by `Lambda <https://aws.amazon.com/lambda/>`_ functions. No servers to manage means stronger security and automatic scaling!
* **Infrastructure-As-Code:** The entire infrastructure is described with `Terraform <https://www.terraform.io/>`_ configuration files, enabling anyone to deploy BinaryAlert in a matter of minutes with a single command.
* **Retroactive Analysis:** After updating the YARA ruleset, BinaryAlert will retroactively scan the entire file corpus to find any new matches.
* **Production-Ready:** BinaryAlert ships with a custom metric dashboard and alarms which automatically trigger if BinaryAlert is not operating as expected.
* **Low Cost:** The AWS bill is based only on how many files you upload and how often they are re-analyzed. BinaryAlert can analyze 1 TB for around `$60/month <https://medium.com/@austinbyers/good-question-693200ef5830>`_.


Resources
---------

* `GitHub Repo <https://github.com/airbnb/binaryalert>`_
* `Blog Post <https://medium.com/airbnb-engineering/binaryalert-real-time-serverless-malware-detection-ca44370c1b90>`_
* `Slack <https://binaryalert.herokuapp.com/>`_
* `Twitter <https://twitter.com/binaryalert_io>`_


Table of Contents
=================
.. toctree::
   :maxdepth: 3

   getting-started
   architecture
   adding-yara-rules
   deploying
   uploading-files
