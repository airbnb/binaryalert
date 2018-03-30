BinaryAlert: Serverless, Real-Time & Retroactive Malware Detection
==================================================================
.. image:: https://travis-ci.org/airbnb/binaryalert.svg?branch=master
  :target: https://travis-ci.org/airbnb/binaryalert
  :alt: Build Status

.. image:: https://coveralls.io/repos/github/airbnb/binaryalert/badge.svg?branch=master
  :target: https://coveralls.io/github/airbnb/binaryalert?branch=master
  :alt: Coverage Status

.. image:: https://readthedocs.org/projects/binaryalert/badge/?version=latest
  :target: http://www.binaryalert.io/?badge=latest
  :alt: Documentation Status

.. image:: https://binaryalert.herokuapp.com/badge.svg
  :target: http://binaryalert.herokuapp.com
  :alt: Slack Channel

|

.. image:: docs/images/logo.png
  :align: center
  :scale: 75%
  :alt: BinaryAlert Logo

BinaryAlert is an open-source serverless AWS pipeline where any file uploaded to an S3 bucket is
immediately scanned with a configurable set of `YARA <https://virustotal.github.io/yara/>`_ rules.
An alert will fire as soon as any match is found, giving an incident response team the ability to
quickly contain the threat before it spreads.

Read the documentation at `binaryalert.io <https://binaryalert.io>`_!


Links
-----

- `Announcement Post <https://medium.com/airbnb-engineering/binaryalert-real-time-serverless-malware-detection-ca44370c1b90>`_
- `Documentation <https://binaryalert.io>`_
- `Slack <https://binaryalert.herokuapp.com>`_ (unofficial)
