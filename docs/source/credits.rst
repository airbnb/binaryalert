Credits
=======

People
------
BinaryAlert is brought to you by `Airbnb <http://airbnb.io>`_:

- `Austin Byers <https://github.com/austinbyers>`_ (Architect, Primary Engineer)
- `mime-frame <https://github.com/mime-frame>`_ (Concept, Design Review, YARA Rules)
- `Daimon <https://github.com/fusionrace>`_ (YARA Rules)
- And many others in the `full list of contributors <https://github.com/airbnb/binaryalert/graphs/contributors>`_


.. _yara-credits:

YARA Rules
----------
When :ref:`cloning YARA rules from other projects <clone-yara-rules>`, subsets of the following
collections are included by default:

- `Neo23x0/signature-base <https://github.com/Neo23x0/signature-base>`_
- `YARA-Rules/rules <https://github.com/YARA-Rules/rules>`_


Open-Source Tools
-----------------
We are proud to contribute to the open-source community, without which BinaryAlert would not be
possible. BinaryAlert relies on several open-source tools and libraries:

- `backoff <https://github.com/litl/backoff>`_: Function decoration for backoff and retry
- `boto3 <https://boto3.readthedocs.io>`_: AWS SDK for Python
- `cbapi <https://cbapi.readthedocs.io>`_: Carbon Black API for Python
- `pyhcl <https://github.com/virtuald/pyhcl>`_: Python parser for HCL (e.g. Terraform configuration)
- `terraform <https://www.terraform.io/>`_: Infrastructure-as-Code
- `yara <http://virustotal.github.io/yara/>`_: Pattern matching for malware analysis
- `yara-python <https://github.com/VirusTotal/yara-python>`_: The Python interface for YARA
- `yextend <https://github.com/BayshoreNetworks/yextend>`_: YARA analysis of archive data


Bundled Software
................
The following tools are pre-compiled for use in Lambda and included in the BinaryAlert repo:

- `cbapi-python <https://github.com/carbonblack/cbapi-python>`_ | `LICENSE <https://github.com/carbonblack/cbapi-python/blob/master/LICENSE>`__
- `yara-python <https://github.com/VirusTotal/yara-python>`_  | `LICENSE <https://github.com/VirusTotal/yara-python/blob/master/LICENSE>`__
- `yextend <https://github.com/BayshoreNetworks/yextend>`_  | `LICENSE <https://github.com/BayshoreNetworks/yextend/blob/master/LICENSE>`__
