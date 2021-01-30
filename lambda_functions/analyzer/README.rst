YARA Analyzer
=============
This Lambda function is the core of BinaryAlert. Each invocation downloads one
or more binaries from S3, scans them against all available YARA rules, and
forwards any matches to Dynamo and SNS.


Updating YARA Binaries
----------------------
Many libraries used by BinaryAlert are natively compiled, and must therefore be
pre-built on an Amazon Linux AMI in order to run in Lambda. This has already
been done for you in the `dependencies.zip` file that ships with the repo, but you
can rebuild it yourself via Docker.

If you need to update or re-create the ZIP file, do it before deployment.

.. code-block:: bash
    $ make

And you'll find the new `dependencies.zip` file in this folder.
