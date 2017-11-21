CarbonBlack Binary Downloader
=============================
This optional Lambda function copies a binary from CarbonBlack Enterprise Response into the BinaryAlert S3 bucket for analysis.
It can invoked every time CarbonBlack logs a ``binarystore.file.added`` event over the server message bus.

For more information, see the `documentation <https://binaryalert.io/uploading-files.html#carbonblack-downloader>`_.

Cbapi Pip Dependency
--------------------
The ``cbapi`` library needs to be pre-built on the AWS Lambda AMI. ``cbapi_1.3.4.zip`` is already
included in the repo for you, but if you need to upgrade it or rebuild it, SSH to an EC2 instance
running the
`AWS Lambda AMI <http://docs.aws.amazon.com/lambda/latest/dg/current-supported-versions.html>`_
and install ``cbapi`` as follows:

.. code-block:: bash

    # Install requirements
    sudo yum update
    sudo yum install gcc python36

    # Install cbapi and build the zipfile
    pip-3.6 install cbapi -t ~
    rm -r *dist-info *egg-info  # Remove unnecessary package information
    zip -r cbapi.zip *

Then you need only ``scp`` the new zip file to replace ``cbapi_1.3.4.zip``
