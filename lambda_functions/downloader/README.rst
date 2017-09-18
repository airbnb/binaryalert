CarbonBlack Binary Downloader
=============================
This optional Lambda function copies a binary from CarbonBlack Enterprise Response into the BinaryAlert S3 bucket for analysis.
It can invoked every time CarbonBlack logs a ``binarystore.file.added`` event over the server message bus.

For more information, see the `documentation <https://binaryalert.io/uploading-files.html#carbonblack-downloader>`_.

Cbapi Pip Dependency
--------------------
The ``cbapi`` library works best when pre-built on the Lambda AMI. Follow the same instructions given
in the `analyzer README <../analyzer/README.rst>`_ to upgrade ``cbapi_1.3.2.zip`` when needed.
