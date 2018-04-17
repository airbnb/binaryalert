CarbonBlack Binary Downloader
=============================
This optional Lambda function copies a binary from CarbonBlack Enterprise Response into the BinaryAlert S3 bucket for analysis.
It can invoked every time CarbonBlack logs a ``binarystore.file.added`` event over the server message bus.

For more information, see the `documentation <https://binaryalert.io/uploading-files.html#carbonblack-downloader>`_.
