# CarbonBlack Binary Downloader
This optional Lambda function copies a binary from CarbonBlack Enterprise Response into the BinaryAlert S3 bucket for analysis.
It can invoked every time CarbonBlack logs a `binary.added` event.


## One-Time Copy All CarbonBlack Binaries
`python3 copy_all.py` will enumerate all CarbonBlack binaries and copy each one into S3 (keyed by a
random UUID). It uses multiple processes, but can still take several hours.

Note that CarbonBlack only stores the first 25MB of binary data. The CarbonBlack MD5 will cover the entire
original file, but only the first 25MB of data will be copied to S3.

## Cbapi Pip Dependency
The `cbapi` library works best when pre-built on the Lambda AMI. Follow the same instructions given
in the [analyzer README](../analyzer/README.md) to upgrade `cbapi_1.3.2.zip` when needed.
