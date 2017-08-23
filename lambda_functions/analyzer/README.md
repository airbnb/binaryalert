# YARA Analyzer
This Lambda function is the core of BinaryAlert. Each invocation downloads one or more binaries from
S3, scans them against all available YARA rules, and forwards any matches to Dynamo and SNS.


## Updating YARA-Python
The [`yara-python`](https://github.com/VirusTotal/yara-python) library is natively compiled.
It must therefore be pre-built on an Amazon Linux AMI in order to run in Lambda.
This has already been done for you: [`yara_python_3.6.3.zip`](yara_python_3.6.3.zip) contains the
pre-built `yara_python` library (v3.6.3) for the Lambda environment and is automatically bundled
on every deploy.

If, however, you need to update or re-create the zipfile, SSH to an EC2 instance running the
[AWS Lambda AMI](http://docs.aws.amazon.com/lambda/latest/dg/current-supported-versions.html)
and install `yara-python`:

```
$ sudo su
# yum update
# yum install gcc openssl-devel.x86_64 python35-devel.x86_64 python35-pip.noarch
# python3
    >>> import pip
    >>> pip.main(['install', '--upgrade', 'pip'])
    >>> exit()
# python3
    >>> import pip
    >>> pip.main(['install', 'yara-python', '--target', '.'])
    >>> exit()
# mv yara.cpython-35m-x86_64-linux-gnu.so yara.so
# cp /usr/lib64/libpython3.5m.so.1.0 .
# zip -r yara_python_VERSION.zip *
```

Some notes:
* Python3.6 is not currently available in the public Lambda AMI. You can either manually install
Python3.6 from source or (what's done here) include the required Python3.5 bytecode in the zipfile.
* The openssl development libraries are required to support the "hash" module.

Then replace [`yara_python_3.6.3.zip`](yara_python_3.6.3.zip) in the repo with the newly generated
package from the EC2 instance and update the filename in [`manage.py`](../../manage.py).
