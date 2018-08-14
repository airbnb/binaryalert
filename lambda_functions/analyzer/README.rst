YARA Analyzer
=============
This Lambda function is the core of BinaryAlert. Each invocation downloads one or more binaries from
S3, scans them against all available YARA rules, and forwards any matches to Dynamo and SNS.


Updating YARA Binaries
----------------------
Many libraries used by BinaryAlert are natively compiled, and must therefore be pre-built on an
Amazon Linux AMI in order to run in Lambda. This has already been done for you:
``dependencies.zip`` contains the following pre-built libraries:

- `cryptography <https://cryptography.io>`_ (v2.3)
- `UPX <https://github.com/upx/upx>`_ (v3.94)
- `yara-python <https://github.com/VirusTotal/yara-python>`_ (v3.8.0)
    - `yara <https://github.com/VirusTotal/yara>`_ (v3.8.0)
- `yextend <https://github.com/BayshoreNetworks/yextend>`_ (v1.6)
    - `pdftotext <https://poppler.freedesktop.org/>`_ (v0.26.5)

If, however, you need to update or re-create the zipfile, SSH to an EC2 instance running the
`AWS Lambda AMI <http://docs.aws.amazon.com/lambda/latest/dg/current-supported-versions.html>`_
and install the dependencies as follows:

.. code-block:: bash

    # Install requirements
    sudo yum update
    sudo yum install autoconf automake bzip2-devel gcc64 gcc64-c++ libarchive-devel libffi-devel \
        libtool libuuid-devel openssl-devel pcre-devel poppler-utils python36 python36-devel zlib-devel
    sudo pip install nose

    # Compile YARA
    wget https://github.com/VirusTotal/yara/archive/v3.8.0.tar.gz
    tar -xzf v3.8.0.tar.gz
    cd yara-3.8.0
    ./bootstrap.sh
    ./configure
    make
    make check  # Run unit tests
    sudo make install

    # Install cryptography and yara-python
    cd ~
    mkdir pip
    pip-3.6 install cryptography yara-python -t pip

    # Compile yextend
    wget https://github.com/BayshoreNetworks/yextend/archive/1.6.tar.gz
    tar -xvzf 1.6.tar.gz
    cd yextend-1.6
    # Manually: modify main.cpp, line 473 to hardcode the yara version to 3.8
    ./build.sh
    make unittests  # Run unit tests

    # Clean cryptography files
    cd ~/pip
    rm -r *.dist-info *.egg-info
    find . -name __pycache__ | xargs rm -r
    mv _cffi_backend.cpython-36m-x86_64-linux-gnu.so _cffi_backend.so
    cd cryptography/hazmat/bindings
    mv _constant_time.abi3.so _constant_time.so
    mv _openssl.abi3.so _openssl.so
    mv _padding.abi3.so _padding.so

    # Gather pip files
    cd ~
    mkdir lambda
    cp pip/.libs_cffi_backend/* lambda
    cp -r pip/* lambda
    mv lambda/yara.cpython-36m-x86_64-linux-gnu.so lambda/yara.so
    wget https://raw.githubusercontent.com/VirusTotal/yara/master/COPYING -O lambda/YARA_LICENSE
    wget https://raw.githubusercontent.com/VirusTotal/yara-python/master/LICENSE -O lambda/YARA_PYTHON_LICENSE

    # Gather Yextend files
    cp yextend-1.6/yextend lambda
    cp yextend-1.6/LICENSE lambda/YEXTEND_LICENSE
    mkdir lambda/libs
    cp yextend-1.6/libs/*.o lambda/libs
    cp yextend-1.6/libs/*.yara lambda/libs

    # Download UPX
    wget https://github.com/upx/upx/releases/download/v3.94/upx-3.94-amd64_linux.tar.xz
    tar -xf upx-3.94-amd64_linux.tar.xz
    cp upx-3.94-amd64_linux/upx lambda
    cp upx-3.94-amd64_linux/COPYING lambda/UPX_LICENSE

    # Gather compiled libraries
    cp /usr/bin/pdftotext lambda
    cp /usr/lib64/libarchive.so.13 lambda
    cp /usr/lib64/libfontconfig.so.1 lambda
    cp /usr/lib64/libfreetype.so.6 lambda
    cp /usr/lib64/libjbig.so.2.0 lambda
    cp /usr/lib64/libjpeg.so.62 lambda
    cp /usr/lib64/liblcms2.so.2 lambda
    cp /usr/lib64/liblzma.so.5 lambda
    cp /usr/lib64/liblzo2.so.2 lambda
    cp /usr/lib64/libopenjpeg.so.2 lambda
    cp /usr/lib64/libpcrecpp.so.0 lambda
    cp /usr/lib64/libpng12.so.0 lambda
    cp /usr/lib64/libpoppler.so.46 lambda
    cp /usr/lib64/libstdc++.so.6 lambda
    cp /usr/lib64/libtiff.so.5 lambda
    cp /usr/lib64/libxml2.so.2 lambda
    cp /usr/local/lib/libyara.so.3 lambda

    # Build Zipfile
    cd lambda
    zip -r dependencies.zip *


Then ``scp`` the ``dependencies.zip`` package to replace the one in the repo.