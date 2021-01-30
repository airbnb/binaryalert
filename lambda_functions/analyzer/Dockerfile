FROM amazonlinux:latest

ENV APP_DIR /var/task
ENV LAMBDA_DIR ${APP_DIR}/lambda
ENV PIP_DIR $APP_DIR/pip

ENV CRYPTO_VER 3.3.1
ENV ASN1CRYPTO_VER 1.4.0
ENV YARA_VER 4.0.0
ENV UPX_VER 3.94
ENV YEXTEND_VER 1.6
ENV ARCH amd64

VOLUME /var/out
WORKDIR $APP_DIR

RUN yum -y update \
    && yum -y install \
        git \
        zip \
        xz \
        wget \
        tar \
        install \
        autoconf \
        automake \
        pkgconfig \
        bzip2-devel \
        gcc \
        gcc-c++ \
        libarchive-devel \
        libffi-devel \
        libtool \
        libuuid-devel \
        make \
        openssl-devel \
        pcre-devel \
        poppler-utils \
        poppler-cpp-devel \
        zlib-devel \
        python3 \
        python3-pip \
        python3-devel \
    && yum clean all \
    && pip3 install nose

# install Yara
RUN wget -O yara.tar.gz https://github.com/VirusTotal/yara/archive/v${YARA_VER}.tar.gz \
  && tar -xzf yara.tar.gz \
  && cd yara-${YARA_VER} \
  && ./bootstrap.sh \
  && ./configure \
  && make \
  && make check \
  && make install \
  && echo "/usr/local/lib" > /etc/ld.so.conf.d/yara.conf \
  && ldconfig \
  && yara -v

# Install Python pacakges
RUN pip3 install \
    "cryptography==${CRYPTO_VER}" \
    "yara-python==${YARA_VER}" \
    "asn1crypto==${ASN1CRYPTO_VER}" \
    -t $PIP_DIR

# Copy crypto libs
RUN cd $PIP_DIR \
    && rm -r *.dist-info *.egg-info \
    && find . -name __pycache__ | xargs rm -rf \
    && mv _cffi_backend.cpython-*m-x86_64-linux-gnu.so _cffi_backend.so \
    && cd cryptography/hazmat/bindings \
    && mv _openssl.abi3.so _openssl.so \
    && mv _padding.abi3.so _padding.so

# Gather pip files
RUN mkdir ${LAMBDA_DIR} \
    && cp -r ${PIP_DIR}/* ${LAMBDA_DIR}

# Compile yextend
RUN mkdir ${LAMBDA_DIR}/libs \
    && git clone https://github.com/BayshoreNetworks/yextend.git \
    && cd yextend \
    && git checkout yara-${YARA_VER} \
    && mv configure.ac configure.ac.orig \
    && sed 's/python \-c/python3 -c/g' configure.ac.orig > configure.ac \
    && ./build.sh \
    && make unittests \
    && cp yextend ${LAMBDA_DIR} \
    && cp libs/*.o ${LAMBDA_DIR}/libs \
    && cp libs/*.yara ${LAMBDA_DIR}/libs

# UPX
RUN wget https://github.com/upx/upx/releases/download/v${UPX_VER}/upx-${UPX_VER}-${ARCH}_linux.tar.xz \
    && tar -xf upx-${UPX_VER}-${ARCH}_linux.tar.xz \
    && cp upx-${UPX_VER}-${ARCH}_linux/upx ${LAMBDA_DIR}

## Gather compiled libraries
RUN cp /usr/bin/pdftotext ${LAMBDA_DIR} \
    && mkdir tmplib \
    && find \
        /usr/lib64/lib* \
        -depth \
        -type f \
        -o \
        -type d \
        -name 'lib*.so.*' | \
        grep -E 'lib(archive|fontconfig|jbig|jpeg|lcms|lzma|lzo2|openjpeg|pcrecpp|png|poppler|stdc|tiff|xml)' | \
        cpio -pamVd tmplib \
    && mv tmplib/usr/lib64/* ${LAMBDA_DIR} \
    && cp /usr/local/lib/libyara.so.* ${LAMBDA_DIR}

RUN cd ${LAMBDA_DIR} \
    && zip -r dependencies.zip * \
    && mv ${LAMBDA_DIR}/dependencies.zip ${APP_DIR}/dependencies.zip

CMD cp ${APP_DIR}/dependencies.zip /var/out/
