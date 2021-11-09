FROM greenbone/gvm-libs:main as builder

ARG DEBIAN_FRONTEND=noninteractive

# Install Debian core dependencies required for building gvm with PostgreSQL
# support and not yet installed as dependencies of gvm-libs-core
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    pkg-config \
    libglib2.0-dev \
    libgnutls28-dev \
    libgpgme-dev \
    libpq-dev \
    libical-dev \
    postgresql-server-dev-13 \
    xml-twig-tools \
    xsltproc && \
    rm -rf /var/lib/apt/lists/*

COPY . /source
WORKDIR /source

RUN mkdir /build && \
    mkdir /install && \
    cd /build && \
    cmake -DCMAKE_BUILD_TYPE=Release /source && \
    make DESTDIR=/install install

FROM greenbone/gvm-libs:main

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libpq5 \
    libgpgme11 \
    libical3 \
    xml-twig-tools && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /install/ /
