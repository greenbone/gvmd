FROM greenbone/gvm-libs:main as builder

# This will make apt-get install without question
ARG DEBIAN_FRONTEND=noninteractive

# Install Debian core dependencies required for building gvm with PostgreSQL
# support and not yet installed as dependencies of gvm-libs-core
RUN apt-get update && \
    apt-get install -y --no-install-recommends \ 
    gcc \
    cmake \
    libglib2.0-dev \
    libgnutls30-dev \
    libpq-dev \
    postgresql-server-dev-11 \
    pkg-config \
    libical-dev \
    xsltproc \
    libgpgme-dev && \
    rm -rf /var/lib/apt/lists/*

COPY . /usr/local/src/gvmd
WORKDIR /usr/local/src

RUN cmake --version && \ 
    mkdir /build && \
    mkdir /install && \
    cd /build && \
    cmake -DCMAKE_BUILD_TYPE=Release /source && \
    make DESTDIR=/install install

FROM debian:stable-slim

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \ 
    libglib2.0-0 \
    libgnutls30 \
    libpq5 \
    libgpgme11 \
    postgresql-13 \
    libical3 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /install/ /

RUN ldconfig
