# Define ARG we use through the build
ARG VERSION=stable

# We want gvm-libs to be ready so we use the build docker image of gvm-libs
FROM greenbone/gvm-libs:$VERSION

# This will make apt-get install without question
ARG DEBIAN_FRONTEND=noninteractive

WORKDIR /usr/local/src

# Install Debian core dependencies required for building gvm with PostgreSQL
# support and not yet installed as dependencies of gvm-libs-core
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    libglib2.0-dev \
    libgnutls28-dev \
    libpq-dev \
    libcgreen1-dev \
    libical-dev \
    lcov \
    libgpgme-dev \
    postgresql-server-dev-13 \
    pkg-config \
    xsltproc \
    && rm -rf /var/lib/apt/lists/*

RUN ldconfig
