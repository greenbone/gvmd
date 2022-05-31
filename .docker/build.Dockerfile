# Define ARG we use through the build
ARG VERSION=unstable

# We want gvm-libs to be ready so we use the build docker image of gvm-libs
FROM greenbone/gvm-libs:$VERSION

# This will make apt-get install without question
ARG DEBIAN_FRONTEND=noninteractive

# Redefine ARG we use through the build
ARG VERSION

WORKDIR /usr/local/src

# Install Debian core dependencies required for building gvm with PostgreSQL
# support and not yet installed as dependencies of gvm-libs-core
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    gcc \
    libglib2.0-dev \
    libgnutls28-dev \
    libpq-dev \
    postgresql-server-dev-13 \
    pkg-config \
    libical-dev \
    xsltproc \
    libcgreen1-dev \
    lcov \
    libbsd-dev \
    libgpgme-dev && \
    rm -rf /var/lib/apt/lists/*

RUN ldconfig
