# Dockerfile for gvmd-$VERSION-$COMPILER-testing

# Define ARG we use through the build
ARG VERSION=master
ARG BUILD_TYPE=Debug
ARG COMPILER=gcc

# We want gvm-libs to be ready so we use the build docker image of gvm-libs
FROM greenbone/gvm-libs-$VERSION-$COMPILER-build

# This will make apt-get install without question
ARG DEBIAN_FRONTEND=noninteractive

# Install Debian core dependencies required for building gvm with PostgreSQL
# support and not yet installed as dependencies of gvm-libs-core
RUN apt-get update && apt-get install --assume-yes \
    libical-dev \
    libpq-dev \
    postgresql-server-dev-all \
    xsltproc \
 && rm -rf /var/lib/apt/lists/*
