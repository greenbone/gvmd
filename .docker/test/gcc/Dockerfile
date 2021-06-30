# gvmd-master-debian-buster-gcc-test

# Base on gvm-libs image as long as we need gvm-libs as well
FROM greenbone/gvm-libs-master-debian-buster-gcc-deploy

# Provides a Debian buster image with the core build dependencies for gvm with
# Postgres support
LABEL module="gvmd"
LABEL branch="master"
LABEL platform="debian-buster"
LABEL compiler="gcc"
LABEL configuration="test"

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

# Install Debian core dependencies required for testing gvm-libs
# support and not yet installed as dependencies of gvm-libs-core
RUN apt-get update && apt-get install --assume-yes \
    g++ \
    lcov \
    libical-dev \
    libpq-dev \
    libnet1-dev \
    postgresql-server-dev-all \
    xsltproc \
 && rm -rf /var/lib/apt/lists/*

# install cgreen for unit tests
RUN git clone --depth 1 https://github.com/cgreen-devs/cgreen.git \
 && cd cgreen \
 && make \
 && make test \
 && make install \
 && cd .. \
 && rm -rf cgreen
