# gvmd-master-debian-buster-gcc-deploy

# Base on gvm-libs image as long as we need gvm-libs as well
FROM greenbone/gvm-libs-master-debian-buster-gcc-deploy

# Provides a Debian buster image with the core build dependencies for gvm with
# Postgres support
LABEL module="gvmd"
LABEL branch="master"
LABEL platform="debian-buster"
LABEL compiler="gcc"
LABEL configuration="deploy"

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

# clone and install gvmd
 RUN git clone --depth 1 \
     https://github.com/greenbone/gvmd.git \
     -b master && \
     cd gvmd && \
     mkdir build && \
     cd build && \
     cmake -DCMAKE_BUILD_TYPE=Release .. && \
     make install