# Define ARG we use through the build
ARG VERSION=main
ARG COMPILER=gcc

# We want gvm-libs to be ready so we use the build docker image of gvm-libs
FROM greenbone/gvm-libs:$VERSION

# This will make apt-get install without question
ARG DEBIAN_FRONTEND=noninteractive

# Redefine ARG we use through the build
ARG VERSION
ARG COMPILER

WORKDIR /usr/local/src

# Install Debian core dependencies required for building gvm with PostgreSQL
# support and not yet installed as dependencies of gvm-libs-core
RUN apt-get update && \
    apt-get install -y --no-install-recommends \ 
    cmake \
    libglib2.0-dev \
    libgnutls30-dev \
    libpq-dev \
    postgresql-server-dev-11 \
    pkg-config \
    libical-dev \
    xsltproc \
    libcgreen1-dev \
    lcov \
    libgpgme-dev && \
    rm -rf /var/lib/apt/lists/*


# Install gcc/g++ compiler
RUN if ( test "$COMPILER" = "gcc"); then \
    echo "Compiler is $COMPILER" && \
    apt-get update && \
    apt-get install --no-install-recommends --assume-yes gcc g++; \
    fi

# Install clang compiler
RUN if ( test "$COMPILER" = "clang"); then \
    echo "Compiler is $COMPILER" && \
    apt-get update && \
    apt-get install --no-install-recommends --assume-yes \
    clang \
    clang-format \
    clang-tools; \
    fi

RUN ldconfig