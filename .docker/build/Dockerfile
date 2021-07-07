# Dockerfile for gvmd-$VERSION-$COMPILER-build

# Define ARG we use through the build
ARG VERSION=master
ARG BUILD_TYPE=Debug
ARG COMPILER=gcc

FROM greenbone/gvmd-$VERSION-$COMPILER-testing

# This will make apt-get install without question
ARG DEBIAN_FRONTEND=noninteractive

COPY . /usr/local/src/gvmd
WORKDIR /usr/local/src

# clone and install gvmd
 RUN cd gvmd && \
    mkdir build && \
    cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make install