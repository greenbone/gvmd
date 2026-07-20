#!/bin/sh
set -e

PKGS="curl graphviz python3-pip"

apt-get update && \
apt-get install -y --no-install-recommends $PKGS && \
pip install --no-cache-dir --break-system-packages pycha && \
apt-get purge -y python3-pip && \
apt-get autoremove -y --purge && \
rm -rf /var/lib/apt/lists/*
