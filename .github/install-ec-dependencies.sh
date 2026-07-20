#!/bin/sh
set -e

# GSR/GXR PDF
# pycha

apt-get update && \
apt-get install -y --no-install-recommends python3-pip && \
pip install --no-cache-dir --break-system-packages pycha && \
apt-get purge -y python3-pip && \
apt-get autoremove -y --purge
