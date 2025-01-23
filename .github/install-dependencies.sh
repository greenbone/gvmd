#!/bin/bash
# This script installs the dependencies of gvmd
set -e

BASEDIR=$(dirname "$0")
DEFAULT_DEPENDENCIES_FILE="$BASEDIR/build-dependencies.list"
DEPENDENCIES_FILE=${1:-$DEFAULT_DEPENDENCIES_FILE}

if [[ ! -f "$DEPENDENCIES_FILE" ]]; then
    echo "Dependencies file not found: $DEPENDENCIES_FILE"
    exit 1
fi

apt-get update && \
apt-get install -y --no-install-recommends  --no-install-suggests \
    $(grep -v '#' "$DEPENDENCIES_FILE")
