#!/bin/sh
# Copyright (C) 2026 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

# ensure all required directories exist and have sufficient permissions

mkdir -p /etc/gvmd && \
mkdir -p /run/gvmd && \
mkdir -p /var/lib/gvm && \
mkdir -p /var/log/gvm && \
chown -R gvmd:gvmd /etc/gvm && \
chown -R gvmd:gvmd /run/gvmd && \
chown -R gvmd:gvmd /var/lib/gvm && \
chown -R gvmd:gvmd /var/log/gvm
