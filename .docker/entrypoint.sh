#!/bin/sh
# Copyright (C) 2022 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

. setup-directories
. setup-mta

exec gosu gvmd "$@"
