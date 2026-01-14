#!/bin/sh
# Copyright (C) 2022 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

#!/bin/bash

. setup-mta
exec gosu gvmd "$@"
