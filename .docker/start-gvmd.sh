#!/bin/sh
# Copyright (C) 2022 Greenbone AG
#
# SPDX-License-Identifier: GPL-3.0-or-later

[ -z "$USER" ] && USER="admin"
[ -z "$PASSWORD" ] && PASSWORD="admin"
[ -z "$GVMD_ARGS" ] && GVMD_ARGS="-f --listen-mode=666"
[ -z "$GVMD_USER" ] && GVMD_USER="gvmd"
[ -z "$PGRES_DATA" ] && PGRES_DATA="/var/lib/postgresql"

if [ -n "$GVM_CERTS" ] && [ "$GVM_CERTS" = true ]; then
    echo "Generating certs"
    gvm-manage-certs -a
fi

# check for psql connection
FILE=$PGRES_DATA/started
until test -f "$FILE"; do
    echo "waiting 1 second for ready postgres container"
    sleep 1
done
until psql -U "$GVMD_USER" -d gvmd -c "SELECT 'connected' as connection"; do
    echo "waiting 1 second to retry psql connection"
    sleep 1
done

# migrate db if necessary
gvmd --migrate || true

gvmd --create-user=$USER --password=$PASSWORD || true

# set the feed import owner
uid=$(gvmd --get-users --verbose | grep "^$USER " | awk '{print $2}')
gvmd --modify-setting 78eceaec-3385-11ea-b237-28d24461215b --value "$uid"
# set the agent owner
gvmd --modify-setting 1ee1f106-8b2e-461c-b426-7f5d76001b29 --value "$uid"

echo "starting gvmd"
gvmd $GVMD_ARGS ||
    (echo "Starting gvmd failed" && exit 1)