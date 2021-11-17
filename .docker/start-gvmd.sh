#!/bin/sh

[ -z "$USER" ] && USER="admin"
[ -z "$PASSWORD" ] && PASSWORD="admin"
[ -z "$GVMD_ARGS" ] && GVMD_ARGS="--listen-mode=666"
[ -z "$GVMD_USER" ] && GVMD_USER="gvmd"

# check for psql connection
until psql -U "$GVMD_USER" -d gvmd -c "SELECT 'connected' as connection"; do
	echo "waiting 1 second to retry psql connection"
	sleep 1
done

# migrate db if necessary
gvmd --migrate || true

gvmd --create-user=$USER --password=$PASSWORD || true

# set the feed import owner
uid=$(gvmd --get-users --verbose | grep $USER | awk '{print $2}')
gvmd --modify-setting 78eceaec-3385-11ea-b237-28d24461215b --value "$uid"

echo "starting gvmd"
gvmd "$GVMD_ARGS" ||
	(cat /var/log/gvm/gvmd.log && exit 1)

tail -f /var/log/gvm/gvmd.log
