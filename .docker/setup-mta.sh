#!/bin/bash

# Make any changes only when MTA_HOST has been set
if [ -n "$MTA_HOST" ]; then
    echo "setting up configuration file for mail agent"
    CONFIG="/etc/msmtprc"
    echo "host $MTA_HOST" > $CONFIG
    [ -n "$MTA_PORT" ] && echo "port $MTA_PORT" >> $CONFIG
    [ -n "$MTA_TLS" ] && echo "tls $MTA_TLS" >> $CONFIG
    [ -n "$MTA_STARTTLS" ] && echo "tls_starttls $MTA_STARTTLS" >> $CONFIG
    [ -n "$MTA_TLS_CERTCHECK" ] && echo "tls_certcheck $MTA_TLS_CERTCHECK" >> $CONFIG
    [ -n "$MTA_AUTH" ] && echo "auth $MTA_AUTH" >> $CONFIG
    [ -n "$MTA_USER" ] && echo "user $MTA_USER" >> $CONFIG
    [ -n "$MTA_FROM" ] && echo "from $MTA_FROM" >> $CONFIG
    [ -n "$MTA_PASSWORD" ] && echo "password $MTA_PASSWORD" >> $CONFIG
    [ -n "$MTA_LOGFILE" ] && echo "logfile $MTA_LOGFILE" >> $CONFIG
    chown gvmd:mail $CONFIG
    chmod 750 $CONFIG
fi
