[libopenvas]
prepend="%p"
file=${OPENVAS_LOG_DIR}/libopenvas.log
level=128

[libnasl]
prepend="%p"
file=${OPENVAS_LOG_DIR}/libnasl.log
level=128

[openvasd]
prepend="%p"
file=${OPENVAS_LOG_DIR}/openvasd.log
level=128

[openvasmd]
prepend="%p"
file=${OPENVAS_LOG_DIR}/openvasmd.log
level=128

[*]
prepend="%p"
file=${OPENVAS_LOG_DIR}/openvas.log
