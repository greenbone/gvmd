[libopenvas]
prepend="%t %p"
prepend_time_format=%Y%m%d%H%M%S
file=${OPENVAS_LOG_DIR}/libopenvas.log

[libnasl]
prepend="%t %p"
prepend_time_format=%Y%m%d%H%M%S
file=${OPENVAS_LOG_DIR}/libnasl.log

[openvasd]
prepend="%t %p"
prepend_time_format=%Y%m%d%H%M%S
file=${OPENVAS_LOG_DIR}/openvasd.log

[md   main]
prepend="%t %p"
prepend_time_format=%Y%m%d%H%M%S
file=${OPENVAS_LOG_DIR}/openvasmd.log
level=128

[md   file]
prepend="%t %p"
prepend_time_format=%Y%m%d%H%M%S
file=${OPENVAS_LOG_DIR}/openvasmd.log
level=128

[md string]
prepend="%t %p"
prepend_time_format=%Y%m%d%H%M%S
file=${OPENVAS_LOG_DIR}/openvasmd.log
level=128

[md manage]
prepend="%t %p"
prepend_time_format=%Y%m%d%H%M%S
file=${OPENVAS_LOG_DIR}/openvasmd.log
level=128

[md    omp]
prepend="%t %p"
prepend_time_format=%Y%m%d%H%M%S
file=${OPENVAS_LOG_DIR}/openvasmd.log
level=128

[md    otp]
prepend="%t %p"
prepend_time_format=%Y%m%d%H%M%S
file=${OPENVAS_LOG_DIR}/openvasmd.log
level=128

[*]
prepend="%p"
file=${OPENVAS_LOG_DIR}/openvas.log
