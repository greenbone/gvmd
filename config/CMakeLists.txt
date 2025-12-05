# Copyright (C) 2020-2022 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

if(NOT SYSTEMD_SERVICE_DIR)
  set(SYSTEMD_SERVICE_DIR "${LIBDIR}/systemd/system")
endif(NOT SYSTEMD_SERVICE_DIR)

if(NOT LOGROTATE_DIR)
  set(LOGROTATE_DIR "${SYSCONFDIR}/logrotate.d")
endif(NOT LOGROTATE_DIR)

configure_file(gvmd.service.in gvmd.service)
configure_file(gvmd.logrotate.in gvmd.logrotate)

install(
  FILES ${CMAKE_CURRENT_BINARY_DIR}/gvmd.service
  DESTINATION ${SYSTEMD_SERVICE_DIR}/
)

install(
  FILES ${CMAKE_CURRENT_BINARY_DIR}/gvmd.logrotate
  DESTINATION ${LOGROTATE_DIR}/
  RENAME gvmd
)

# Default gvmd.conf runtime flag configuration
configure_file(gvmd.conf.in gvmd.conf @ONLY)

install(
  FILES ${CMAKE_CURRENT_BINARY_DIR}/gvmd.conf
  DESTINATION ${GVM_SYSCONF_DIR}
  PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ
)
