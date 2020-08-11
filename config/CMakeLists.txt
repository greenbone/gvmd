# Copyright (C) 2020 Greenbone Networks GmbH
#
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.


if (NOT SYSTEMD_SERVICE_DIR)
  set (SYSTEMD_SERVICE_DIR "${CMAKE_INSTALL_PREFIX}/lib/systemd/system")
endif (NOT SYSTEMD_SERVICE_DIR)

if (NOT DEFAULT_CONFIG_DIR)
  set (DEFAULT_CONFIG_DIR "${CMAKE_INSTALL_PREFIX}/etc/default")
endif (NOT DEFAULT_CONFIG_DIR)

if (NOT LOGROTATE_DIR)
  set (LOGROTATE_DIR "${CMAKE_INSTALL_PREFIX}/etc/logrotate.d")
endif (NOT LOGROTATE_DIR)

configure_file (gvmd.service.in gvmd.service)
configure_file (gvmd.logrotate.in gvmd.logrotate)
configure_file (gvmd.default.in gvmd.default)

install (FILES ${CMAKE_CURRENT_BINARY_DIR}/gvmd.service
         DESTINATION ${SYSTEMD_SERVICE_DIR}/)

install (FILES ${CMAKE_CURRENT_BINARY_DIR}/gvmd.default
         DESTINATION ${DEFAULT_CONFIG_DIR}/ RENAME gvmd)

install (FILES ${CMAKE_CURRENT_BINARY_DIR}/gvmd.logrotate
         DESTINATION ${LOGROTATE_DIR}/ RENAME gvmd)
