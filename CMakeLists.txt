# Copyright (C) 2009-2021 Greenbone Networks GmbH
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
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

cmake_minimum_required (VERSION 3.0)

message ("-- Configuring Greenbone Vulnerability Manager...")

project (gvm
         VERSION 21.4.5
         LANGUAGES C)

if (POLICY CMP0005)
  cmake_policy (SET CMP0005 NEW)
endif (POLICY CMP0005)

SET(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

include (FindPkgConfig)

if (NOT CMAKE_BUILD_TYPE)
  set (CMAKE_BUILD_TYPE Debug)
endif (NOT CMAKE_BUILD_TYPE)

OPTION (ENABLE_COVERAGE "Enable support for coverage analysis" OFF)
OPTION (DEBUG_FUNCTION_NAMES "Print function names on entry and exit" OFF)

## Retrieve git revision (at configure time)
include (GetGit)
if (NOT CMAKE_BUILD_TYPE MATCHES "Release")
  if (EXISTS "${CMAKE_SOURCE_DIR}/.git/")
    if (GIT_FOUND)
      Git_GET_REVISION(${CMAKE_SOURCE_DIR} ProjectRevision)
      set (GIT_REVISION "~git-${ProjectRevision}")
    else (GIT_FOUND)
      set (GIT_REVISION "~git")
    endif (GIT_FOUND)
  endif (EXISTS "${CMAKE_SOURCE_DIR}/.git/")
endif (NOT CMAKE_BUILD_TYPE MATCHES "Release")

# Set dev version if this is a development version and not a full release,
# unset (put value 0 or delete line) before a full release and reset after.
set (PROJECT_DEV_VERSION 0)

# If PROJECT_DEV_VERSION is set, the version string will be set to:
#   "major.minor.patch~dev${PROJECT_DEV_VERSION}${GIT_REVISION}"
# If PROJECT_DEV_VERSION is NOT set, the version string will be set to:
#   "major.minor.patch${GIT_REVISION}"
# For CMAKE_BUILD_TYPE "Release" the git revision will be empty.
if (PROJECT_DEV_VERSION)
  set (PROJECT_VERSION_SUFFIX "~dev${PROJECT_DEV_VERSION}")
endif (PROJECT_DEV_VERSION)

set (PROJECT_VERSION_STRING 
"${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}${PROJECT_VERSION_SUFFIX}${GIT_REVISION}")

## CPack configuration

set (CPACK_CMAKE_GENERATOR "Unix Makefiles")
set (CPACK_GENERATOR "TGZ")
set (CPACK_INSTALL_CMAKE_PROJECTS ".;gvm;ALL;/")
set (CPACK_MODULE_PATH "")
set (CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/COPYING")
set (CPACK_RESOURCE_FILE_README "${CMAKE_SOURCE_DIR}/README.md")
set (CPACK_RESOURCE_FILE_WELCOME "${CMAKE_SOURCE_DIR}/README.md")
set (CPACK_SOURCE_GENERATOR "TGZ")
set (CPACK_SOURCE_TOPLEVEL_TAG "")
set (CPACK_SYSTEM_NAME "")
set (CPACK_TOPLEVEL_TAG "")

set (CPACK_PACKAGE_VERSION "${PROJECT_VERSION_STRING}${PROJECT_VERSION_GIT}")

set (CPACK_PACKAGE_FILE_NAME "${PROJECT_NAME}-${CPACK_PACKAGE_VERSION}")
set (CPACK_SOURCE_PACKAGE_FILE_NAME "${PROJECT_NAME}-${CPACK_PACKAGE_VERSION}")
set (CPACK_PACKAGE_VENDOR "Greenbone Networks GmbH")
set (CPACK_SOURCE_IGNORE_FILES
"${CMAKE_BINARY_DIR}"
"/.git/"
"swp$"
)

include (CPack)

## Variables

set (GVMD_DATABASE_VERSION 242)

set (GVMD_SCAP_DATABASE_VERSION 18)

set (GVMD_CERT_DATABASE_VERSION 8)

set (GMP_VERSION "21.4")
set (GMP_VERSION_FEED "21.04")

if (SYSCONF_INSTALL_DIR)
  set (SYSCONFDIR "${SYSCONF_INSTALL_DIR}")
endif (SYSCONF_INSTALL_DIR)

if (NOT SYSCONFDIR)
  set (SYSCONFDIR "/etc")
endif (NOT SYSCONFDIR)

if (NOT EXEC_PREFIX)
  set (EXEC_PREFIX "${CMAKE_INSTALL_PREFIX}")
endif (NOT EXEC_PREFIX)

if (NOT BINDIR)
  set (BINDIR "${EXEC_PREFIX}/bin")
endif (NOT BINDIR)

if (NOT SBINDIR)
  set (SBINDIR "${EXEC_PREFIX}/sbin")
endif (NOT SBINDIR)

if (NOT LIBDIR)
  set (LIBDIR "${EXEC_PREFIX}/lib")
endif (NOT LIBDIR)

if (NOT LOCALSTATEDIR)
  set (LOCALSTATEDIR "/var")
endif (NOT LOCALSTATEDIR)

if (NOT DATADIR)
  set (DATADIR "${CMAKE_INSTALL_PREFIX}/share")
endif (NOT DATADIR)

if (NOT INCLUDEDIR)
  set (INCLUDEDIR "${CMAKE_INSTALL_PREFIX}/include")
endif (NOT INCLUDEDIR)

set (GVM_SYSCONF_DIR  "${SYSCONFDIR}/gvm")

set (GVM_DATA_DIR     "${DATADIR}/gvm")
if (NOT GVMD_DATA_DIR)
  set (GVMD_DATA_DIR  "${GVM_DATA_DIR}/gvmd")
endif (NOT GVMD_DATA_DIR)

if (NOT GVM_STATE_DIR)
  set (GVM_STATE_DIR    "${LOCALSTATEDIR}/lib/gvm")
else (NOT GVM_STATE_DIR)
  set (GVM_STATE_DIR "${GVM_STATE_DIR}")
endif (NOT GVM_STATE_DIR)

if (NOT GVMD_STATE_DIR)
  set (GVMD_STATE_DIR  "${GVM_STATE_DIR}/gvmd")
endif (NOT GVMD_STATE_DIR)

if (NOT GVM_LOG_DIR)
  set (GVM_LOG_DIR    "${LOCALSTATEDIR}/log/gvm")
else (NOT GVM_LOG_DIR)
  set (GVM_LOG_DIR    "${GVM_LOG_DIR}")
endif (NOT GVM_LOG_DIR)

set (GVM_SCAP_RES_DIR "${GVM_DATA_DIR}/scap")
set (GVM_CERT_RES_DIR "${GVM_DATA_DIR}/cert")
set (GVM_CA_DIR       "${GVMD_STATE_DIR}/trusted_certs")

if (NOT GVM_LIB_INSTALL_DIR)
  set (GVM_LIB_INSTALL_DIR     "${LIBDIR}")
else (NOT GVM_LIB_INSTALL_DIR)
  set (GVM_LIB_INSTALL_DIR "${GVM_LIB_INSTALL_DIR}")
endif (NOT GVM_LIB_INSTALL_DIR)

set (GVM_SCANNER_CERTIFICATE "${GVM_STATE_DIR}/CA/servercert.pem")
set (GVM_SCANNER_KEY         "${GVM_STATE_DIR}/private/CA/serverkey.pem")
set (GVM_CLIENT_CERTIFICATE  "${GVM_STATE_DIR}/CA/clientcert.pem")
set (GVM_CLIENT_KEY          "${GVM_STATE_DIR}/private/CA/clientkey.pem")
set (GVM_CA_CERTIFICATE      "${GVM_STATE_DIR}/CA/cacert.pem")

if (NOT GVMD_RUN_DIR)
  set (GVMD_RUN_DIR      "/run/gvmd")
endif (NOT GVMD_RUN_DIR)

if (NOT GVMD_PID_PATH)
  set (GVMD_PID_PATH     "${GVMD_RUN_DIR}/gvmd.pid")
endif (NOT GVMD_PID_PATH)

if (NOT GVM_FEED_LOCK_PATH)
  set (GVM_FEED_LOCK_PATH "${GVM_STATE_DIR}/feed-update.lock")
endif (NOT GVM_FEED_LOCK_PATH)
add_definitions (-DGVM_FEED_LOCK_PATH="${GVM_FEED_LOCK_PATH}")

if (NOT OPENVAS_DEFAULT_SOCKET)
  set (OPENVAS_DEFAULT_SOCKET "/run/ospd/ospd-openvas.sock")
endif (NOT OPENVAS_DEFAULT_SOCKET)
add_definitions (-DOPENVAS_DEFAULT_SOCKET="${OPENVAS_DEFAULT_SOCKET}")

# TODO: Once we separate the RFP signatures out of "plugins" and
# into var/lib/gvm/rfpsigs/ (via a sync script) then we do not need
# to know about the NVT_DIR anymore.
if (NOT GVM_NVT_DIR)
  set (GVM_NVT_DIR "${LOCALSTATEDIR}/lib/openvas/plugins/")
endif (NOT GVM_NVT_DIR)

if (NOT DATA_OBJECTS_FEED_DIR)
  set (DATA_OBJECTS_FEED_DIR "${LOCALSTATEDIR}/lib/gvm/data-objects")
endif (NOT DATA_OBJECTS_FEED_DIR)

if (NOT GVMD_FEED_DIR)
  set (GVMD_FEED_DIR "${DATA_OBJECTS_FEED_DIR}/gvmd")
endif (NOT GVMD_FEED_DIR)

if (NOT GVM_ACCESS_KEY_DIR)
  set (GVM_ACCESS_KEY_DIR "${GVM_SYSCONF_DIR}")
endif (NOT GVM_ACCESS_KEY_DIR)

if (NOT GVM_CERT_DATA_DIR)
  set (GVM_CERT_DATA_DIR "${GVM_STATE_DIR}/cert-data")
endif (NOT GVM_CERT_DATA_DIR)

if (NOT GVM_SCAP_DATA_DIR)
  set (GVM_SCAP_DATA_DIR "${GVM_STATE_DIR}/scap-data")
endif (NOT GVM_SCAP_DATA_DIR)

# System username to use when dropping privileges
if (NOT GVM_DEFAULT_DROP_USER)
  set (GVM_DEFAULT_DROP_USER "")
endif (NOT GVM_DEFAULT_DROP_USER)

message ("-- Install prefix: ${CMAKE_INSTALL_PREFIX}")

## Version

set (GVMD_VERSION "${PROJECT_VERSION_STRING}")

# Configure Doxyfile with version number
configure_file (doc/Doxyfile.in doc/Doxyfile)
configure_file (doc/Doxyfile_full.in doc/Doxyfile_full)
configure_file (doc/Doxyfile_xml.in doc/Doxyfile_xml)
configure_file (doc/example-gvm-manage-certs.conf.in doc/example-gvm-manage-certs.conf @ONLY)
configure_file (VERSION.in VERSION)
configure_file (src/gvmd_log_conf.cmake_in src/gvmd_log.conf)
configure_file (src/schema_formats/XML/GMP.xml.in src/schema_formats/XML/GMP.xml @ONLY)
configure_file (tools/greenbone-feed-sync.in tools/greenbone-feed-sync @ONLY)
configure_file (tools/greenbone-scapdata-sync.in tools/greenbone-scapdata-sync @ONLY)
configure_file (tools/greenbone-certdata-sync.in tools/greenbone-certdata-sync @ONLY)
configure_file (tools/gvm-manage-certs.in tools/gvm-manage-certs @ONLY)

## Testing

enable_testing ()

## Program

if (ENABLE_COVERAGE)
  set (COVERAGE_FLAGS "--coverage")
endif (ENABLE_COVERAGE)

if (DEBUG_FUNCTION_NAMES)
  # The excluded functions are for update_nvti_cache, which fills the log
  # quickly.  Hopefully this internal NVTi cache is removed soon.
  set (DEBUG_FUNCTION_NAMES_FLAGS "-finstrument-functions -finstrument-functions-exclude-function-list=iterator_string,sql_column_text,next,sql_exec_internal")
  set (LINKER_DEBUG_FLAGS "${CMAKE_DL_LIBS}")
endif (DEBUG_FUNCTION_NAMES)

set (HARDENING_FLAGS            "-Wformat -Wformat-security -D_FORTIFY_SOURCE=2 -fstack-protector")
set (LINKER_HARDENING_FLAGS     "-Wl,-z,relro -Wl,-z,now")

# To find unused functions, add: -flto -fwhole-program -ffunction-sections -Wl,--gc-sections -Wl,--print-gc-sections
set (CMAKE_C_FLAGS              "${CMAKE_C_FLAGS} -Wall -D_BSD_SOURCE -D_ISOC99_SOURCE -D_SVID_SOURCE -D_DEFAULT_SOURCE -D_FILE_OFFSET_BITS=64")

set (CMAKE_C_FLAGS_DEBUG        "${CMAKE_C_FLAGS_DEBUG} -Werror -Wshadow ${COVERAGE_FLAGS} ${DEBUG_FUNCTION_NAMES_FLAGS}")
set (CMAKE_C_FLAGS_RELEASE      "${CMAKE_C_FLAGS_RELEASE} ${HARDENING_FLAGS} ${COVERAGE_FLAGS}")

# Flags used only for the gvmd binary, and not for the Postgres module.
set (C_FLAGS_DEBUG_GVMD         "-Wredundant-decls")

if (NOT SKIP_SRC)
  add_subdirectory (src)
endif (NOT SKIP_SRC)

## Configs (e.g. systemd service file)

add_subdirectory (config)

## Documentation

add_subdirectory (doc)

## Install

install (DIRECTORY DESTINATION ${GVMD_STATE_DIR})

install (DIRECTORY DESTINATION ${GVMD_RUN_DIR})

install (FILES ${CMAKE_BINARY_DIR}/src/gvmd_log.conf
         DESTINATION ${GVM_SYSCONF_DIR})

install (FILES ${CMAKE_SOURCE_DIR}/src/pwpolicy.conf
         DESTINATION ${GVM_SYSCONF_DIR})

# Schema formats.

install (FILES src/schema_formats/rnc.xsl
               src/schema_formats/HTML/HTML.xsl
         DESTINATION ${GVMD_DATA_DIR}/global_schema_formats/02052818-dab6-11df-9be4-002264764cea/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/schema_formats/HTML/generate
         DESTINATION ${GVMD_DATA_DIR}/global_schema_formats/02052818-dab6-11df-9be4-002264764cea/
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES src/schema_formats/rnc.xsl
               src/schema_formats/RNC/RNC.xsl
         DESTINATION ${GVMD_DATA_DIR}/global_schema_formats/787a4a18-dabc-11df-9486-002264764cea/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/schema_formats/RNC/generate
         DESTINATION ${GVMD_DATA_DIR}/global_schema_formats/787a4a18-dabc-11df-9486-002264764cea/
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES ${CMAKE_BINARY_DIR}/src/schema_formats/XML/GMP.xml
         DESTINATION ${GVMD_DATA_DIR}/global_schema_formats/18e826fc-dab6-11df-b913-002264764cea/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/schema_formats/XML/generate
         DESTINATION ${GVMD_DATA_DIR}/global_schema_formats/18e826fc-dab6-11df-b913-002264764cea/
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES src/schema_formats/XML-brief/GMP.xsl
         DESTINATION ${GVMD_DATA_DIR}/global_schema_formats/d6cf255e-947c-11e1-829a-406186ea4fc5/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/schema_formats/XML-brief/generate
         DESTINATION ${GVMD_DATA_DIR}/global_schema_formats/d6cf255e-947c-11e1-829a-406186ea4fc5/
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

# Alert methods.

install (FILES src/alert_methods/SCP/alert
         DESTINATION ${GVMD_DATA_DIR}/global_alert_methods/2db07698-ec49-11e5-bcff-28d24461215b/
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES src/alert_methods/Send/alert
         DESTINATION ${GVMD_DATA_DIR}/global_alert_methods/4a398d42-87c0-11e5-a1c0-28d24461215b/
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES src/alert_methods/SMB/alert
         DESTINATION ${GVMD_DATA_DIR}/global_alert_methods/c427a688-b653-40ab-a9d0-d6ba842a9d63/
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES src/alert_methods/SNMP/alert
         DESTINATION ${GVMD_DATA_DIR}/global_alert_methods/9d435134-15d3-11e6-bf5c-28d24461215b/
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES src/alert_methods/Sourcefire/alert
         DESTINATION ${GVMD_DATA_DIR}/global_alert_methods/cd1f5a34-6bdc-11e0-9827-002264764cea/
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES src/alert_methods/TippingPoint/alert
         DESTINATION ${GVMD_DATA_DIR}/global_alert_methods/5b39c481-9137-4876-b734-263849dd96ce/
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES src/alert_methods/TippingPoint/report-convert.py
         DESTINATION ${GVMD_DATA_DIR}/global_alert_methods/5b39c481-9137-4876-b734-263849dd96ce/
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES src/alert_methods/verinice/alert
         DESTINATION ${GVMD_DATA_DIR}/global_alert_methods/f9d97653-f89b-41af-9ba1-0f6ee00e9c1a/
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES src/alert_methods/vFire/alert
         DESTINATION ${GVMD_DATA_DIR}/global_alert_methods/159f79a5-fce8-4ec5-aa49-7d17a77739a3/
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

 install (CODE "file (MAKE_DIRECTORY \$ENV{DESTDIR}${GVMD_DATA_DIR}/wizards)")

install (FILES src/wizards/quick_first_scan.xml
               src/wizards/get_tasks_deep.xml
               src/wizards/delete_task_deep.xml
               src/wizards/quick_auth_scan.xml
               src/wizards/quick_task.xml
               src/wizards/reset_task.xml
               src/wizards/modify_task.xml
         DESTINATION ${GVMD_DATA_DIR}/wizards/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES tools/cpe_getbyname.xsl tools/cve_getbyname.xsl
         tools/ovaldef_getbyname.xsl
         DESTINATION ${GVM_SCAP_RES_DIR}
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES tools/cert_bund_getbyname.xsl tools/dfn_cert_getbyname.xsl
         DESTINATION ${GVM_CERT_RES_DIR}
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES ${CMAKE_BINARY_DIR}/tools/greenbone-feed-sync
         DESTINATION ${SBINDIR}
         PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE
                     GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES ${CMAKE_BINARY_DIR}/tools/greenbone-scapdata-sync
         DESTINATION ${SBINDIR}
         PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE
                     GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES ${CMAKE_BINARY_DIR}/tools/greenbone-certdata-sync
         DESTINATION ${SBINDIR}
         PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE
                     GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES ${CMAKE_SOURCE_DIR}/tools/gvm-lsc-deb-creator
               ${CMAKE_SOURCE_DIR}/tools/gvm-lsc-exe-creator
               ${CMAKE_SOURCE_DIR}/tools/gvm-lsc-rpm-creator
         DESTINATION ${GVM_DATA_DIR}
         PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE
                     GROUP_READ GROUP_EXECUTE
                     WORLD_READ WORLD_EXECUTE)

install (FILES ${CMAKE_SOURCE_DIR}/tools/template.nsis
         DESTINATION ${GVMD_DATA_DIR}
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES ${CMAKE_BINARY_DIR}/tools/gvm-manage-certs
         DESTINATION ${BINDIR}
         PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE
                     GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES ${CMAKE_SOURCE_DIR}/doc/gvm-manage-certs.1
          DESTINATION ${DATADIR}/man/man1 )

install (FILES ${CMAKE_BINARY_DIR}/doc/example-gvm-manage-certs.conf
         DESTINATION ${DATADIR}/doc/gvm/ )

## End
