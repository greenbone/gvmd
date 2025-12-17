# Copyright (C) 2009-2022 Greenbone AG
#
# SPDX-License-Identifier: AGPL-3.0-or-later

cmake_minimum_required(VERSION 3.5)

message("-- Configuring Greenbone Vulnerability Manager...")

project(gvm VERSION 26.12.2 LANGUAGES C)

if(POLICY CMP0005)
  cmake_policy(SET CMP0005 NEW)
endif(POLICY CMP0005)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR}/cmake)

include(FindPkgConfig)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif(NOT CMAKE_BUILD_TYPE)

option(ENABLE_COVERAGE "Enable support for coverage analysis" OFF)
option(DEBUG_FUNCTION_NAMES "Print function names on entry and exit" OFF)

## Retrieve git revision (at configure time)
include(GetGit)
if(NOT CMAKE_BUILD_TYPE MATCHES "Release")
  if(EXISTS "${CMAKE_SOURCE_DIR}/.git/")
    if(GIT_FOUND)
      git_get_revision(${CMAKE_SOURCE_DIR} ProjectRevision)
      set(GIT_REVISION "~git-${ProjectRevision}")
    else(GIT_FOUND)
      set(GIT_REVISION "~git")
    endif(GIT_FOUND)
  endif(EXISTS "${CMAKE_SOURCE_DIR}/.git/")
endif(NOT CMAKE_BUILD_TYPE MATCHES "Release")

# Set dev version if this is a development version and not a full release,
# unset (put value 0 or delete line) before a full release and reset after.
set(PROJECT_DEV_VERSION 1)

# If PROJECT_DEV_VERSION is set, the version string will be set to:
#   "major.minor.patch~dev${PROJECT_DEV_VERSION}${GIT_REVISION}"
# If PROJECT_DEV_VERSION is NOT set, the version string will be set to:
#   "major.minor.patch${GIT_REVISION}"
# For CMAKE_BUILD_TYPE "Release" the git revision will be empty.
if(PROJECT_DEV_VERSION)
  set(PROJECT_VERSION_SUFFIX "~dev${PROJECT_DEV_VERSION}")
endif(PROJECT_DEV_VERSION)

set(
  PROJECT_VERSION_STRING
  "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}${PROJECT_VERSION_SUFFIX}${GIT_REVISION}"
)

## make format
message(STATUS "Looking for clang-format...")
find_program(CLANG_FORMAT clang-format)

if(CLANG_FORMAT)
  message(STATUS "Looking for clang-format... ${CLANG_FORMAT}")
  add_custom_target(
    format
    COMMAND
      ${CLANG_FORMAT} "-style=file" "src/gmp_{base,delete,get,tickets}.h"
      "src/{gmp,gmpd,iterator,sql,types,utils,manage_utils}.h"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
  )
else(CLANG_FORMAT)
  message(STATUS "clang-format not found.")
endif(CLANG_FORMAT)

## CPack configuration

set(CPACK_CMAKE_GENERATOR "Unix Makefiles")
set(CPACK_GENERATOR "TGZ")
set(CPACK_INSTALL_CMAKE_PROJECTS ".;gvm;ALL;/")
set(CPACK_MODULE_PATH "")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/COPYING")
set(CPACK_RESOURCE_FILE_README "${CMAKE_SOURCE_DIR}/README.md")
set(CPACK_RESOURCE_FILE_WELCOME "${CMAKE_SOURCE_DIR}/README.md")
set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_TOPLEVEL_TAG "")
set(CPACK_SYSTEM_NAME "")
set(CPACK_TOPLEVEL_TAG "")

set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION_STRING}${PROJECT_VERSION_GIT}")

set(CPACK_PACKAGE_FILE_NAME "${PROJECT_NAME}-${CPACK_PACKAGE_VERSION}")
set(CPACK_SOURCE_PACKAGE_FILE_NAME "${PROJECT_NAME}-${CPACK_PACKAGE_VERSION}")
set(CPACK_PACKAGE_VENDOR "Greenbone AG")
set(CPACK_SOURCE_IGNORE_FILES "${CMAKE_BINARY_DIR}" "/.git/" "swp$")

include(CPack)

## Variables

set(GVMD_DATABASE_VERSION 264)

set(GVMD_SCAP_DATABASE_VERSION 22)

set(GVMD_CERT_DATABASE_VERSION 8)

if(ENABLE_AGENTS OR ENABLE_CONTAINER_SCANNING)
  # Set a to the next GMP version if unstable features are enabled
  set(GMP_VERSION "22.8")
else(ENABLE_AGENTS OR ENABLE_CONTAINER_SCANNING)
  set(GMP_VERSION "22.7")
endif(ENABLE_AGENTS OR ENABLE_CONTAINER_SCANNING)

if(SYSCONF_INSTALL_DIR)
  set(SYSCONFDIR "${SYSCONF_INSTALL_DIR}")
endif(SYSCONF_INSTALL_DIR)

if(NOT SYSCONFDIR)
  set(SYSCONFDIR "/etc")
endif(NOT SYSCONFDIR)

if(NOT EXEC_PREFIX)
  set(EXEC_PREFIX "${CMAKE_INSTALL_PREFIX}")
endif(NOT EXEC_PREFIX)

if(NOT BINDIR)
  set(BINDIR "${EXEC_PREFIX}/bin")
endif(NOT BINDIR)

if(NOT SBINDIR)
  set(SBINDIR "${EXEC_PREFIX}/sbin")
endif(NOT SBINDIR)

if(NOT LIBDIR)
  set(LIBDIR "${EXEC_PREFIX}/lib")
endif(NOT LIBDIR)

if(NOT LOCALSTATEDIR)
  set(LOCALSTATEDIR "/var")
endif(NOT LOCALSTATEDIR)

if(NOT DATADIR)
  set(DATADIR "${CMAKE_INSTALL_PREFIX}/share")
endif(NOT DATADIR)

if(NOT INCLUDEDIR)
  set(INCLUDEDIR "${CMAKE_INSTALL_PREFIX}/include")
endif(NOT INCLUDEDIR)

set(GVM_SYSCONF_DIR "${SYSCONFDIR}/gvm")

set(GVM_DATA_DIR "${DATADIR}/gvm")
if(NOT GVMD_DATA_DIR)
  set(GVMD_DATA_DIR "${GVM_DATA_DIR}/gvmd")
endif(NOT GVMD_DATA_DIR)

if(NOT GVM_STATE_DIR)
  set(GVM_STATE_DIR "${LOCALSTATEDIR}/lib/gvm")
else(NOT GVM_STATE_DIR)
  set(GVM_STATE_DIR "${GVM_STATE_DIR}")
endif(NOT GVM_STATE_DIR)

if(NOT GVMD_STATE_DIR)
  set(GVMD_STATE_DIR "${GVM_STATE_DIR}/gvmd")
endif(NOT GVMD_STATE_DIR)

if(NOT GVMD_LOG_FILE)
  if(GVM_LOG_DIR)
    set(GVMD_LOG_FILE "${GVM_LOG_DIR}/gvmd.log")
  else(GVM_LOG_DIR)
    set(GVMD_LOG_FILE "-")
  endif(GVM_LOG_DIR)
endif(NOT GVMD_LOG_FILE)

set(GVM_SCAP_RES_DIR "${GVM_DATA_DIR}/scap")
set(GVM_CERT_RES_DIR "${GVM_DATA_DIR}/cert")
set(GVM_CA_DIR "${GVMD_STATE_DIR}/trusted_certs")

if(NOT GVM_LIB_INSTALL_DIR)
  set(GVM_LIB_INSTALL_DIR "${LIBDIR}")
else(NOT GVM_LIB_INSTALL_DIR)
  set(GVM_LIB_INSTALL_DIR "${GVM_LIB_INSTALL_DIR}")
endif(NOT GVM_LIB_INSTALL_DIR)

set(GVM_SCANNER_CERTIFICATE "${GVM_STATE_DIR}/CA/servercert.pem")
set(GVM_SCANNER_KEY "${GVM_STATE_DIR}/private/CA/serverkey.pem")
set(GVM_CLIENT_CERTIFICATE "${GVM_STATE_DIR}/CA/clientcert.pem")
set(GVM_CLIENT_KEY "${GVM_STATE_DIR}/private/CA/clientkey.pem")
set(GVM_CA_CERTIFICATE "${GVM_STATE_DIR}/CA/cacert.pem")

if(NOT GVMD_RUN_DIR)
  set(GVMD_RUN_DIR "/run/gvmd")
endif(NOT GVMD_RUN_DIR)

if(NOT GVMD_PID_PATH)
  set(GVMD_PID_PATH "${GVMD_RUN_DIR}/gvmd.pid")
endif(NOT GVMD_PID_PATH)

if(NOT GVM_FEED_LOCK_PATH)
  set(GVM_FEED_LOCK_PATH "${GVM_STATE_DIR}/feed-update.lock")
endif(NOT GVM_FEED_LOCK_PATH)
add_definitions(-DGVM_FEED_LOCK_PATH="${GVM_FEED_LOCK_PATH}")

if(NOT OPENVAS_DEFAULT_SOCKET)
  set(OPENVAS_DEFAULT_SOCKET "/run/ospd/ospd-openvas.sock")
endif(NOT OPENVAS_DEFAULT_SOCKET)
add_definitions(-DOPENVAS_DEFAULT_SOCKET="${OPENVAS_DEFAULT_SOCKET}")

# TODO: Once we separate the RFP signatures out of "plugins" and
# into var/lib/gvm/rfpsigs/ (via a sync script) then we do not need
# to know about the NVT_DIR anymore.
if(NOT GVM_NVT_DIR)
  set(GVM_NVT_DIR "${LOCALSTATEDIR}/lib/openvas/plugins/")
endif(NOT GVM_NVT_DIR)

if(NOT DATA_OBJECTS_FEED_DIR)
  set(DATA_OBJECTS_FEED_DIR "${LOCALSTATEDIR}/lib/gvm/data-objects")
endif(NOT DATA_OBJECTS_FEED_DIR)

if(NOT GVMD_FEED_DIR)
  set(GVMD_FEED_DIR "${DATA_OBJECTS_FEED_DIR}/gvmd")
endif(NOT GVMD_FEED_DIR)

if(NOT GVM_ACCESS_KEY_DIR)
  set(GVM_ACCESS_KEY_DIR "${GVM_SYSCONF_DIR}")
endif(NOT GVM_ACCESS_KEY_DIR)

if(NOT GVM_CERT_DATA_DIR)
  set(GVM_CERT_DATA_DIR "${GVM_STATE_DIR}/cert-data")
endif(NOT GVM_CERT_DATA_DIR)

if(NOT GVM_SCAP_DATA_DIR)
  set(GVM_SCAP_DATA_DIR "${GVM_STATE_DIR}/scap-data")
endif(NOT GVM_SCAP_DATA_DIR)

# System username to use when dropping privileges
if(NOT GVM_DEFAULT_DROP_USER)
  set(GVM_DEFAULT_DROP_USER "")
endif(NOT GVM_DEFAULT_DROP_USER)

# Feature toggles
if(NOT ENABLE_OPENVASD)
  set(ENABLE_OPENVASD 0)
endif(NOT ENABLE_OPENVASD)
add_definitions(-DENABLE_OPENVASD=${ENABLE_OPENVASD})

if(NOT ENABLE_AGENTS)
  set(ENABLE_AGENTS 0)
endif(NOT ENABLE_AGENTS)
add_definitions(-DENABLE_AGENTS=${ENABLE_AGENTS})

if(ENABLE_AGENTS EQUAL 1)
  set(IF_ENABLE_AGENTS "")
  set(ENDIF_ENABLE_AGENTS "")
  set(IF_NOT_ENABLE_AGENTS "<!--")
  set(ENDIF_NOT_ENABLE_AGENTS "-->")
elseif(ENABLE_AGENTS EQUAL 0)
  set(IF_ENABLE_AGENTS "<!--")
  set(ENDIF_ENABLE_AGENTS "-->")
  set(IF_NOT_ENABLE_AGENTS "")
  set(ENDIF_NOT_ENABLE_AGENTS "")
endif()

if(NOT ENABLE_CONTAINER_SCANNING)
  set(ENABLE_CONTAINER_SCANNING 0)
endif(NOT ENABLE_CONTAINER_SCANNING)
add_definitions(-DENABLE_CONTAINER_SCANNING=${ENABLE_CONTAINER_SCANNING})

if(ENABLE_CONTAINER_SCANNING EQUAL 1)
  set(IF_ENABLE_CONTAINER_SCANNNING "")
  set(ENDIF_ENABLE_CONTAINER_SCANNNING "")
elseif(ENABLE_CONTAINER_SCANNING EQUAL 0)
  set(IF_ENABLE_CONTAINER_SCANNNING "<!--")
  set(ENDIF_ENABLE_CONTAINER_SCANNNING "-->")
endif()

# HTTP scanner capability (used by ENABLE_OPENVASD / AGENTS / CONTAINER_SCANNING)
if(ENABLE_OPENVASD OR ENABLE_AGENTS OR ENABLE_CONTAINER_SCANNING)
  set(ENABLE_HTTP_SCANNER 1)
else()
  set(ENABLE_HTTP_SCANNER 0)
endif()
add_definitions(-DENABLE_HTTP_SCANNER=${ENABLE_HTTP_SCANNER})

# Credential stores
if(NOT ENABLE_CREDENTIAL_STORES)
  set(ENABLE_CREDENTIAL_STORES 0)
endif(NOT ENABLE_CREDENTIAL_STORES)
add_definitions(-DENABLE_CREDENTIAL_STORES=${ENABLE_CREDENTIAL_STORES})

if(ENABLE_CREDENTIAL_STORES EQUAL 1)
  set(IF_ENABLE_CREDENTIAL_STORES "")
  set(ENDIF_ENABLE_CREDENTIAL_STORES "")
elseif(ENABLE_CONTAINER_SCANNING EQUAL 0)
  set(IF_ENABLE_CREDENTIAL_STORES "<!--")
  set(ENDIF_ENABLE_CREDENTIAL_STORES "-->")
endif()

message("-- Install prefix: ${CMAKE_INSTALL_PREFIX}")
message("-- Log file: ${GVMD_LOG_FILE}")

## Version

set(GVMD_VERSION "${PROJECT_VERSION_STRING}")

# Configure Doxyfile with version number
configure_file(docs/Doxyfile.in docs/Doxyfile)
configure_file(docs/Doxyfile_full.in docs/Doxyfile_full)
configure_file(docs/Doxyfile_xml.in docs/Doxyfile_xml)
configure_file(
  docs/example-gvm-manage-certs.conf.in
  docs/example-gvm-manage-certs.conf
  @ONLY
)
configure_file(VERSION.in VERSION)
configure_file(src/gvmd_log_conf.cmake_in src/gvmd_log.conf)
configure_file(
  src/schema_formats/XML/GMP.xml.in
  src/schema_formats/XML/GMP.xml
  @ONLY
)
configure_file(tools/gvm-manage-certs.in tools/gvm-manage-certs @ONLY)

## Code coverage

option(ENABLE_COVERAGE "Enable support for coverage analysis" OFF)
if(ENABLE_COVERAGE)
  set(COVERAGE_FLAGS "--coverage -ftest-coverage -fprofile-arcs")
  set(COVERAGE_DIR "${CMAKE_BINARY_DIR}/coverage")
  file(MAKE_DIRECTORY ${COVERAGE_DIR})
  message("-- Code Coverage enabled")
endif(ENABLE_COVERAGE)

## Testing

enable_testing()

## Program

if(DEBUG_FUNCTION_NAMES)
  # The excluded functions are for update_nvti_cache, which fills the log
  # quickly.  Hopefully this internal NVTi cache is removed soon.
  set(
    DEBUG_FUNCTION_NAMES_FLAGS
    "-finstrument-functions -finstrument-functions-exclude-function-list=iterator_string,sql_column_text,next,sql_exec_internal"
  )
  set(LINKER_DEBUG_FLAGS "${CMAKE_DL_LIBS}")
endif(DEBUG_FUNCTION_NAMES)

set(
  HARDENING_FLAGS
  "-Wformat -Wformat-security -D_FORTIFY_SOURCE=2 -fstack-protector"
)
set(LINKER_HARDENING_FLAGS "-Wl,-z,relro -Wl,-z,now")

# To find unused functions, add: -flto -fwhole-program -ffunction-sections -Wl,--gc-sections -Wl,--print-gc-sections
set(
  CMAKE_C_FLAGS
  "${CMAKE_C_FLAGS} -Wall -D_BSD_SOURCE -D_ISOC99_SOURCE -D_SVID_SOURCE -D_DEFAULT_SOURCE -D_FILE_OFFSET_BITS=64 ${COVERAGE_FLAGS}"
)

set(
  CMAKE_C_FLAGS_DEBUG
  "${CMAKE_C_FLAGS_DEBUG} -Werror -Wshadow ${COVERAGE_FLAGS} ${DEBUG_FUNCTION_NAMES_FLAGS}"
)
set(
  CMAKE_C_FLAGS_RELEASE
  "${CMAKE_C_FLAGS_RELEASE} ${HARDENING_FLAGS} ${COVERAGE_FLAGS}"
)

# Flags used only for the gvmd binary, and not for the Postgres module.
set(C_FLAGS_DEBUG_GVMD "-Wredundant-decls")

if(NOT SKIP_SRC)
  add_subdirectory(src)
endif(NOT SKIP_SRC)

## Configs (e.g. systemd service file)

add_subdirectory(config)

## Documentation

add_subdirectory(docs)

## Install

install(DIRECTORY DESTINATION ${GVMD_STATE_DIR})

install(
  FILES ${CMAKE_BINARY_DIR}/src/gvmd_log.conf
  DESTINATION ${GVM_SYSCONF_DIR}
)

install(
  FILES ${CMAKE_SOURCE_DIR}/src/pwpolicy.conf
  DESTINATION ${GVM_SYSCONF_DIR}
)

# Schema formats.

install(
  FILES src/schema_formats/rnc.xsl
  DESTINATION ${GVMD_DATA_DIR}/global_schema_formats/
  PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ
)

install(
  FILES src/schema_formats/rnc.xsl src/schema_formats/HTML/HTML.xsl
  DESTINATION
    ${GVMD_DATA_DIR}/global_schema_formats/02052818-dab6-11df-9be4-002264764cea/
  PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ
)

install(
  FILES src/schema_formats/HTML/generate
  DESTINATION
    ${GVMD_DATA_DIR}/global_schema_formats/02052818-dab6-11df-9be4-002264764cea/
  PERMISSIONS
    OWNER_WRITE
    OWNER_READ
    OWNER_EXECUTE
    GROUP_READ
    GROUP_EXECUTE
    WORLD_READ
    WORLD_EXECUTE
)

install(
  FILES src/schema_formats/rnc.xsl src/schema_formats/RNC/RNC.xsl
  DESTINATION
    ${GVMD_DATA_DIR}/global_schema_formats/787a4a18-dabc-11df-9486-002264764cea/
  PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ
)

install(
  FILES src/schema_formats/RNC/generate
  DESTINATION
    ${GVMD_DATA_DIR}/global_schema_formats/787a4a18-dabc-11df-9486-002264764cea/
  PERMISSIONS
    OWNER_WRITE
    OWNER_READ
    OWNER_EXECUTE
    GROUP_READ
    GROUP_EXECUTE
    WORLD_READ
    WORLD_EXECUTE
)

install(
  FILES ${CMAKE_BINARY_DIR}/src/schema_formats/XML/GMP.xml
  DESTINATION
    ${GVMD_DATA_DIR}/global_schema_formats/18e826fc-dab6-11df-b913-002264764cea/
  PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ
)

install(
  FILES src/schema_formats/XML/generate
  DESTINATION
    ${GVMD_DATA_DIR}/global_schema_formats/18e826fc-dab6-11df-b913-002264764cea/
  PERMISSIONS
    OWNER_WRITE
    OWNER_READ
    OWNER_EXECUTE
    GROUP_READ
    GROUP_EXECUTE
    WORLD_READ
    WORLD_EXECUTE
)

install(
  FILES src/schema_formats/XML-brief/GMP.xsl
  DESTINATION
    ${GVMD_DATA_DIR}/global_schema_formats/d6cf255e-947c-11e1-829a-406186ea4fc5/
  PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ
)

install(
  FILES src/schema_formats/XML-brief/generate
  DESTINATION
    ${GVMD_DATA_DIR}/global_schema_formats/d6cf255e-947c-11e1-829a-406186ea4fc5/
  PERMISSIONS
    OWNER_WRITE
    OWNER_READ
    OWNER_EXECUTE
    GROUP_READ
    GROUP_EXECUTE
    WORLD_READ
    WORLD_EXECUTE
)

# Alert methods.

install(
  FILES src/alert_methods/SCP/alert
  DESTINATION
    ${GVMD_DATA_DIR}/global_alert_methods/2db07698-ec49-11e5-bcff-28d24461215b/
  PERMISSIONS
    OWNER_WRITE
    OWNER_READ
    OWNER_EXECUTE
    GROUP_READ
    GROUP_EXECUTE
    WORLD_READ
    WORLD_EXECUTE
)

install(
  FILES src/alert_methods/Send/alert
  DESTINATION
    ${GVMD_DATA_DIR}/global_alert_methods/4a398d42-87c0-11e5-a1c0-28d24461215b/
  PERMISSIONS
    OWNER_WRITE
    OWNER_READ
    OWNER_EXECUTE
    GROUP_READ
    GROUP_EXECUTE
    WORLD_READ
    WORLD_EXECUTE
)

install(
  FILES src/alert_methods/SMB/alert
  DESTINATION
    ${GVMD_DATA_DIR}/global_alert_methods/c427a688-b653-40ab-a9d0-d6ba842a9d63/
  PERMISSIONS
    OWNER_WRITE
    OWNER_READ
    OWNER_EXECUTE
    GROUP_READ
    GROUP_EXECUTE
    WORLD_READ
    WORLD_EXECUTE
)

install(
  FILES src/alert_methods/SNMP/alert
  DESTINATION
    ${GVMD_DATA_DIR}/global_alert_methods/9d435134-15d3-11e6-bf5c-28d24461215b/
  PERMISSIONS
    OWNER_WRITE
    OWNER_READ
    OWNER_EXECUTE
    GROUP_READ
    GROUP_EXECUTE
    WORLD_READ
    WORLD_EXECUTE
)

install(
  FILES src/alert_methods/Sourcefire/alert
  DESTINATION
    ${GVMD_DATA_DIR}/global_alert_methods/cd1f5a34-6bdc-11e0-9827-002264764cea/
  PERMISSIONS
    OWNER_WRITE
    OWNER_READ
    OWNER_EXECUTE
    GROUP_READ
    GROUP_EXECUTE
    WORLD_READ
    WORLD_EXECUTE
)

install(
  FILES src/alert_methods/TippingPoint/alert
  DESTINATION
    ${GVMD_DATA_DIR}/global_alert_methods/5b39c481-9137-4876-b734-263849dd96ce/
  PERMISSIONS
    OWNER_WRITE
    OWNER_READ
    OWNER_EXECUTE
    GROUP_READ
    GROUP_EXECUTE
    WORLD_READ
    WORLD_EXECUTE
)

install(
  FILES src/alert_methods/TippingPoint/report-convert.py
  DESTINATION
    ${GVMD_DATA_DIR}/global_alert_methods/5b39c481-9137-4876-b734-263849dd96ce/
  PERMISSIONS
    OWNER_WRITE
    OWNER_READ
    OWNER_EXECUTE
    GROUP_READ
    GROUP_EXECUTE
    WORLD_READ
    WORLD_EXECUTE
)

install(
  FILES src/alert_methods/verinice/alert
  DESTINATION
    ${GVMD_DATA_DIR}/global_alert_methods/f9d97653-f89b-41af-9ba1-0f6ee00e9c1a/
  PERMISSIONS
    OWNER_WRITE
    OWNER_READ
    OWNER_EXECUTE
    GROUP_READ
    GROUP_EXECUTE
    WORLD_READ
    WORLD_EXECUTE
)

install(
  FILES src/alert_methods/vFire/alert
  DESTINATION
    ${GVMD_DATA_DIR}/global_alert_methods/159f79a5-fce8-4ec5-aa49-7d17a77739a3/
  PERMISSIONS
    OWNER_WRITE
    OWNER_READ
    OWNER_EXECUTE
    GROUP_READ
    GROUP_EXECUTE
    WORLD_READ
    WORLD_EXECUTE
)

install(CODE "file (MAKE_DIRECTORY \$ENV{DESTDIR}${GVMD_DATA_DIR}/wizards)")

install(
  FILES
    src/wizards/quick_first_scan.xml
    src/wizards/get_tasks_deep.xml
    src/wizards/delete_task_deep.xml
    src/wizards/quick_auth_scan.xml
    src/wizards/quick_task.xml
    src/wizards/reset_task.xml
    src/wizards/modify_task.xml
  DESTINATION ${GVMD_DATA_DIR}/wizards/
  PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ
)

install(
  FILES tools/cpe_getbyname.xsl tools/cve_getbyname.xsl
  DESTINATION ${GVM_SCAP_RES_DIR}
  PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ
)

install(
  FILES tools/cert_bund_getbyname.xsl tools/dfn_cert_getbyname.xsl
  DESTINATION ${GVM_CERT_RES_DIR}
  PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ
)

install(
  FILES
    ${CMAKE_SOURCE_DIR}/tools/gvm-lsc-deb-creator
    ${CMAKE_SOURCE_DIR}/tools/gvm-lsc-exe-creator
    ${CMAKE_SOURCE_DIR}/tools/gvm-lsc-rpm-creator
  DESTINATION ${GVM_DATA_DIR}
  PERMISSIONS
    OWNER_EXECUTE
    OWNER_READ
    OWNER_WRITE
    GROUP_READ
    GROUP_EXECUTE
    WORLD_READ
    WORLD_EXECUTE
)

install(
  FILES ${CMAKE_SOURCE_DIR}/tools/template.nsis
  DESTINATION ${GVMD_DATA_DIR}
  PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ
)

install(
  FILES ${CMAKE_BINARY_DIR}/tools/gvm-manage-certs
  DESTINATION ${BINDIR}
  PERMISSIONS
    OWNER_EXECUTE
    OWNER_READ
    OWNER_WRITE
    GROUP_READ
    GROUP_EXECUTE
    WORLD_READ
    WORLD_EXECUTE
)

install(
  FILES ${CMAKE_SOURCE_DIR}/docs/gvm-manage-certs.1
  DESTINATION ${DATADIR}/man/man1
)

install(
  FILES ${CMAKE_BINARY_DIR}/docs/example-gvm-manage-certs.conf
  DESTINATION ${DATADIR}/doc/gvm/
)

## End
