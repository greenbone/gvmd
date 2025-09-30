# Copyright (C) 2009-2022 Greenbone AG
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

## Libraries

find_package(Threads)

## Dependency checks
##
## TODO Also check for headers where needed.
## Improve for workflow: First collect list of missing libs, then print the
## list and throw an error, otherwise long install-cmake-install-cmake cycles
## might occur.

pkg_check_modules(CJSON REQUIRED libcjson>=1.7.14)
pkg_check_modules(LIBGVM_BASE REQUIRED libgvm_base>=22.28)
pkg_check_modules(LIBGVM_UTIL REQUIRED libgvm_util>=22.28)
pkg_check_modules(LIBGVM_OSP REQUIRED libgvm_osp>=22.28)
pkg_check_modules(LIBGVM_GMP REQUIRED libgvm_gmp>=22.28)

if(ENABLE_HTTP_SCANNER)
  pkg_check_modules(LIBGVM_HTTP REQUIRED libgvm_http>=22.28)
  pkg_check_modules(LIBGVM_HTTP_SCANNER REQUIRED libgvm_http_scanner>=22.28)
endif(ENABLE_HTTP_SCANNER)
if(OPENVASD)
  pkg_check_modules(LIBGVM_OPENVASD REQUIRED libgvm_openvasd>=22.28)
else(OPENVASD)
  message(STATUS "OPENVASD flag is not enabled")
endif(OPENVASD)
if(ENABLE_AGENTS)
  pkg_check_modules(
    LIBGVM_AGENT_CONTROLLER
    REQUIRED
    libgvm_agent_controller>=22.28
  )
else(ENABLE_AGENTS)
  message(STATUS "ENABLE_AGENTS flag is not enabled")
endif(ENABLE_AGENTS)
pkg_check_modules(GNUTLS REQUIRED gnutls>=3.2.15)
pkg_check_modules(GLIB REQUIRED glib-2.0>=2.42)
pkg_check_modules(LIBBSD REQUIRED libbsd)
pkg_check_modules(LIBICAL REQUIRED libical>=1.00)
pkg_check_modules(GPGME REQUIRED gpgme)

message(STATUS "Looking for PostgreSQL...")
find_program(PG_CONFIG_EXECUTABLE pg_config DOC "pg_config")
execute_process(
  COMMAND ${PG_CONFIG_EXECUTABLE} --includedir-server
  OUTPUT_VARIABLE PostgreSQL_SERVER_INCLUDE_DIRS
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
set(PostgreSQL_ADDITIONAL_SEARCH_PATHS ${PostgreSQL_SERVER_INCLUDE_DIRS})
find_package(PostgreSQL REQUIRED)
if(NOT PostgreSQL_FOUND)
  message(SEND_ERROR "The PostgreSQL library is required.")
endif(NOT PostgreSQL_FOUND)
string(
  REGEX MATCH
  "^[ \t]*\([0-9]+\)\\.\([0-9]+\)\(.*\)"
  TEMP
  "${PostgreSQL_VERSION_STRING}"
)
if(NOT CMAKE_MATCH_1)
  message(SEND_ERROR "Error matching PostgreSQL version.")
elseif(
  (CMAKE_MATCH_1 EQUAL 9 AND CMAKE_MATCH_2 LESS 6)
  OR (CMAKE_MATCH_1 LESS 9)
)
  message(SEND_ERROR "PostgreSQL version >= 9.6 is required")
  message(
    STATUS
    "PostgreSQL version ${CMAKE_MATCH_1}.${CMAKE_MATCH_2}${CMAKE_MATCH_3}"
  )
endif(NOT CMAKE_MATCH_1)

message(STATUS "Looking for xsltproc...")
find_program(XSLTPROC_EXECUTABLE xsltproc DOC "xsltproc")
if(NOT XSLTPROC_EXECUTABLE)
  message(SEND_ERROR "The xsltproc binary is required.")
else(NOT XSLTPROC_EXECUTABLE)
  message(STATUS "Looking for xsltproc... ${XSLTPROC_EXECUTABLE}")
endif(NOT XSLTPROC_EXECUTABLE)

if(NOT GPGME_FOUND)
  # fallback for older gpgme versions without gpgme.pc file
  message(STATUS "Looking for gpgme...")
  find_library(GPGME gpgme)
  if(NOT GPGME)
    message(SEND_ERROR "The gpgme library is required.")
  else(NOT GPGME)
    message(STATUS "Looking for gpgme... ${GPGME}")
    execute_process(
      COMMAND gpgme-config --cflags
      OUTPUT_VARIABLE GPGME_CFLAGS
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    execute_process(
      COMMAND gpgme-config --libs
      OUTPUT_VARIABLE GPGME_LDFLAGS
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )
  endif(NOT GPGME)
endif(NOT GPGME_FOUND)

if(WITH_LIBTHEIA)
  find_package(Theia 1.0.0 REQUIRED)
  message(STATUS "Using libtheia ${Theia_VERSION} in ${Theia_DIR}")
  add_definitions(-DHAS_LIBTHEIA="1")
  set(OPT_THEIA_TGT Theia::Theia)
else(WITH_LIBTHEIA)
  message(STATUS "Not using libtheia - licensing functions disabled")
  set(OPT_THEIA_TGT "")
endif(WITH_LIBTHEIA)

include_directories(
  ${LIBGVM_AGENT_CONTROLLER_INCLUDE_DIRS}
  ${LIBGVM_GMP_INCLUDE_DIRS}
  ${LIBGVM_OPENVASD_INCLUDE_DIRS}
  ${LIBGVM_BASE_INCLUDE_DIRS}
  ${LIBGVM_UTIL_INCLUDE_DIRS}
  ${LIBGVM_OSP_INCLUDE_DIRS}
  ${LIBBSD_INCLUDE_DIRS}
  ${GLIB_INCLUDE_DIRS}
)

add_library(gvm-pg-server SHARED manage_pg_server.c manage_utils.c)
set_target_properties(
  gvm-pg-server
  PROPERTIES SOVERSION "${CPACK_PACKAGE_VERSION_MAJOR}"
)
set_target_properties(
  gvm-pg-server
  PROPERTIES VERSION "${CPACK_PACKAGE_VERSION}"
)
include_directories(
  ${PostgreSQL_INCLUDE_DIRS}
  ${PostgreSQL_SERVER_INCLUDE_DIRS}
)

# Source lists
set(
  ALL_MANAGE_SRC
  manage.c
  manage_acl.c
  manage_alerts.c
  manage_configs.c
  manage_events.c
  manage_filter_utils.c
  manage_commands.c
  manage_get.c
  manage_http_scanner.c
  manage_license.c
  manage_openvas.c
  manage_osp.c
  manage_port_lists.c
  manage_preferences.c
  manage_resources.c
  manage_report_configs.c
  manage_report_formats.c
  manage_authentication.c
  manage_settings.c
  manage_tls_certificates.c
  manage_utils.c
  manage_migrators.c
  manage_pg.c
  manage_scan_handler.c
  manage_scan_queue.c
  manage_oci_image_targets.c
)

if(ENABLE_AGENTS)
  list(
    APPEND
    ALL_MANAGE_SRC
    manage_agent_common.c
    manage_agent_groups.c
    manage_agents.c
    manage_agent_installers.c
    manage_agent_control_scan_config.c
  )
endif()

set(
  ALL_MANAGE_SQL_SRC
  manage_sql.c
  manage_sql_copy.c
  manage_sql_alerts.c
  manage_sql_assets.c
  manage_sql_events.c
  manage_sql_filters.c
  manage_sql_nvts.c
  manage_sql_secinfo.c
  manage_sql_port_lists.c
  manage_sql_configs.c
  manage_sql_report_configs.c
  manage_sql_report_formats.c
  manage_sql_tickets.c
  manage_sql_tls_certificates.c
  manage_sql_nvts_osp.c
  manage_sql_nvts_openvasd.c
  manage_sql_nvts_common.c
  manage_sql_scan_queue.c
  manage_sql_oci_image_targets.c
)

if(ENABLE_AGENTS)
  list(
    APPEND
    ALL_MANAGE_SQL_SRC
    manage_sql_agent_groups.c
    manage_sql_agents.c
    manage_sql_agent_installers.c
  )
endif()

set(
  ALL_GMP_SRC
  gmp.c
  gmp_base.c
  gmp_configs.c
  gmp_delete.c
  gmp_get.c
  gmp_license.c
  gmp_logout.c
  gmp_port_lists.c
  gmp_report_configs.c
  gmp_report_formats.c
  gmp_tickets.c
  gmp_tls_certificates.c
  gmp_oci_image_targets.c
)

if(ENABLE_AGENTS)
  list(
    APPEND
    ALL_GMP_SRC
    gmp_agent_control_scan_agent_config.c
    gmp_agent_groups.c
    gmp_agents.c
    gmp_agent_installers.c
  )
endif()

set(ALL_SQL_SRC sql.c sql_pg.c)

set(
  ALL_MISC_SRC
  debug_utils.c
  gvmd.c
  gmpd.c
  ipc.c
  lsc_user.c
  lsc_crypt.c
  utils.c
)

## Object libraries

add_library(all-manage-obj OBJECT ${ALL_MANAGE_SRC})

add_library(all-manage-sql-obj OBJECT ${ALL_MANAGE_SQL_SRC})

add_library(all-gmp-obj OBJECT ${ALL_GMP_SRC})

add_library(all-sql-obj OBJECT ${ALL_SQL_SRC})

add_library(all-misc-obj OBJECT ${ALL_MISC_SRC})

## Program

set(TEST_TARGET_EXTRA_SRC ${ALL_MANAGE_SQL_SRC})
list(REMOVE_ITEM TEST_TARGET_EXTRA_SRC manage_sql.c)
add_executable(
  manage-sql-test
  EXCLUDE_FROM_ALL
  manage_sql_tests.c
  $<TARGET_OBJECTS:all-gmp-obj>
  $<TARGET_OBJECTS:all-misc-obj>
  $<TARGET_OBJECTS:all-manage-obj>
  $<TARGET_OBJECTS:all-sql-obj>
  ${TEST_TARGET_EXTRA_SRC}
)

add_test(manage-sql-test manage-sql-test)

set(TEST_TARGET_EXTRA_SRC ${ALL_GMP_SRC})
list(REMOVE_ITEM TEST_TARGET_EXTRA_SRC gmp_tickets.c)
add_executable(
  gmp-tickets-test
  EXCLUDE_FROM_ALL
  gmp_tickets_tests.c
  $<TARGET_OBJECTS:all-manage-obj>
  $<TARGET_OBJECTS:all-manage-sql-obj>
  $<TARGET_OBJECTS:all-misc-obj>
  $<TARGET_OBJECTS:all-sql-obj>
  ${TEST_TARGET_EXTRA_SRC}
)

add_test(gmp-tickets-test gmp-tickets-test)

set(TEST_TARGET_EXTRA_SRC ${ALL_MISC_SRC})
list(REMOVE_ITEM TEST_TARGET_EXTRA_SRC utils.c)
add_executable(
  utils-test
  EXCLUDE_FROM_ALL
  utils_tests.c
  $<TARGET_OBJECTS:all-gmp-obj>
  $<TARGET_OBJECTS:all-manage-obj>
  $<TARGET_OBJECTS:all-manage-sql-obj>
  $<TARGET_OBJECTS:all-sql-obj>
  ${TEST_TARGET_EXTRA_SRC}
)

add_test(utils-test utils-test)

set(
  TEST_DEPENDENCIES
  gmp-tickets-test
  manage-sql-test
  manage-utils-test
  utils-test
)

if(ENABLE_COVERAGE)
  add_custom_target(
    coverage-html
    COMMAND
      gcovr --html-details ${COVERAGE_DIR}/coverage.html -r ${CMAKE_SOURCE_DIR}
      ${CMAKE_BINARY_DIR}
  )
  add_custom_target(
    coverage-xml
    COMMAND
      gcovr --xml ${COVERAGE_DIR}/coverage.xml -r ${CMAKE_SOURCE_DIR}
      ${CMAKE_BINARY_DIR}
  )
  add_custom_target(coverage DEPENDS coverage-xml coverage-html)
endif(ENABLE_COVERAGE)

add_custom_target(
  clean-coverage
  COMMAND find . -name *.gcda -delete -or -name *.gcno -delete
  COMMAND rm -f ${COVERAGE_DIR}/*
)

add_executable(
  gvmd
  main.c
  $<TARGET_OBJECTS:all-gmp-obj>
  $<TARGET_OBJECTS:all-manage-obj>
  $<TARGET_OBJECTS:all-manage-sql-obj>
  $<TARGET_OBJECTS:all-misc-obj>
  $<TARGET_OBJECTS:all-sql-obj>
)

target_link_libraries(
  gvmd
  m
  ${GNUTLS_LDFLAGS}
  ${GPGME_LDFLAGS}
  ${CMAKE_THREAD_LIBS_INIT}
  ${LINKER_HARDENING_FLAGS}
  ${LINKER_DEBUG_FLAGS}
  ${PostgreSQL_LIBRARIES}
  ${LIBBSD_LDFLAGS}
  ${CJSON_LDFLAGS}
  ${GLIB_LDFLAGS}
  ${GTHREAD_LDFLAGS}
  ${LIBGVM_AGENT_CONTROLLER_LDFLAGS}
  ${LIBGVM_BASE_LDFLAGS}
  ${LIBGVM_UTIL_LDFLAGS}
  ${LIBGVM_OSP_LDFLAGS}
  ${LIBGVM_OPENVASD_LDFLAGS}
  ${LIBGVM_GMP_LDFLAGS}
  ${LIBGVM_HTTP_LDFLAGS}
  ${LIBGVM_HTTP_SCANNER_LDFLAGS}
  ${LIBICAL_LDFLAGS}
  ${LINKER_HARDENING_FLAGS}
  ${OPT_THEIA_TGT}
)
target_link_libraries(
  manage-sql-test
  cgreen
  m
  ${GNUTLS_LDFLAGS}
  ${GPGME_LDFLAGS}
  ${CMAKE_THREAD_LIBS_INIT}
  ${LINKER_HARDENING_FLAGS}
  ${LINKER_DEBUG_FLAGS}
  ${PostgreSQL_LIBRARIES}
  ${LIBBSD_LDFLAGS}
  ${CJSON_LDFLAGS}
  ${GLIB_LDFLAGS}
  ${GTHREAD_LDFLAGS}
  ${LIBGVM_AGENT_CONTROLLER_LDFLAGS}
  ${LIBGVM_BASE_LDFLAGS}
  ${LIBGVM_UTIL_LDFLAGS}
  ${LIBGVM_OSP_LDFLAGS}
  ${LIBGVM_OPENVASD_LDFLAGS}
  ${LIBGVM_GMP_LDFLAGS}
  ${LIBGVM_HTTP_LDFLAGS}
  ${LIBGVM_HTTP_SCANNER_LDFLAGS}
  ${LIBICAL_LDFLAGS}
  ${LINKER_HARDENING_FLAGS}
  ${OPT_THEIA_TGT}
)
target_link_libraries(
  gmp-tickets-test
  cgreen
  m
  ${GNUTLS_LDFLAGS}
  ${GPGME_LDFLAGS}
  ${CMAKE_THREAD_LIBS_INIT}
  ${LINKER_HARDENING_FLAGS}
  ${LINKER_DEBUG_FLAGS}
  ${PostgreSQL_LIBRARIES}
  ${LIBBSD_LDFLAGS}
  ${CJSON_LDFLAGS}
  ${GLIB_LDFLAGS}
  ${GTHREAD_LDFLAGS}
  ${LIBGVM_AGENT_CONTROLLER_LDFLAGS}
  ${LIBGVM_BASE_LDFLAGS}
  ${LIBGVM_UTIL_LDFLAGS}
  ${LIBGVM_OSP_LDFLAGS}
  ${LIBGVM_OPENVASD_LDFLAGS}
  ${LIBGVM_GMP_LDFLAGS}
  ${LIBGVM_HTTP_LDFLAGS}
  ${LIBGVM_HTTP_SCANNER_LDFLAGS}
  ${LIBICAL_LDFLAGS}
  ${LINKER_HARDENING_FLAGS}
  ${OPT_THEIA_TGT}
)
target_link_libraries(
  utils-test
  cgreen
  m
  ${GNUTLS_LDFLAGS}
  ${GPGME_LDFLAGS}
  ${CMAKE_THREAD_LIBS_INIT}
  ${LINKER_HARDENING_FLAGS}
  ${LINKER_DEBUG_FLAGS}
  ${PostgreSQL_LIBRARIES}
  ${LIBBSD_LDFLAGS}
  ${CJSON_LDFLAGS}
  ${GLIB_LDFLAGS}
  ${GTHREAD_LDFLAGS}
  ${LIBGVM_AGENT_CONTROLLER_LDFLAGS}
  ${LIBGVM_BASE_LDFLAGS}
  ${LIBGVM_UTIL_LDFLAGS}
  ${LIBGVM_OSP_LDFLAGS}
  ${LIBGVM_OPENVASD_LDFLAGS}
  ${LIBGVM_GMP_LDFLAGS}
  ${LIBGVM_HTTP_LDFLAGS}
  ${LIBGVM_HTTP_SCANNER_LDFLAGS}
  ${LIBICAL_LDFLAGS}
  ${LINKER_HARDENING_FLAGS}
  ${OPT_THEIA_TGT}
)
target_link_libraries(
  gvm-pg-server
  ${LIBBSD_LDFLAGS}
  ${GLIB_LDFLAGS}
  ${GTHREAD_LDFLAGS}
  ${LIBGVM_AGENT_CONTROLLER_LDFLAGS}
  ${LIBGVM_BASE_LDFLAGS}
  ${LIBGVM_OPENVASD_LDFLAGS}
  ${LIBGVM_UTIL_LDFLAGS}
  ${LIBICAL_LDFLAGS}
  ${LINKER_HARDENING_FLAGS}
)

set_target_properties(gvmd PROPERTIES LINKER_LANGUAGE C)

macro(add_unit_test _baseName)
  string(REPLACE "-" "_" _testSource "${_baseName}")
  # manage_filter_utils.c
  set(_source "${_testSource}.c")
  # manage_filter_utils_tests.c
  set(_testSource "${_testSource}_tests.c")
  # manage-filter-utils-test
  set(_testName "${_baseName}-test")

  list(APPEND TEST_DEPENDENCIES ${_testName})
  set(TEST_TARGET_EXTRA_SRC ${ALL_MANAGE_SRC})
  list(REMOVE_ITEM TEST_TARGET_EXTRA_SRC ${_source})
  foreach(_extraArg ${ARGN})
    list(REMOVE_ITEM TEST_TARGET_EXTRA_SRC ${_extraArg})
  endforeach(_extraArg ${ARGN})

  add_executable(
    ${_testName}
    EXCLUDE_FROM_ALL
    ${_testSource}
    $<TARGET_OBJECTS:all-gmp-obj>
    $<TARGET_OBJECTS:all-manage-sql-obj>
    $<TARGET_OBJECTS:all-misc-obj>
    $<TARGET_OBJECTS:all-sql-obj>
    ${TEST_TARGET_EXTRA_SRC}
  )
  add_test(${_testName} ${_testName})
  target_link_libraries(
    ${_testName}
    cgreen
    m
    ${GNUTLS_LDFLAGS}
    ${GPGME_LDFLAGS}
    ${CMAKE_THREAD_LIBS_INIT}
    ${LINKER_HARDENING_FLAGS}
    ${LINKER_DEBUG_FLAGS}
    ${PostgreSQL_LIBRARIES}
    ${LIBBSD_LDFLAGS}
    ${CJSON_LDFLAGS}
    ${GLIB_LDFLAGS}
    ${GTHREAD_LDFLAGS}
    ${LIBGVM_AGENT_CONTROLLER_LDFLAGS}
    ${LIBGVM_BASE_LDFLAGS}
    ${LIBGVM_UTIL_LDFLAGS}
    ${LIBGVM_OSP_LDFLAGS}
    ${LIBGVM_OPENVASD_LDFLAGS}
    ${LIBGVM_GMP_LDFLAGS}
    ${LIBGVM_HTTP_LDFLAGS}
    ${LIBGVM_HTTP_SCANNER_LDFLAGS}
    ${LIBICAL_LDFLAGS}
    ${LINKER_HARDENING_FLAGS}
    ${OPT_THEIA_TGT}
  )
  set_target_properties(${_testName} PROPERTIES LINKER_LANGUAGE C)
  if(NOT CMAKE_BUILD_TYPE MATCHES "Release")
    target_compile_options(${_testName} PUBLIC ${C_FLAGS_DEBUG_GVMD})
  endif(NOT CMAKE_BUILD_TYPE MATCHES "Release")
endmacro()

add_unit_test(manage)
if(ENABLE_AGENTS)
  add_unit_test(manage-agent-installers manage_sql_agent_installers.c)
endif()
add_unit_test(manage-filter-utils)
add_unit_test(manage-oci-image-targets)
add_unit_test(manage-utils)

add_custom_target(tests DEPENDS ${TEST_DEPENDENCIES})

set_target_properties(manage-sql-test PROPERTIES LINKER_LANGUAGE C)
set_target_properties(gmp-tickets-test PROPERTIES LINKER_LANGUAGE C)

if(DEBUG_FUNCTION_NAMES)
  add_definitions(-DDEBUG_FUNCTION_NAMES)
endif(DEBUG_FUNCTION_NAMES)

if(GVMD_VERSION)
  add_definitions(-DGVMD_VERSION="${GVMD_VERSION}")
endif(GVMD_VERSION)

if(NOT CMAKE_BUILD_TYPE MATCHES "Release")
  target_compile_options(gvmd PUBLIC ${C_FLAGS_DEBUG_GVMD})
  target_compile_options(manage-sql-test PUBLIC ${C_FLAGS_DEBUG_GVMD})
  target_compile_options(gmp-tickets-test PUBLIC ${C_FLAGS_DEBUG_GVMD})

  # If we got GIT_REVISION at configure time,
  # assume we can get it at build time as well
  if(GIT_REVISION)
    # Path to generated header
    set(GIT_REVISION_HEADER ${CMAKE_CURRENT_BINARY_DIR}/gitrevision.h)

    # Create gitrevision.h using CMake script
    add_custom_command(
      OUTPUT ${GIT_REVISION_HEADER}
      COMMAND
        ${CMAKE_COMMAND} -DSOURCE_DIR=${CMAKE_SOURCE_DIR} -P
        ${CMAKE_SOURCE_DIR}/cmake/GetGit.cmake
      DEPENDS ${CMAKE_SOURCE_DIR}/cmake/GetGit.cmake
      VERBATIM
    )

    # Custom target that triggers the command
    add_custom_target(revisiontag ALL DEPENDS ${GIT_REVISION_HEADER})

    # Ensure the object files depending on gitrevision.h are built *after* it's created
    add_dependencies(all-misc-obj revisiontag)

    # Include the output directory where gitrevision.h is generated
    include_directories(${CMAKE_CURRENT_BINARY_DIR})
    add_definitions(-DGIT_REV_AVAILABLE)
  endif(GIT_REVISION)
endif(NOT CMAKE_BUILD_TYPE MATCHES "Release")

if(GMP_VERSION)
  add_definitions(-DGMP_VERSION="${GMP_VERSION}")
endif(GMP_VERSION)

add_definitions(-DGVMD_DATABASE_VERSION=${GVMD_DATABASE_VERSION})
add_definitions(-DGVMD_SCAP_DATABASE_VERSION=${GVMD_SCAP_DATABASE_VERSION})
add_definitions(-DGVMD_CERT_DATABASE_VERSION=${GVMD_CERT_DATABASE_VERSION})
add_definitions(-DGVM_OS_NAME="${CMAKE_SYSTEM}")
add_definitions(-DPREFIX="${CMAKE_INSTALL_PREFIX}")

add_definitions(-DGVM_SCAP_RES_DIR="${GVM_SCAP_RES_DIR}")
add_definitions(-DGVM_SCAP_DATA_DIR="${GVM_SCAP_DATA_DIR}")
add_definitions(
  -DGVM_SCAP_DATA_CSV_DIR="${GVM_SCAP_DATA_DIR}/${GVMD_SCAP_DATABASE_VERSION}"
)

add_definitions(-DGVM_CERT_RES_DIR="${GVM_CERT_RES_DIR}")
add_definitions(-DGVM_CERT_DATA_DIR="${GVM_CERT_DATA_DIR}")

if(GVM_SCANNER_CERTIFICATE)
  add_definitions(-DSCANNERCERT="${GVM_SCANNER_CERTIFICATE}")
endif(GVM_SCANNER_CERTIFICATE)

if(GVM_SCANNER_KEY)
  add_definitions(-DSCANNERKEY="${GVM_SCANNER_KEY}")
endif(GVM_SCANNER_KEY)

if(GVM_CLIENT_CERTIFICATE)
  add_definitions(-DCLIENTCERT="${GVM_CLIENT_CERTIFICATE}")
endif(GVM_CLIENT_CERTIFICATE)

if(GVM_CLIENT_KEY)
  add_definitions(-DCLIENTKEY="${GVM_CLIENT_KEY}")
endif(GVM_CLIENT_KEY)

if(GVM_CA_CERTIFICATE)
  add_definitions(-DCACERT="${GVM_CA_CERTIFICATE}")
endif(GVM_CA_CERTIFICATE)

if(GVM_CA_DIR)
  add_definitions(-DCA_DIR="${GVM_CA_DIR}")
endif(GVM_CA_DIR)

if(GVM_LOG_DIR)
  add_definitions(-DGVM_LOG_DIR="${GVM_LOG_DIR}")
endif(GVM_LOG_DIR)

if(GVM_STATE_DIR)
  add_definitions(-DGVM_STATE_DIR="${GVM_STATE_DIR}")
endif(GVM_STATE_DIR)

if(GVMD_STATE_DIR)
  add_definitions(-DGVMD_STATE_DIR="${GVMD_STATE_DIR}")
endif(GVMD_STATE_DIR)

if(GVMD_RUN_DIR)
  add_definitions(-DGVMD_RUN_DIR="${GVMD_RUN_DIR}")
endif(GVMD_RUN_DIR)

if(GVMD_PID_PATH)
  add_definitions(-DGVMD_PID_PATH="${GVMD_PID_PATH}")
endif(GVMD_PID_PATH)

if(GVM_SYSCONF_DIR)
  add_definitions(-DGVM_SYSCONF_DIR="${GVM_SYSCONF_DIR}")
endif(GVM_SYSCONF_DIR)

if(GVM_DATA_DIR)
  add_definitions(-DGVM_DATA_DIR="${GVM_DATA_DIR}")
endif(GVM_DATA_DIR)

if(GVMD_DATA_DIR)
  add_definitions(-DGVMD_DATA_DIR="${GVMD_DATA_DIR}")
endif(GVMD_DATA_DIR)

if(GVM_LIB_INSTALL_DIR)
  add_definitions(-DGVM_LIB_INSTALL_DIR="${GVM_LIB_INSTALL_DIR}")
endif(GVM_LIB_INSTALL_DIR)

if(GVM_NVT_DIR)
  add_definitions(-DGVM_NVT_DIR="${GVM_NVT_DIR}")
endif(GVM_NVT_DIR)

add_definitions(-DGVMD_FEED_DIR="${GVMD_FEED_DIR}")

if(BINDIR)
  add_definitions(-DBINDIR="${BINDIR}")
endif(BINDIR)

## Install

install(
  TARGETS gvmd
  RUNTIME DESTINATION ${SBINDIR}
  LIBRARY DESTINATION ${LIBDIR}
  ARCHIVE DESTINATION ${LIBDIR}/static
)

install(TARGETS gvm-pg-server LIBRARY DESTINATION ${GVM_LIB_INSTALL_DIR})

## Static analysis

add_custom_target(
  cppcheck
  COMMENT "Running cppcheck..."
  COMMAND sh -c \"cppcheck ${CMAKE_CURRENT_SOURCE_DIR}\"
)

add_custom_target(check COMMENT "Checking code...")
add_dependencies(check cppcheck)

## Tag files

set(
  C_FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/gvmd.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/gmpd.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/gmp.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/gmp_agent_installers.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/gmp_base.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/gmp_delete.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/gmp_get.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/gmp_configs.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/gmp_oci_image_targets.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/gmp_port_lists.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/gmp_report_formats.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/gmp_tickets.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/gmp_tls_certificates.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_utils.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_acl.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_agent_installers.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_alerts.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_events.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_configs.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_get.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_oci_image_targets.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_port_lists.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_preferences.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_report_formats.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_authentication.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_sql.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_sql_agent_installers.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_sql_alerts.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_sql_assets.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_sql_events.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_sql_filters.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_sql_configs.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_sql_nvts.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_sql_oci_image_targets.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_sql_port_lists.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_sql_report_formats.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_sql_secinfo.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_sql_tickets.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_sql_tls_certificates.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_migrators.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/lsc_user.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/lsc_crypt.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/sql.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/utils.c"
)
add_custom_target(etags COMMENT "Building TAGS..." COMMAND etags ${C_FILES})
add_custom_target(ctags COMMENT "Building tags..." COMMAND ctags ${C_FILES})
add_custom_target(tags COMMENT "Building tags files...")
add_dependencies(tags etags ctags)

## End
