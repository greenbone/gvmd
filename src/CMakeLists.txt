# Copyright (C) 2009-2020 Greenbone Networks GmbH
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

find_package (Threads)

## Dependency checks
##
## TODO Also check for headers where needed.
## Improve for workflow: First collect list of missing libs, then print the
## list and throw an error, otherwise long install-cmake-install-cmake cycles
## might occur.

pkg_check_modules (LIBGVM_BASE REQUIRED libgvm_base>=21.4.1)
pkg_check_modules (LIBGVM_UTIL REQUIRED libgvm_util>=21.4.1)
pkg_check_modules (LIBGVM_OSP REQUIRED libgvm_osp>=21.4.1)
pkg_check_modules (LIBGVM_GMP REQUIRED libgvm_gmp>=21.4.1)
pkg_check_modules (GNUTLS REQUIRED gnutls>=3.2.15)
pkg_check_modules (GLIB REQUIRED glib-2.0>=2.42)
pkg_check_modules (LIBICAL REQUIRED libical>=1.00)

message (STATUS "Looking for PostgreSQL...")
find_program (PG_CONFIG_EXECUTABLE pg_config DOC "pg_config")
execute_process (COMMAND ${PG_CONFIG_EXECUTABLE} --includedir-server
                 OUTPUT_VARIABLE PostgreSQL_SERVER_INCLUDE_DIRS
                 OUTPUT_STRIP_TRAILING_WHITESPACE)
set(PostgreSQL_ADDITIONAL_SEARCH_PATHS ${PostgreSQL_SERVER_INCLUDE_DIRS})
find_package (PostgreSQL REQUIRED)
if (NOT PostgreSQL_FOUND)
  message (SEND_ERROR "The PostgreSQL library is required.")
endif (NOT PostgreSQL_FOUND)
string (REGEX MATCH "^[ \t]*\([0-9]+\)\\.\([0-9]+\)\(.*\)" TEMP ${PostgreSQL_VERSION_STRING})
if (NOT CMAKE_MATCH_1)
  message (SEND_ERROR "Error matching PostgreSQL version.")
elseif ((CMAKE_MATCH_1 EQUAL 9 AND CMAKE_MATCH_2 LESS 6)
        OR (CMAKE_MATCH_1 LESS 9))
  message (SEND_ERROR "PostgreSQL version >= 9.6 is required")
  message (STATUS "PostgreSQL version ${CMAKE_MATCH_1}.${CMAKE_MATCH_2}${CMAKE_MATCH_3}")
endif (NOT CMAKE_MATCH_1)

message (STATUS "Looking for xml_split...")
find_program (XML_SPLIT_EXECUTABLE xml_split DOC "xml_split")
if (NOT XML_SPLIT_EXECUTABLE)
  message (WARNING "xml_split is recommended to reduce SCAP sync memory usage (Debian package xml-twig-tools).")
else (NOT XML_SPLIT_EXECUTABLE)
  message (STATUS "Looking for xml_split... ${XML_SPLIT_EXECUTABLE}")
endif (NOT XML_SPLIT_EXECUTABLE)

message (STATUS "Looking for xsltproc...")
find_program (XSLTPROC_EXECUTABLE xsltproc DOC "xsltproc")
if (NOT XSLTPROC_EXECUTABLE)
  message (SEND_ERROR "The xsltproc binary is required.")
else (NOT XSLTPROC_EXECUTABLE)
  message (STATUS "Looking for xsltproc... ${XSLTPROC_EXECUTABLE}")
endif (NOT XSLTPROC_EXECUTABLE)

message (STATUS "Looking for gpgme...")
find_library (GPGME gpgme)
if (NOT GPGME)
  message (SEND_ERROR "The gpgme library is required.")
else (NOT GPGME)
  message (STATUS "Looking for gpgme... ${GPGME}")
  execute_process (COMMAND gpgme-config --cflags
    OUTPUT_VARIABLE GPGME_CFLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  execute_process (COMMAND gpgme-config --libs
    OUTPUT_VARIABLE GPGME_LDFLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE)
endif (NOT GPGME)

include_directories (${LIBGVM_GMP_INCLUDE_DIRS}
                     ${LIBGVM_BASE_INCLUDE_DIRS} ${LIBGVM_UTIL_INCLUDE_DIRS}
                     ${LIBGVM_OSP_INCLUDE_DIRS}  ${GLIB_INCLUDE_DIRS})

add_library (gvm-pg-server SHARED
             manage_pg_server.c manage_utils.c)
set_target_properties (gvm-pg-server PROPERTIES SOVERSION "${CPACK_PACKAGE_VERSION_MAJOR}")
set_target_properties (gvm-pg-server PROPERTIES VERSION "${CPACK_PACKAGE_VERSION}")
include_directories (${PostgreSQL_INCLUDE_DIRS} ${PostgreSQL_SERVER_INCLUDE_DIRS})

## Program

add_executable (manage-utils-test
                EXCLUDE_FROM_ALL
                manage_utils_tests.c

                gvmd.c gmpd.c
                manage.c sql.c
                manage_acl.c manage_configs.c manage_get.c
                manage_port_lists.c manage_preferences.c
                manage_report_formats.c
                manage_authentication.c
                manage_sql.c manage_sql_nvts.c manage_sql_secinfo.c
                manage_sql_port_lists.c manage_sql_configs.c
                manage_sql_report_formats.c
                manage_sql_tickets.c manage_sql_tls_certificates.c
                manage_tls_certificates.c
                manage_migrators.c
                sql_pg.c manage_pg.c
                lsc_user.c lsc_crypt.c utils.c
                gmp.c gmp_base.c gmp_configs.c gmp_delete.c gmp_get.c
                gmp_port_lists.c gmp_report_formats.c gmp_tickets.c
                gmp_tls_certificates.c)

add_test (manage-utils-test manage-utils-test)

add_executable (manage-test
                EXCLUDE_FROM_ALL
                manage_tests.c

                gvmd.c gmpd.c
                manage_utils.c sql.c
                manage_acl.c manage_configs.c manage_get.c
                manage_port_lists.c manage_preferences.c
                manage_report_formats.c
                manage_authentication.c
                manage_sql.c manage_sql_nvts.c manage_sql_secinfo.c
                manage_sql_port_lists.c manage_sql_configs.c
                manage_sql_report_formats.c
                manage_sql_tickets.c manage_sql_tls_certificates.c
                manage_tls_certificates.c
                manage_migrators.c
                sql_pg.c manage_pg.c
                lsc_user.c lsc_crypt.c utils.c
                gmp.c gmp_base.c gmp_configs.c gmp_delete.c gmp_get.c
                gmp_port_lists.c gmp_report_formats.c gmp_tickets.c
                gmp_tls_certificates.c)

add_test (manage-test manage-test)

add_executable (manage-sql-test
                EXCLUDE_FROM_ALL
                manage_sql_tests.c

                gvmd.c gmpd.c
                manage_utils.c manage.c sql.c
                manage_acl.c manage_configs.c manage_get.c
                manage_port_lists.c manage_preferences.c
                manage_report_formats.c
                manage_authentication.c
                manage_sql_nvts.c manage_sql_secinfo.c
                manage_sql_port_lists.c manage_sql_configs.c
                manage_sql_report_formats.c
                manage_sql_tickets.c manage_sql_tls_certificates.c
                manage_tls_certificates.c
                manage_migrators.c
                sql_pg.c manage_pg.c
                lsc_user.c lsc_crypt.c utils.c
                gmp.c gmp_base.c gmp_configs.c gmp_delete.c gmp_get.c
                gmp_port_lists.c gmp_report_formats.c gmp_tickets.c
                gmp_tls_certificates.c)

add_test (manage-sql-test manage-sql-test)

add_executable (gmp-tickets-test
                EXCLUDE_FROM_ALL
                gmp_tickets_tests.c

                gvmd.c gmpd.c
                manage_utils.c manage.c sql.c
                manage_acl.c manage_configs.c manage_get.c
                manage_port_lists.c manage_preferences.c
                manage_report_formats.c
                manage_authentication.c
                manage_sql.c manage_sql_nvts.c manage_sql_secinfo.c
                manage_sql_port_lists.c manage_sql_configs.c
                manage_sql_report_formats.c
                manage_sql_tickets.c manage_sql_tls_certificates.c
                manage_tls_certificates.c
                manage_migrators.c
                sql_pg.c manage_pg.c
                lsc_user.c lsc_crypt.c utils.c
                gmp.c gmp_base.c gmp_configs.c gmp_delete.c gmp_get.c
                gmp_port_lists.c gmp_report_formats.c gmp_tls_certificates.c)

add_test (gmp-tickets-test gmp-tickets-test)

add_executable (utils-test
                EXCLUDE_FROM_ALL
                utils_tests.c

                gvmd.c gmpd.c
                manage_utils.c manage.c sql.c
                manage_acl.c manage_configs.c manage_get.c
                manage_port_lists.c manage_preferences.c
                manage_report_formats.c
                manage_authentication.c
                manage_sql.c manage_sql_nvts.c manage_sql_secinfo.c
                manage_sql_port_lists.c manage_sql_configs.c
                manage_sql_report_formats.c
                manage_sql_tickets.c manage_sql_tls_certificates.c
                manage_tls_certificates.c
                manage_migrators.c
                sql_pg.c manage_pg.c
                lsc_user.c lsc_crypt.c
                gmp.c gmp_base.c gmp_configs.c gmp_delete.c gmp_get.c
                gmp_port_lists.c gmp_report_formats.c gmp_tickets.c
                gmp_tls_certificates.c)

add_test (utils-test utils-test)

add_custom_target (tests
                   DEPENDS
                   gmp-tickets-test manage-test manage-sql-test manage-utils-test utils-test)

add_executable (gvmd
                main.c gvmd.c gmpd.c
                manage_utils.c manage.c sql.c
                manage_acl.c manage_configs.c manage_get.c
                manage_port_lists.c manage_preferences.c
                manage_report_formats.c
                manage_authentication.c
                manage_sql.c manage_sql_nvts.c manage_sql_secinfo.c
                manage_sql_port_lists.c manage_sql_configs.c
                manage_sql_report_formats.c
                manage_sql_tickets.c manage_sql_tls_certificates.c
                manage_tls_certificates.c
                manage_migrators.c
                sql_pg.c manage_pg.c
                lsc_user.c lsc_crypt.c utils.c
                gmp.c gmp_base.c gmp_configs.c gmp_delete.c gmp_get.c
                gmp_port_lists.c gmp_report_formats.c gmp_tickets.c
                gmp_tls_certificates.c)

target_link_libraries (gvmd m
                       ${GNUTLS_LDFLAGS} ${GPGME_LDFLAGS} ${CMAKE_THREAD_LIBS_INIT} ${LINKER_HARDENING_FLAGS} ${LINKER_DEBUG_FLAGS}
                       ${PostgreSQL_LIBRARIES} ${GLIB_LDFLAGS} ${GTHREAD_LDFLAGS}
                       ${LIBGVM_BASE_LDFLAGS} ${LIBGVM_UTIL_LDFLAGS} ${LIBGVM_OSP_LDFLAGS} ${LIBGVM_GMP_LDFLAGS}
                       ${LIBICAL_LDFLAGS} ${LINKER_HARDENING_FLAGS})
target_link_libraries (manage-test cgreen m
                       ${GNUTLS_LDFLAGS} ${GPGME_LDFLAGS} ${CMAKE_THREAD_LIBS_INIT} ${LINKER_HARDENING_FLAGS} ${LINKER_DEBUG_FLAGS}
                       ${PostgreSQL_LIBRARIES} ${GLIB_LDFLAGS} ${GTHREAD_LDFLAGS}
                       ${LIBGVM_BASE_LDFLAGS} ${LIBGVM_UTIL_LDFLAGS} ${LIBGVM_OSP_LDFLAGS} ${LIBGVM_GMP_LDFLAGS}
                       ${LIBICAL_LDFLAGS} ${LINKER_HARDENING_FLAGS})
target_link_libraries (manage-sql-test cgreen m
                       ${GNUTLS_LDFLAGS} ${GPGME_LDFLAGS} ${CMAKE_THREAD_LIBS_INIT} ${LINKER_HARDENING_FLAGS} ${LINKER_DEBUG_FLAGS}
                       ${PostgreSQL_LIBRARIES} ${GLIB_LDFLAGS} ${GTHREAD_LDFLAGS}
                       ${LIBGVM_BASE_LDFLAGS} ${LIBGVM_UTIL_LDFLAGS} ${LIBGVM_OSP_LDFLAGS} ${LIBGVM_GMP_LDFLAGS}
                       ${LIBICAL_LDFLAGS} ${LINKER_HARDENING_FLAGS})
target_link_libraries (manage-utils-test cgreen m
                       ${GNUTLS_LDFLAGS} ${GPGME_LDFLAGS} ${CMAKE_THREAD_LIBS_INIT} ${LINKER_HARDENING_FLAGS} ${LINKER_DEBUG_FLAGS}
                       ${PostgreSQL_LIBRARIES} ${GLIB_LDFLAGS} ${GTHREAD_LDFLAGS}
                       ${LIBGVM_BASE_LDFLAGS} ${LIBGVM_UTIL_LDFLAGS} ${LIBGVM_OSP_LDFLAGS} ${LIBGVM_GMP_LDFLAGS}
                       ${LIBICAL_LDFLAGS} ${LINKER_HARDENING_FLAGS})
target_link_libraries (gmp-tickets-test cgreen m
                       ${GNUTLS_LDFLAGS} ${GPGME_LDFLAGS} ${CMAKE_THREAD_LIBS_INIT} ${LINKER_HARDENING_FLAGS} ${LINKER_DEBUG_FLAGS}
                       ${PostgreSQL_LIBRARIES} ${GLIB_LDFLAGS} ${GTHREAD_LDFLAGS}
                       ${LIBGVM_BASE_LDFLAGS} ${LIBGVM_UTIL_LDFLAGS} ${LIBGVM_OSP_LDFLAGS} ${LIBGVM_GMP_LDFLAGS}
                       ${LIBICAL_LDFLAGS} ${LINKER_HARDENING_FLAGS})
target_link_libraries (utils-test cgreen m
                       ${GNUTLS_LDFLAGS} ${GPGME_LDFLAGS} ${CMAKE_THREAD_LIBS_INIT} ${LINKER_HARDENING_FLAGS} ${LINKER_DEBUG_FLAGS}
                       ${PostgreSQL_LIBRARIES} ${GLIB_LDFLAGS} ${GTHREAD_LDFLAGS}
                       ${LIBGVM_BASE_LDFLAGS} ${LIBGVM_UTIL_LDFLAGS} ${LIBGVM_OSP_LDFLAGS} ${LIBGVM_GMP_LDFLAGS}
                       ${LIBICAL_LDFLAGS} ${LINKER_HARDENING_FLAGS})
target_link_libraries (gvm-pg-server ${GLIB_LDFLAGS} ${GTHREAD_LDFLAGS} ${LIBGVM_BASE_LDFLAGS} ${LIBGVM_UTIL_LDFLAGS} ${LIBICAL_LDFLAGS} ${LINKER_HARDENING_FLAGS})

set_target_properties (gvmd PROPERTIES LINKER_LANGUAGE C)
set_target_properties (manage-test PROPERTIES LINKER_LANGUAGE C)
set_target_properties (manage-sql-test PROPERTIES LINKER_LANGUAGE C)
set_target_properties (manage-utils-test PROPERTIES LINKER_LANGUAGE C)
set_target_properties (gmp-tickets-test PROPERTIES LINKER_LANGUAGE C)

if (DEBUG_FUNCTION_NAMES)
  add_definitions (-DDEBUG_FUNCTION_NAMES)
endif (DEBUG_FUNCTION_NAMES)

if (GVMD_VERSION)
  add_definitions (-DGVMD_VERSION="${GVMD_VERSION}")
endif (GVMD_VERSION)

if (NOT CMAKE_BUILD_TYPE MATCHES "Release")
  target_compile_options (gvmd PUBLIC ${C_FLAGS_DEBUG_GVMD})
  target_compile_options (manage-test PUBLIC ${C_FLAGS_DEBUG_GVMD})
  target_compile_options (manage-sql-test PUBLIC ${C_FLAGS_DEBUG_GVMD})
  target_compile_options (manage-utils-test PUBLIC ${C_FLAGS_DEBUG_GVMD})
  target_compile_options (gmp-tickets-test PUBLIC ${C_FLAGS_DEBUG_GVMD})

  # If we got GIT_REVISION at configure time,
  # assume we can get it at build time as well
  if (GIT_REVISION)
    # a custom target that is always built
    add_custom_target (revisiontag ALL)

    # creates gitversion.h using cmake script
    add_custom_command (TARGET revisiontag COMMAND ${CMAKE_COMMAND}
                        -DSOURCE_DIR=${CMAKE_SOURCE_DIR}
                        -P ${CMAKE_SOURCE_DIR}/cmake/GetGit.cmake)

    # explicitly say that the executable depends on custom target
    add_dependencies (gvmd revisiontag)

    # include the output directory, where the gitversion.h file is generated
    include_directories (${CMAKE_CURRENT_BINARY_DIR})
    add_definitions (-DGIT_REV_AVAILABLE)
  endif (GIT_REVISION)
endif (NOT CMAKE_BUILD_TYPE MATCHES "Release")

if (GMP_VERSION)
  add_definitions (-DGMP_VERSION="${GMP_VERSION}")
endif (GMP_VERSION)
if (GMP_VERSION_FEED)
  add_definitions (-DGMP_VERSION_FEED="${GMP_VERSION_FEED}")
endif (GMP_VERSION_FEED)

add_definitions (-DGVMD_DATABASE_VERSION=${GVMD_DATABASE_VERSION})
add_definitions (-DGVMD_SCAP_DATABASE_VERSION=${GVMD_SCAP_DATABASE_VERSION})
add_definitions (-DGVMD_CERT_DATABASE_VERSION=${GVMD_CERT_DATABASE_VERSION})
add_definitions (-DGVM_OS_NAME="${CMAKE_SYSTEM}")
add_definitions (-DPREFIX="${CMAKE_INSTALL_PREFIX}")

add_definitions (-DGVM_SCAP_RES_DIR="${GVM_SCAP_RES_DIR}")
add_definitions (-DGVM_SCAP_DATA_DIR="${GVM_SCAP_DATA_DIR}")
add_definitions (-DGVM_SCAP_DATA_CSV_DIR="${GVM_SCAP_DATA_DIR}/${GVMD_SCAP_DATABASE_VERSION}")

add_definitions (-DGVM_CERT_RES_DIR="${GVM_CERT_RES_DIR}")
add_definitions (-DGVM_CERT_DATA_DIR="${GVM_CERT_DATA_DIR}")

if (GVM_SCANNER_CERTIFICATE)
        add_definitions (-DSCANNERCERT="${GVM_SCANNER_CERTIFICATE}")
endif (GVM_SCANNER_CERTIFICATE)

if (GVM_SCANNER_KEY)
        add_definitions (-DSCANNERKEY="${GVM_SCANNER_KEY}")
endif (GVM_SCANNER_KEY)

if (GVM_CLIENT_CERTIFICATE)
        add_definitions (-DCLIENTCERT="${GVM_CLIENT_CERTIFICATE}")
endif (GVM_CLIENT_CERTIFICATE)

if (GVM_CLIENT_KEY)
        add_definitions (-DCLIENTKEY="${GVM_CLIENT_KEY}")
endif (GVM_CLIENT_KEY)

if (GVM_CA_CERTIFICATE)
        add_definitions (-DCACERT="${GVM_CA_CERTIFICATE}")
endif (GVM_CA_CERTIFICATE)

if (GVM_CA_DIR)
        add_definitions (-DCA_DIR="${GVM_CA_DIR}")
endif (GVM_CA_DIR)

if (GVM_LOG_DIR)
        add_definitions (-DGVM_LOG_DIR="${GVM_LOG_DIR}")
endif (GVM_LOG_DIR)

if (GVM_STATE_DIR)
        add_definitions (-DGVM_STATE_DIR="${GVM_STATE_DIR}")
endif (GVM_STATE_DIR)

if (GVMD_STATE_DIR)
  add_definitions (-DGVMD_STATE_DIR="${GVMD_STATE_DIR}")
endif (GVMD_STATE_DIR)

if (GVMD_RUN_DIR)
        add_definitions (-DGVMD_RUN_DIR="${GVMD_RUN_DIR}")
endif (GVMD_RUN_DIR)

if (GVMD_PID_PATH)
        add_definitions (-DGVMD_PID_PATH="${GVMD_PID_PATH}")
endif (GVMD_PID_PATH)

if (GVM_SYSCONF_DIR)
        add_definitions (-DGVM_SYSCONF_DIR="${GVM_SYSCONF_DIR}")
endif (GVM_SYSCONF_DIR)

if (GVM_SYSCONF_DIR)
  add_definitions (-DGVM_SYSCONF_DIR="${GVM_SYSCONF_DIR}")
endif (GVM_SYSCONF_DIR)

if (GVM_DATA_DIR)
        add_definitions (-DGVM_DATA_DIR="${GVM_DATA_DIR}")
endif (GVM_DATA_DIR)

if (GVMD_DATA_DIR)
  add_definitions (-DGVMD_DATA_DIR="${GVMD_DATA_DIR}")
endif (GVMD_DATA_DIR)

if (GVM_LIB_INSTALL_DIR)
        add_definitions (-DGVM_LIB_INSTALL_DIR="${GVM_LIB_INSTALL_DIR}")
endif (GVM_LIB_INSTALL_DIR)

if (GVM_NVT_DIR)
        add_definitions (-DGVM_NVT_DIR="${GVM_NVT_DIR}")
endif (GVM_NVT_DIR)

add_definitions (-DGVMD_FEED_DIR="${GVMD_FEED_DIR}")

if (BINDIR)
  add_definitions (-DBINDIR="${BINDIR}")
endif (BINDIR)

## Install

install (TARGETS gvmd
         RUNTIME DESTINATION ${SBINDIR}
         LIBRARY DESTINATION ${LIBDIR}
         ARCHIVE DESTINATION ${LIBDIR}/static)

install (TARGETS gvm-pg-server
         LIBRARY DESTINATION ${GVM_LIB_INSTALL_DIR})

## Static analysis

add_custom_target (cppcheck COMMENT "Running cppcheck..."
                   COMMAND sh -c \"cppcheck ${CMAKE_CURRENT_SOURCE_DIR}\")

add_custom_target (check COMMENT "Checking code...")
add_dependencies (check cppcheck)

## Tag files

set (C_FILES "${CMAKE_CURRENT_SOURCE_DIR}/gvmd.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/gmpd.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/gmp.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/gmp_base.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/gmp_delete.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/gmp_get.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/gmp_configs.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/gmp_port_lists.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/gmp_report_formats.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/gmp_tickets.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/gmp_tls_certificates.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_utils.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_acl.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_configs.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_get.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_port_lists.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_preferences.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_report_formats.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_authentication.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_sql.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_sql_configs.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_sql_nvts.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_sql_port_lists.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_sql_report_formats.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_sql_secinfo.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_sql_tickets.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_sql_tls_certificates.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_migrators.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/lsc_user.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/lsc_crypt.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/sql.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/utils.c")
add_custom_target (etags COMMENT "Building TAGS..."
                   COMMAND etags ${C_FILES})
add_custom_target (ctags COMMENT "Building tags..."
                   COMMAND ctags ${C_FILES})
add_custom_target (tags COMMENT "Building tags files...")
add_dependencies (tags etags ctags)

## End
