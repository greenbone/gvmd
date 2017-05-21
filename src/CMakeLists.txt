# GVM
# $Id$
# Description: CMakefile for the Greenbone Vulnerability Manager program
#
# Authors:
# Matthew Mundell <matthew.mundell@greenbone.net>
# Timo Pollmeier <timo.pollmeier@greenbone.net>
#
# Copyright:
# Copyright (C) 2009-2014 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

## Libraries

add_library (gvm-comm STATIC gvm-comm.c)
include_directories (${LIBGVM_GMP_INCLUDE_DIRS}
                     ${LIBGVM_BASE_INCLUDE_DIRS} ${LIBGVM_UTIL_INCLUDE_DIRS}
                     ${LIBGVM_OSP_INCLUDE_DIRS}  ${GLIB_INCLUDE_DIRS})

find_package (Threads)

if (BACKEND STREQUAL SQLITE3)
  set (BACKEND_FILES sql_sqlite3.c manage_sqlite3.c)
else (BACKEND STREQUAL SQLITE3)
  set (BACKEND_FILES sql_pg.c manage_pg.c)

  add_library (manage-pg-server SHARED
               manage_pg_server.c manage_utils.c)
  set_target_properties (manage-pg-server PROPERTIES SOVERSION "${CPACK_PACKAGE_VERSION_MAJOR}")
  set_target_properties (manage-pg-server PROPERTIES VERSION "${CPACK_PACKAGE_VERSION}")
  include_directories (${PostgreSQL_INCLUDE_DIRS} ${PostgreSQL_SERVER_INCLUDE_DIRS})
endif (BACKEND STREQUAL SQLITE3)

add_library (manage STATIC
             manage_utils.c manage.c sql.c
             manage_ranges_all_tcp_nmap_5_51_top_100.c
             manage_ranges_all_tcp_nmap_5_51_top_1000.c
             manage_ranges_iana_tcp_2012.c manage_ranges_iana_tcp_udp_2012.c
             manage_ranges_nmap_5_51_top_2000_top_100.c
             manage_acl.c manage_config_discovery.c
             manage_config_host_discovery.c manage_config_system_discovery.c
             manage_sql.c manage_sql_secinfo.c manage_migrators.c scanner.c
             ${BACKEND_FILES}
             lsc_user.c lsc_crypt.c utils.c)

if (BACKEND STREQUAL SQLITE3)
  target_link_libraries (manage m ${SQLITE3_LDFLAGS} ${GLIB_LDFLAGS} ${GTHREAD_LDFLAGS} ${LIBGVM_BASE_LDFLAGS} ${LIBGVM_UTIL_LDFLAGS} ${LIBGVM_OSP_LDFLAGS} ${LIBGVM_GMP_LDFLAGS} ${LINKER_HARDENING_FLAGS})
else (BACKEND STREQUAL SQLITE3)
  target_link_libraries (manage m ${PostgreSQL_LIBRARIES} ${GLIB_LDFLAGS} ${GTHREAD_LDFLAGS} ${LIBGVM_BASE_LDFLAGS} ${LIBGVM_UTIL_LDFLAGS} ${LIBGVM_OSP_LDFLAGS} ${LIBGVM_GMP_LDFLAGS} ${LINKER_HARDENING_FLAGS})
  target_link_libraries (manage-pg-server m ${PostgreSQL_LIBRARIES} ${GLIB_LDFLAGS} ${GTHREAD_LDFLAGS} ${LIBGVM_BASE_LDFLAGS} ${LIBGVM_UTIL_LDFLAGS} ${LIBGVM_OSP_LDFLAGS} ${LIBGVM_GMP_LDFLAGS} ${LINKER_HARDENING_FLAGS})
endif (BACKEND STREQUAL SQLITE3)

add_library (gmp STATIC gmp.c)

add_library (otp STATIC otp.c)

## Program

if (BACKEND STREQUAL SQLITE3)
  set (BINARY_NAME "gvmd-sqlite")
else (BACKEND STREQUAL SQLITE3)
  set (BINARY_NAME "gvmd-pg")
endif (BACKEND STREQUAL SQLITE3)

add_executable (${BINARY_NAME} gvmd.c gmpd.c)
target_link_libraries (${BINARY_NAME} gvm-comm gmp otp manage ${GNUTLS_LDFLAGS} ${GPGME_LDFLAGS} ${CMAKE_THREAD_LIBS_INIT} ${LINKER_HARDENING_FLAGS})

set_target_properties (${BINARY_NAME} PROPERTIES LINKER_LANGUAGE C)

if (GVMD_VERSION)
  add_definitions (-DGVMD_VERSION=\\\"${GVMD_VERSION}\\\")
endif (GVMD_VERSION)

if (NOT CMAKE_BUILD_TYPE MATCHES "Release")
  # If we got SVN_REVISION at configure time,
  # assume we can get it at build time as well
  if (SVN_REVISION)
    # a custom target that is always built
    add_custom_target (revisiontag ALL)

    # creates svnversion.h using cmake script
    add_custom_command (TARGET revisiontag COMMAND ${CMAKE_COMMAND}
                        -DSOURCE_DIR=${CMAKE_SOURCE_DIR}
                        -P ${CMAKE_SOURCE_DIR}/getsvn.cmake)

    # explicitly say that the executable depends on custom target
    add_dependencies (${BINARY_NAME} revisiontag)

    # include the output directory, where the svnversion.h file is generated
    include_directories (${CMAKE_CURRENT_BINARY_DIR})
    add_definitions (-DSVN_REV_AVAILABLE)
  endif (SVN_REVISION)
endif (NOT CMAKE_BUILD_TYPE MATCHES "Release")

add_custom_command (TARGET ${BINARY_NAME} POST_BUILD
                    COMMAND ln -sf ${BINARY_NAME} gvmd)

if (GMP_VERSION)
  add_definitions (-DGMP_VERSION=\\\"${GMP_VERSION}\\\")
endif (GMP_VERSION)

add_definitions (-DGVMD_DATABASE_VERSION=${GVMD_DATABASE_VERSION})
add_definitions (-DGVMD_SCAP_DATABASE_VERSION=${GVMD_SCAP_DATABASE_VERSION})
add_definitions (-DGVMD_CERT_DATABASE_VERSION=${GVMD_CERT_DATABASE_VERSION})
add_definitions (-DGVM_OS_NAME=\\\"${CMAKE_SYSTEM}\\\")
add_definitions (-DPREFIX=\\\"${CMAKE_INSTALL_PREFIX}\\\")

add_definitions (-DGVM_SCAP_RES_DIR=\\\"${GVM_SCAP_RES_DIR}\\\")
add_definitions (-DGVM_SCAP_DATA_DIR=\\\"${GVM_SCAP_DATA_DIR}\\\")

add_definitions (-DGVM_CERT_RES_DIR=\\\"${GVM_CERT_RES_DIR}\\\")
add_definitions (-DGVM_CERT_DATA_DIR=\\\"${GVM_CERT_DATA_DIR}\\\")

if (GVM_SCANNER_CERTIFICATE)
        add_definitions (-DSCANNERCERT=\\\"${GVM_SCANNER_CERTIFICATE}\\\")
endif (GVM_SCANNER_CERTIFICATE)

if (GVM_SCANNER_KEY)
        add_definitions (-DSCANNERKEY=\\\"${GVM_SCANNER_KEY}\\\")
endif (GVM_SCANNER_KEY)

if (GVM_CLIENT_CERTIFICATE)
        add_definitions (-DCLIENTCERT=\\\"${GVM_CLIENT_CERTIFICATE}\\\")
endif (GVM_CLIENT_CERTIFICATE)

if (GVM_CLIENT_KEY)
        add_definitions (-DCLIENTKEY=\\\"${GVM_CLIENT_KEY}\\\")
endif (GVM_CLIENT_KEY)

if (GVM_CA_CERTIFICATE)
        add_definitions (-DCACERT=\\\"${GVM_CA_CERTIFICATE}\\\")
endif (GVM_CA_CERTIFICATE)

if (GVM_CA_DIR)
        add_definitions (-DCA_DIR=\\\"${GVM_CA_DIR}\\\")
endif (GVM_CA_DIR)

if (GVM_LOG_DIR)
        add_definitions (-DGVM_LOG_DIR=\\\"${GVM_LOG_DIR}\\\")
endif (GVM_LOG_DIR)

if (GVM_STATE_DIR)
        add_definitions (-DGVM_STATE_DIR=\\\"${GVM_STATE_DIR}\\\")
endif (GVM_STATE_DIR)

if (GVMD_STATE_DIR)
  add_definitions (-DGVMD_STATE_DIR=\\\"${GVMD_STATE_DIR}\\\")
endif (GVMD_STATE_DIR)

if (GVM_RUN_DIR)
        add_definitions (-DGVM_RUN_DIR=\\\"${GVM_RUN_DIR}\\\")
endif (GVM_RUN_DIR)

if (GVM_SYSCONF_DIR)
        add_definitions (-DGVM_SYSCONF_DIR=\\\"${GVM_SYSCONF_DIR}\\\")
endif (GVM_SYSCONF_DIR)

if (GVM_SYSCONF_DIR)
  add_definitions (-DGVM_SYSCONF_DIR=\\\"${GVM_SYSCONF_DIR}\\\")
endif (GVM_SYSCONF_DIR)

if (GVM_DATA_DIR)
        add_definitions (-DGVM_DATA_DIR=\\\"${GVM_DATA_DIR}\\\")
endif (GVM_DATA_DIR)

if (GVM_LIB_INSTALL_DIR)
        add_definitions (-DGVM_LIB_INSTALL_DIR=\\\"${GVM_LIB_INSTALL_DIR}\\\")
endif (GVM_LIB_INSTALL_DIR)

if (GVM_NVT_DIR)
        add_definitions (-DGVM_NVT_DIR=\\\"${GVM_NVT_DIR}\\\")
endif (GVM_NVT_DIR)

if (SBINDIR)
  add_definitions (-DSBINDIR=\\\"${SBINDIR}\\\")
endif (SBINDIR)

if (DEFINED GVM_SQLITE_SLEEP_MAX)
        add_definitions (-DGVM_SQLITE_SLEEP_MAX=${GVM_SQLITE_SLEEP_MAX})
endif (DEFINED GVM_SQLITE_SLEEP_MAX)

## Install

install (TARGETS ${BINARY_NAME}
         RUNTIME DESTINATION ${SBINDIR}
         LIBRARY DESTINATION ${LIBDIR}
         ARCHIVE DESTINATION ${LIBDIR}/static)

install (FILES ${CMAKE_CURRENT_BINARY_DIR}/gvmd
         DESTINATION ${SBINDIR})

if (BACKEND STREQUAL POSTGRESQL)
  install (TARGETS manage-pg-server
           LIBRARY DESTINATION "${GVM_LIB_INSTALL_DIR}/openvasmd/pg")
endif (BACKEND STREQUAL POSTGRESQL)

## Static analysis

add_custom_target (cppcheck COMMENT "Running cppcheck..."
                   COMMAND sh -c \"cppcheck ${CMAKE_CURRENT_SOURCE_DIR}\")

add_custom_target (check COMMENT "Checking code...")
add_dependencies (check cppcheck)

## Tag files

set (C_FILES "${CMAKE_CURRENT_SOURCE_DIR}/gvmd.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/gmpd.c" "${CMAKE_CURRENT_SOURCE_DIR}/gmp.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/otp.c" "${CMAKE_CURRENT_SOURCE_DIR}/manage.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_utils.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_acl.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/scanner.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_config_discovery.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_config_host_discovery.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_config_system_discovery.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_ranges_all_tcp_nmap_5_51_top_100.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_ranges_all_tcp_nmap_5_51_top_1000.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_ranges_iana_tcp_2012.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_ranges_iana_tcp_udp_2012.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_ranges_nmap_5_51_top_2000_top_100.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_sql.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_sql_secinfo.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_sqlite3.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_migrators.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/gvm-comm.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/lsc_user.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/lsc_crypt.c" "${CMAKE_CURRENT_SOURCE_DIR}/sql.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/sql_sqlite3.c" "${CMAKE_CURRENT_SOURCE_DIR}/utils.c")
add_custom_target (etags COMMENT "Building TAGS..."
                   COMMAND etags ${C_FILES})
add_custom_target (ctags COMMENT "Building tags..."
                   COMMAND ctags ${C_FILES})
add_custom_target (tags COMMENT "Building tags files...")
add_dependencies (tags etags ctags)

## End
