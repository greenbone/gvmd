# OpenVAS
# $Id$
# Description: CMakefile for the OpenVAS Manager program
#
# Authors:
# Matthew Mundell <matthew.mundell@greenbone.net>
# Timo Pollmeier <timo.pollmeier@greenbone.net>
#
# Copyright:
# Copyright (C) 2009-2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or, at your option, any later version as published by the Free
# Software Foundation
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

add_library (ovas-mngr-comm STATIC ovas-mngr-comm.c)
set_target_properties (ovas-mngr-comm PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS}")

add_library (manage STATIC
             manage.c sql.c manage_ranges_all_tcp_nmap_5_51_top_100.c
             manage_ranges_all_tcp_nmap_5_51_top_1000.c
             manage_ranges_iana_tcp_2012.c manage_ranges_iana_tcp_udp_2012.c
             manage_ranges_nmap_5_51_top_2000_top_100.c
             manage_acl.c manage_config_discovery.c
             manage_config_host_discovery.c manage_config_system_discovery.c
             manage_sql.c manage_migrators.c lsc_user.c lsc_crypt.c)
set_target_properties (manage PROPERTIES COMPILE_FLAGS "${OPENVAS_CFLAGS} ${GLIB_CFLAGS}")

target_link_libraries (manage m "${SQLITE3_LDFLAGS} ${GLIB_LDFLAGS} ${OPENVAS_LDFLAGS}")

add_library (omp STATIC omp.c)
set_target_properties (omp PROPERTIES COMPILE_FLAGS "${OPENVAS_CFLAGS} ${GLIB_CFLAGS}")

add_library (otp STATIC otp.c)
set_target_properties (otp PROPERTIES COMPILE_FLAGS "${OPENVAS_CFLAGS} ${GLIB_CFLAGS}")

## Program

add_executable (openvasmd openvasmd.c ompd.c)
target_link_libraries (openvasmd ovas-mngr-comm omp otp manage "${GNUTLS_LDFLAGS}")

set_target_properties (openvasmd PROPERTIES LINKER_LANGUAGE C)

if (OPENVASMD_VERSION)
  add_definitions (-DOPENVASMD_VERSION=\\\"${OPENVASMD_VERSION}\\\")
endif (OPENVASMD_VERSION)

add_definitions (-DOPENVASMD_DATABASE_VERSION=${OPENVASMD_DATABASE_VERSION})
add_definitions (-DOPENVASMD_SCAP_DATABASE_VERSION=${OPENVASMD_SCAP_DATABASE_VERSION})
add_definitions (-DOPENVASMD_CERT_DATABASE_VERSION=${OPENVASMD_CERT_DATABASE_VERSION})
add_definitions (-DOPENVAS_OS_NAME=\\\"${CMAKE_SYSTEM}\\\")
add_definitions (-DPREFIX=\\\"${CMAKE_INSTALL_PREFIX}\\\")

add_definitions (-DSCAP_RES_DIR=\\\"${OPENVAS_SCAP_RES_DIR}\\\")
add_definitions (-DSCAP_DATA_DIR=\\\"${OPENVAS_SCAP_DATA_DIR}\\\")

add_definitions (-DCERT_RES_DIR=\\\"${OPENVAS_CERT_RES_DIR}\\\")
add_definitions (-DCERT_DATA_DIR=\\\"${OPENVAS_CERT_DATA_DIR}\\\")

if (OPENVAS_SCANNER_CERTIFICATE)
  add_definitions (-DSCANNERCERT=\\\"${OPENVAS_SCANNER_CERTIFICATE}\\\")
endif (OPENVAS_SCANNER_CERTIFICATE)

if (OPENVAS_SCANNER_KEY)
  add_definitions (-DSCANNERKEY=\\\"${OPENVAS_SCANNER_KEY}\\\")
endif (OPENVAS_SCANNER_KEY)

if (OPENVAS_CLIENT_CERTIFICATE)
  add_definitions (-DCLIENTCERT=\\\"${OPENVAS_CLIENT_CERTIFICATE}\\\")
endif (OPENVAS_CLIENT_CERTIFICATE)

if (OPENVAS_CLIENT_KEY)
  add_definitions (-DCLIENTKEY=\\\"${OPENVAS_CLIENT_KEY}\\\")
endif (OPENVAS_CLIENT_KEY)

if (OPENVAS_CA_CERTIFICATE)
  add_definitions (-DCACERT=\\\"${OPENVAS_CA_CERTIFICATE}\\\")
endif (OPENVAS_CA_CERTIFICATE)

if (OPENVAS_CA_DIR)
  add_definitions (-DCA_DIR=\\\"${OPENVAS_CA_DIR}\\\")
endif (OPENVAS_CA_DIR)

if (OPENVAS_LOG_DIR)
  add_definitions (-DOPENVAS_LOG_DIR=\\\"${OPENVAS_LOG_DIR}\\\")
endif (OPENVAS_LOG_DIR)

if (OPENVAS_STATE_DIR)
  add_definitions (-DOPENVAS_STATE_DIR=\\\"${OPENVAS_STATE_DIR}\\\")
endif (OPENVAS_STATE_DIR)

if (OPENVAS_PID_DIR)
  add_definitions (-DOPENVAS_PID_DIR=\\\"${OPENVAS_PID_DIR}\\\")
endif (OPENVAS_PID_DIR)

if (OPENVAS_SYSCONF_DIR)
  add_definitions (-DOPENVAS_SYSCONF_DIR=\\\"${OPENVAS_SYSCONF_DIR}\\\")
endif (OPENVAS_SYSCONF_DIR)

if (OPENVAS_DATA_DIR)
  add_definitions (-DOPENVAS_DATA_DIR=\\\"${OPENVAS_DATA_DIR}\\\")
endif (OPENVAS_DATA_DIR)

if (OPENVAS_LIB_INSTALL_DIR)
  add_definitions (-DOPENVAS_LIB_INSTALL_DIR=\\\"${OPENVAS_LIB_INSTALL_DIR}\\\")
endif (OPENVAS_LIB_INSTALL_DIR)

if (OPENVAS_NVT_DIR)
  add_definitions (-DOPENVAS_NVT_DIR=\\\"${OPENVAS_NVT_DIR}\\\")
endif (OPENVAS_NVT_DIR)

if (SBINDIR)
  add_definitions (-DSBINDIR=\\\"${SBINDIR}\\\")
endif (SBINDIR)

set_target_properties (openvasmd PROPERTIES COMPILE_FLAGS
                       "${SQLITE3_CFLAGS} ${GNUTLS_CFLAGS} ${OPENVAS_CFLAGS} ${GLIB_CFLAGS}")

## Install

install (TARGETS openvasmd
         RUNTIME DESTINATION ${SBINDIR}
         LIBRARY DESTINATION ${LIBDIR}
         ARCHIVE DESTINATION ${LIBDIR}/static)

## Static analysis

add_custom_target (splint COMMENT "Running splint..."
                   COMMAND sh -c \"splint -booltype gboolean -predboolint +unixlib +export-header `pkg-config --cflags glib-2.0` `pkg-config --cflags libopenvas` ${CMAKE_CURRENT_SOURCE_DIR}/*.c\")

add_custom_target (rats COMMENT "Running rats..."
                   COMMAND sh -c \"rats --warning 2 ${CMAKE_CURRENT_SOURCE_DIR}/*.[ch]\")

add_custom_target (flawfinder COMMENT "Running flawfinder..."
                   COMMAND sh -c \"flawfinder ${CMAKE_CURRENT_SOURCE_DIR}/*.[ch]\")

add_custom_target (check COMMENT "Checking code...")
add_dependencies (check splint rats flawfinder)

## Tag files

set (C_FILES "${CMAKE_CURRENT_SOURCE_DIR}/openvasmd.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/ompd.c" "${CMAKE_CURRENT_SOURCE_DIR}/omp.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/otp.c" "${CMAKE_CURRENT_SOURCE_DIR}/manage.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_acl.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_config_discovery.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_config_host_discovery.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_config_system_discovery.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_ranges_all_tcp_nmap_5_51_top_100.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_ranges_all_tcp_nmap_5_51_top_1000.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_ranges_iana_tcp_2012.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_ranges_iana_tcp_udp_2012.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_ranges_nmap_5_51_top_2000_top_100.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_sql.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/manage_migrators.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/ovas-mngr-comm.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/lsc_user.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/lsc_crypt.c" "${CMAKE_CURRENT_SOURCE_DIR}/sql.c")
add_custom_target (etags COMMENT "Building TAGS..."
                   COMMAND etags ${C_FILES})
add_custom_target (ctags COMMENT "Building tags..."
                   COMMAND ctags ${C_FILES})
add_custom_target (tags COMMENT "Building tags files...")
add_dependencies (tags etags ctags)

## End
