# OpenVAS
# $Id$
# Description: CMakefile for the OpenVAS Manager program
#
# Authors:
# Matthew Mundell <matt@mundell.ukfsn.org>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH
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

## Config

add_definitions (-Werror)

message (STATUS "Looking for sqlite3...")
find_library (SQLITE3 sqlite3)
message (STATUS "Looking for sqlite3... ${SQLITE3}")
if (NOT SQLITE3)
  message (FATAL_ERROR "The sqlite3 database library is required.")
endif (NOT SQLITE3)

exec_program (pkg-config
              ARGS --cflags glib-2.0
              OUTPUT_VARIABLE GLIB_CFLAGS)
exec_program (pkg-config
              ARGS --libs glib-2.0
              OUTPUT_VARIABLE GLIB_LDFLAGS)

if (OPENVAS_HEADER_INSTALL_DIR)
  set (HEADER_TEMP "-I${OPENVAS_HEADER_INSTALL_DIR}")
else (OPENVAS_HEADER_INSTALL_DIR)
  set (HEADER_TEMP "")
endif (OPENVAS_HEADER_INSTALL_DIR)

if (OPENVAS_LIB_INSTALL_DIR)
  set (LIB_TEMP "-L${OPENVAS_LIB_INSTALL_DIR}")
else (OPENVAS_LIB_INSTALL_DIR)
  set (LIB_TEMP "")
endif (OPENVAS_LIB_INSTALL_DIR)


## Gather flags from libopenvas

exec_program (libopenvas-config
              ARGS --cflags
              OUTPUT_VARIABLE OPENVAS_CFLAGS)
exec_program (libopenvas-config
              ARGS --libs
              OUTPUT_VARIABLE OPENVAS_LDFLAGS)

## Libraries

add_library (ovas-mngr-comm STATIC ovas-mngr-comm.c)
set_target_properties (ovas-mngr-comm PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS}")

add_library (manage STATIC manage.c manage_sql.c lsc_user.c)
set_target_properties (manage PROPERTIES COMPILE_FLAGS "${HEADER_TEMP} ${OPENVAS_CFLAGS} ${GLIB_CFLAGS}")
target_link_libraries (manage sqlite3 uuid glib-2.0 openvas_omp)

add_library (omp STATIC omp.c)
set_target_properties (omp PROPERTIES COMPILE_FLAGS "${HEADER_TEMP} ${OPENVAS_CFLAGS} ${GLIB_CFLAGS}")

add_library (otp STATIC otp.c)
set_target_properties (otp PROPERTIES COMPILE_FLAGS "${HEADER_TEMP} ${OPENVAS_CFLAGS} ${GLIB_CFLAGS}")

## Program

add_executable (openvasmd openvasmd.c oxpd.c ompd.c otpd.c)
target_link_libraries (openvasmd ovas-mngr-comm omp otp manage)

set_target_properties (openvasmd PROPERTIES LINKER_LANGUAGE C)

if (OPENVASMD_VERSION)
  add_definitions (-DOPENVASMD_VERSION=\\\"${OPENVASMD_VERSION}\\\")
endif (OPENVASMD_VERSION)

add_definitions (-DOPENVASMD_DATABASE_VERSION=${OPENVASMD_DATABASE_VERSION})
add_definitions (-DOPENVAS_OS_NAME=\\\"${CMAKE_SYSTEM}\\\")
add_definitions (-DPREFIX=\\\"${CMAKE_INSTALL_PREFIX}\\\")

if (OPENVAS_USERS_DIR)
  add_definitions (-DOPENVAS_USERS_DIR=\\\"${OPENVAS_USERS_DIR}\\\")
endif (OPENVAS_USERS_DIR)

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

set_target_properties (openvasmd PROPERTIES LINK_FLAGS
                       "${LIB_TEMP} -lsqlite3 -lgnutls -luuid ${GLIB_LDFLAGS} ${OPENVAS_LDFLAGS}")

set_target_properties (openvasmd PROPERTIES COMPILE_FLAGS
                       "${HEADER_TEMP} ${OPENVAS_CFLAGS} ${GLIB_CFLAGS}")

mark_as_advanced (LIB_TEMP)
mark_as_advanced (HEADER_TEMP)

configure_file (openvasmd_log_conf.cmake_in
                "${CMAKE_CURRENT_SOURCE_DIR}/openvasmd_log.conf")

## Install

install (TARGETS openvasmd
         RUNTIME DESTINATION ${SBINDIR}
         LIBRARY DESTINATION ${LIBDIR}
         ARCHIVE DESTINATION ${LIBDIR}/static)

install (FILES openvasmd_log.conf
         DESTINATION ${OPENVAS_SYSCONF_DIR})

install (FILES report_formats/CPE/generate
               report_formats/CPE/CPE.xsl
         DESTINATION ${OPENVAS_SYSCONF_DIR}/openvasmd/global_report_formats/a0704abb-2120-489f-959f-251c9f4ffebd/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_WRITE GROUP_READ)

install (FILES report_formats/HTML/generate
               report_formats/HTML/HTML.xsl
         DESTINATION ${OPENVAS_SYSCONF_DIR}/openvasmd/global_report_formats/b993b6f5-f9fb-4e6e-9c94-dd46c00e058d/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_WRITE GROUP_READ)

install (FILES report_formats/ITG/generate
               report_formats/ITG/ITG.xsl
         DESTINATION ${OPENVAS_SYSCONF_DIR}/openvasmd/global_report_formats/929884c6-c2c4-41e7-befb-2f6aa163b458/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_WRITE GROUP_READ)

install (FILES report_formats/LaTeX/generate
               report_formats/LaTeX/latex.xsl
         DESTINATION ${OPENVAS_SYSCONF_DIR}/openvasmd/global_report_formats/9f1ab17b-aaaa-411a-8c57-12df446f5588/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_WRITE GROUP_READ)

install (FILES report_formats/NBE/generate
               report_formats/NBE/NBE.xsl
         DESTINATION ${OPENVAS_SYSCONF_DIR}/openvasmd/global_report_formats/f5c2a364-47d2-4700-b21d-0a7693daddab/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_WRITE GROUP_READ)

install (FILES report_formats/PDF/generate
               report_formats/LaTeX/latex.xsl
         DESTINATION ${OPENVAS_SYSCONF_DIR}/openvasmd/global_report_formats/1a60a67e-97d0-4cbf-bc77-f71b08e7043d/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_WRITE GROUP_READ)

install (FILES report_formats/TXT/generate report_formats/TXT/TXT.xsl
         DESTINATION ${OPENVAS_SYSCONF_DIR}/openvasmd/global_report_formats/19f6f1b3-7128-4433-888c-ccc764fe6ed5/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_WRITE GROUP_READ)

install (FILES report_formats/XML/generate
         DESTINATION ${OPENVAS_SYSCONF_DIR}/openvasmd/global_report_formats/d5da9f67-8551-4e51-807b-b6a873d70e34/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_WRITE GROUP_READ)

## Tests

enable_testing ()

add_subdirectory (tests)

## Static analysis

# FIX test coverage

add_custom_target (splint COMMENT "Running splint..."
                   COMMAND sh -c \"splint -booltype gboolean -predboolint +unixlib +export-header `pkg-config --cflags glib-2.0` `libopenvas-config --cflags` *.c\")

add_custom_target (rats COMMENT "Running rats..."
                   COMMAND sh -c \"rats --warning 2 *.[ch]\")

add_custom_target (flawfinder COMMENT "Running flawfinder..."
                   COMMAND sh -c \"flawfinder *.[ch]\")

add_custom_target (check COMMENT "Checking code...")
add_dependencies (check splint rats flawfinder)

## Tag files

set (C_FILES "openvasmd.c" "oxpd.c" "otpd.c" "ompd.c" "omp.c" "otp.c"
             "manage.c" "manage_sql.c" "ovas-mngr-comm.c")
add_custom_target (etags COMMENT "Building TAGS..."
                   COMMAND etags ${C_FILES})
add_custom_target (ctags COMMENT "Building tags..."
                   COMMAND ctags ${C_FILES})
add_custom_target (tags COMMENT "Building tags files...")
add_dependencies (tags etags ctags)

## End
