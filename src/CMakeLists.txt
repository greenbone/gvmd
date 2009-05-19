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

#set (TASKS_CFLAG "-DTASKS_FS")
#set (TASKS_LDFLAG "")
set (TASKS_CFLAG "-DTASKS_SQL")
set (TASKS_LDFLAG "-lsqlite3")

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

if (OPENVAS_USERS_DIR)
  add_definitions (-DOPENVAS_USERS_DIR=\\\"${OPENVAS_USERS_DIR}\\\")
endif (OPENVAS_USERS_DIR)

## Libraries

# file and string are just in libraries to aid testing.

add_library (file file.c)
set_target_properties (file PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS}")

add_library (string string.c)
set_target_properties (string PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS}")

add_library (ovas-mngr-comm ovas-mngr-comm.c)
set_target_properties (ovas-mngr-comm PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS}")

add_library (manage manage.c)
set_target_properties (manage PROPERTIES COMPILE_FLAGS "${HEADER_TEMP} ${TASKS_CFLAG} ${GLIB_CFLAGS}")

add_library (omp omp.c)
set_target_properties (omp PROPERTIES COMPILE_FLAGS "${TASKS_CFLAG} ${GLIB_CFLAGS}")

add_library (otp otp.c)
set_target_properties (otp PROPERTIES COMPILE_FLAGS "${TASKS_CFLAG} ${GLIB_CFLAGS}")

## Program

include_directories (${STRING_SOURCE_DIRECTORY}/string)
include_directories (${FILE_SOURCE_DIRECTORY}/file)

link_directories (${STRING_BINARY_DIRECTORY}/string)
link_directories (${FILE_BINARY_DIRECTORY}/file)

add_executable (openvasmd openvasmd.c ompd.c otpd.c)
target_link_libraries (openvasmd ovas-mngr-comm omp otp manage string file)

exec_program (libopenvas-config
              ARGS --cflags
			  OUTPUT_VARIABLE OPENVAS_CFLAGS)
exec_program (libopenvas-config
              ARGS --libs
			  OUTPUT_VARIABLE OPENVAS_LDFLAGS)

set_target_properties (openvasmd PROPERTIES LINKER_LANGUAGE C)

if (OPENVASMD_VERSION)
  add_definitions (-DOPENVASMD_VERSION=\\\"${OPENVASMD_VERSION}\\\")
endif (OPENVASMD_VERSION)

add_definitions (-DOPENVAS_OS_NAME=\\\"${CMAKE_SYSTEM}\\\")
add_definitions (-DPREFIX=\\\"${CMAKE_INSTALL_PREFIX}\\\")

if (OPENVAS_SERVER_CERTIFICATE)
  add_definitions (-DSERVERCERT=\\\"${OPENVAS_SERVER_CERTIFICATE}\\\")
endif (OPENVAS_SERVER_CERTIFICATE)

if (OPENVAS_SERVER_KEY)
  add_definitions (-DSERVERKEY=\\\"${OPENVAS_SERVER_KEY}\\\")
endif (OPENVAS_SERVER_KEY)

if (OPENVAS_CA_CERTIFICATE)
  add_definitions (-DCACERT=\\\"${OPENVAS_CA_CERTIFICATE}\\\")
endif (OPENVAS_CA_CERTIFICATE)

if (OPENVAS_LOG_DIR)
  add_definitions (-DOPENVAS_LOG_DIR=\\\"${OPENVAS_LOG_DIR}\\\")
endif (OPENVAS_LOG_DIR)

set_target_properties (openvasmd PROPERTIES LINK_FLAGS
                       "${LIB_TEMP} -lpcap -unessus_get_socket_from_connection -lopenvas -lgnutls -lossp-uuid ${GLIB_LDFLAGS} ${TASKS_LDFLAG}")

set_target_properties (openvasmd PROPERTIES COMPILE_FLAGS
                       "${TASKS_CFLAG} ${HEADER_TEMP} ${OPENVAS_CFLAGS} ${GLIB_CFLAGS}")

MARK_AS_ADVANCED (LIB_TEMP)
MARK_AS_ADVANCED (HEADER_TEMP)

## Install

install (TARGETS openvasmd
         RUNTIME DESTINATION ${BINDIR}
         LIBRARY DESTINATION ${LIBDIR}
         ARCHIVE DESTINATION ${LIBDIR}/static)

## Tests

ENABLE_TESTING ()

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
ADD_DEPENDENCIES (check splint rats flawfinder)

## Tag files

set (C_FILES "openvasmd.c" "otpd.c" "ompd.c" "omp.c" "otp.c" "file.c"
             "manage.c" "ovas-mngr-comm.c" "string.c" "tasks_fs.h"
			 "tasks_sql.h")
add_custom_target (etags COMMENT "Building TAGS..."
                   COMMAND etags ${C_FILES})
add_custom_target (ctags COMMENT "Building tags..."
                   COMMAND ctags ${C_FILES})
add_custom_target (tags COMMENT "Building tags files...")
ADD_DEPENDENCIES (tags etags ctags)

## End
