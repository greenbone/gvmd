# OpenVAS
# $Id$
# Description: Top-level cmake control for the Manager
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

message ("-- Configuring the Manager...")

project (openvas-manager C)

cmake_minimum_required (VERSION 2.6)

if (POLICY CMP0005)
   cmake_policy (SET CMP0005 OLD)
endif (POLICY CMP0005)

SET (CMAKE_BUILD_TYPE debug)

## CPack configuration

SET(CPACK_CMAKE_GENERATOR "Unix Makefiles")
SET(CPACK_GENERATOR "TGZ")
SET(CPACK_INSTALL_CMAKE_PROJECTS ".;openvas-manager;ALL;/")
SET(CPACK_MODULE_PATH "")
SET(CPACK_RESOURCE_FILE_LICENSE "COPYING")
SET(CPACK_RESOURCE_FILE_README "README")
SET(CPACK_RESOURCE_FILE_WELCOME "README")
SET(CPACK_SOURCE_GENERATOR "TGZ")
SET(CPACK_SOURCE_TOPLEVEL_TAG "")
SET(CPACK_SYSTEM_NAME "")
SET(CPACK_TOPLEVEL_TAG "")
SET(CPACK_PACKAGE_VERSION_MAJOR "0")
SET(CPACK_PACKAGE_VERSION_MINOR "9")
SET(CPACK_PACKAGE_VERSION_PATCH "5.SVN")
SET(CPACK_PACKAGE_VERSION "${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}")
SET(CPACK_PACKAGE_FILE_NAME "${PROJECT_NAME}-${CPACK_PACKAGE_VERSION}")
SET(CPACK_SOURCE_PACKAGE_FILE_NAME "${PROJECT_NAME}-${CPACK_PACKAGE_VERSION}")
SET(CPACK_PACKAGE_VENDOR "The OpenVAS Project")
SET(CPACK_SOURCE_IGNORE_FILES
"/.svn/"
"/_CPack_Packages/"
"/CMakeFiles/"
"cmake$"
"swp$"
"Cache.txt$"
".tar.gz"
"install_manifest.txt"
"Makefile"
"/doc/generated/"
)

INCLUDE(CPack)

## Variables

set (CMAKE_BUILD                Debug)
#set (CMAKE_VERBOSE_MAKEFILE     ON)

if (NOT SYSCONFDIR)
  set (SYSCONFDIR "${CMAKE_INSTALL_PREFIX}/etc")
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
  set (LOCALSTATEDIR "${CMAKE_INSTALL_PREFIX}/var")
endif (NOT LOCALSTATEDIR)

if (NOT DATADIR)
  set (DATADIR "${CMAKE_INSTALL_PREFIX}/share")
endif (NOT DATADIR)

if (NOT INCLUDEDIR)
  set (INCLUDEDIR "${CMAKE_INSTALL_PREFIX}/include")
endif (NOT INCLUDEDIR)

#if (NOT SYSCONFDIR)
#  set (SYSCONFDIR "${CMAKE_INSTALL_PREFIX}/etc")
#endif (NOT SYSCONFDIR)

set (OPENVAS_DATA_DIR    "${DATADIR}/openvas")
set (OPENVAS_STATE_DIR   "${LOCALSTATEDIR}/lib/openvas")
set (OPENVAS_LOG_DIR     "${LOCALSTATEDIR}/log/openvas")
set (OPENVAS_PID_DIR     "${LOCALSTATEDIR}/run")
set (OPENVAS_SYSCONF_DIR "${SYSCONFDIR}/openvas")

set (OPENVAS_LIB_INSTALL_DIR     "${LIBDIR}")
set (OPENVAS_HEADER_INSTALL_DIR  "${INCLUDEDIR}")
set (OPENVAS_SCANNER_CERTIFICATE "${OPENVAS_STATE_DIR}/CA/servercert.pem")
set (OPENVAS_SCANNER_KEY         "${OPENVAS_STATE_DIR}/private/CA/serverkey.pem")
set (OPENVAS_CA_CERTIFICATE      "${OPENVAS_STATE_DIR}/CA/cacert.pem")

message ("-- Install prefix: ${CMAKE_INSTALL_PREFIX}")


## Checks for libraries openvas-administrator depends on
## TODO Also check for headers where needed. Maybe implement some cmake find
##      modules. Replace the current PATH value (/usr/lib with something more
##      dynamic. Huge potential for improvements here.

## START DEPENDENCIES
# GNUTLS
FIND_LIBRARY(GNUTLS
             NAMES gnutls
             PATHS /usr/lib)
IF(NOT GNUTLS)
message (FATAL_ERROR "gnutls library could not be found but is required.")
ENDIF(NOT GNUTLS)

# PCAP
FIND_LIBRARY(PCAP
             NAMES pcap
             PATHS /usr/lib)
IF(NOT PCAP)
message (FATAL_ERROR "pcap library could not be found but is required.")
ENDIF(NOT PCAP)

# GPGME
FIND_LIBRARY(GPGME
             NAMES gpgme
             PATHS /usr/lib)
IF(NOT GPGME)
message (FATAL_ERROR "gpgme library could not be found but is required.")
ENDIF(NOT GPGME)

# OPENVAS
FIND_LIBRARY(OPENVAS
             NAMES openvas
             PATHS /usr/lib)
IF(NOT OPENVAS)
message (FATAL_ERROR "openvas library could not be found but is required.")
ENDIF(NOT OPENVAS)

# GLIB-2
FIND_LIBRARY(GLIB2
             NAMES glib-2.0
             PATHS /usr/lib)
IF(NOT GLIB2)
message (FATAL_ERROR "glib-2.0 library could not be found but is required.")
ENDIF(NOT GLIB2)

# UUID
FIND_LIBRARY(UUID
             NAMES uuid
             PATHS /usr/lib)
IF(NOT UUID)
message (FATAL_ERROR "uuid library could not be found but is required.")
ENDIF(NOT UUID)
## END DEPENDENCIES

## Version

file (READ VERSION _OPENVASMD_VERSION)
STRING (REPLACE "
" "" OPENVASMD_VERSION ${_OPENVASMD_VERSION})

## Program

set (CMAKE_C_FLAGS_DEBUG        "${CMAKE_C_FLAGS_DEBUG} -Wall")
set (CMAKE_C_FLAGS              "${CMAKE_C_FLAGS} -Wall")

add_subdirectory (src)

## Documentation

add_subdirectory (doc)

## Tests

ENABLE_TESTING ()

## End
