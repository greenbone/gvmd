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

project (openvas-manager)

cmake_minimum_required (VERSION 2.4)

## CPack configuration

SET(CPACK_CMAKE_GENERATOR "Unix Makefiles")
SET(CPACK_GENERATOR "TGZ")
SET(CPACK_INSTALL_CMAKE_PROJECTS ".;openvas-manager;ALL;/")
SET(CPACK_MODULE_PATH "")
SET(CPACK_RESOURCE_FILE_LICENSE "COPYING")
SET(CPACK_RESOURCE_FILE_README "README")
SET(CPACK_RESOURCE_FILE_WELCOME "README")
SET(CPACK_SOURCE_GENERATOR "TGZ")
SET(CPACK_SOURCE_TOPLEVEL_TAG "-source")
SET(CPACK_SYSTEM_NAME "")
SET(CPACK_TOPLEVEL_TAG "")
SET(CPACK_PACKAGE_VERSION_MAJOR "0")
SET(CPACK_PACKAGE_VERSION_MINOR "5")
SET(CPACK_PACKAGE_VERSION_PATCH "0.SVN")
SET(CPACK_PACKAGE_VERSION "${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}")
SET(CPACK_PACKAGE_FILE_NAME "${PROJECT_NAME}-${CPACK_PACKAGE_VERSION}")
SET(CPACK_SOURCE_PACKAGE_FILE_NAME "${PROJECT_NAME}-${CPACK_PACKAGE_VERSION}-source")
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
)

INCLUDE(CPack)

## Variables

set (OPENVAS_LIB_INSTALL_DIR    "${CMAKE_INSTALL_PREFIX}/lib/")
set (OPENVAS_HEADER_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/include/")
set (OPENVAS_SERVER_CERTIFICATE "${CMAKE_INSTALL_PREFIX}/var/lib/openvas/CA/servercert.pem")
set (OPENVAS_SERVER_KEY         "${CMAKE_INSTALL_PREFIX}/var/lib/openvas/private/CA/serverkey.pem")
set (OPENVAS_CA_CERTIFICATE     "${CMAKE_INSTALL_PREFIX}/var/lib/openvas/CA/cacert.pem")

set (CMAKE_BUILD                Debug)
set (CMAKE_VERBOSE_MAKEFILE     ON)

message ("-- Install prefix: ${CMAKE_INSTALL_PREFIX}")

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
