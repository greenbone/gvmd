# OpenVAS
# $Id$
# Description: Top-level cmake control for the Manager
#
# Authors:
# Matthew Mundell <matt@mundell.ukfsn.org>
#
# Copyright:
# Copyright (C) 2008 Intevation GmbH
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

project (OPENVASMD)

cmake_minimum_required (VERSION 2.4)

## Variables

set (OPENVAS_LIB_INSTALL_DIR    "/home/mattm/lib/")
set (OPENVAS_HEADER_INSTALL_DIR "/home/mattm/include/")
set (OPENVAS_SERVER_CERTIFICATE "/var/lib/openvas/CA/servercert.pem")
set (OPENVAS_SERVER_KEY         "/var/lib/openvas/private/CA/serverkey.pem")
set (OPENVAS_CA_CERTIFICATE     "/var/lib/openvas/CA/cacert.pem")

set (CMAKE_BUILD                Debug)
set (CMAKE_VERBOSE_MAKEFILE     ON)
#set (CMAKE_INSTALL_PREFIX      "/home/mattm/")

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

## End
