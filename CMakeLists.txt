# OpenVAS
# $Id$
# Description: Top-level cmake control for the Manager.
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

message ("-- Configuring the Manager...")

project (openvas-manager C)

cmake_minimum_required (VERSION 2.6)

if (POLICY CMP0005)
  cmake_policy (SET CMP0005 OLD)
endif (POLICY CMP0005)

include (FindPkgConfig)

if (NOT CMAKE_BUILD_TYPE)
  set (CMAKE_BUILD_TYPE Debug)
endif (NOT CMAKE_BUILD_TYPE)

## Retrieve svn revision (at configure time)
#  Not using Subversion_WC_INFO, as it would have to connect to the repo
find_program (SVN_EXECUTABLE svn DOC "subversion command line client")

macro (Subversion_GET_REVISION dir variable)
  execute_process (COMMAND ${SVN_EXECUTABLE} info ${CMAKE_SOURCE_DIR}/${dir}
    OUTPUT_VARIABLE ${variable}
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  string (REGEX REPLACE "^(.*\n)?Revision: ([^\n]+).*"
    "\\2" ${variable} "${${variable}}")
endmacro (Subversion_GET_REVISION)

if (NOT CMAKE_BUILD_TYPE MATCHES "Release")
  if (EXISTS ".svn/")
    if (SVN_EXECUTABLE)
      Subversion_GET_REVISION(. ProjectRevision)
      set (SVN_REVISION ".SVN.r${ProjectRevision}")
    else (SVN_EXECUTABLE)
      set (SVN_REVISION ".SVN")
    endif (SVN_EXECUTABLE)
  endif (EXISTS ".svn/")
endif (NOT CMAKE_BUILD_TYPE MATCHES "Release")

## CPack configuration

set (CPACK_CMAKE_GENERATOR "Unix Makefiles")
set (CPACK_GENERATOR "TGZ")
set (CPACK_INSTALL_CMAKE_PROJECTS ".;openvas-manager;ALL;/")
set (CPACK_MODULE_PATH "")
set (CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/COPYING")
set (CPACK_RESOURCE_FILE_README "${CMAKE_SOURCE_DIR}/README")
set (CPACK_RESOURCE_FILE_WELCOME "${CMAKE_SOURCE_DIR}/README")
set (CPACK_SOURCE_GENERATOR "TGZ")
set (CPACK_SOURCE_TOPLEVEL_TAG "")
set (CPACK_SYSTEM_NAME "")
set (CPACK_TOPLEVEL_TAG "")
set (CPACK_PACKAGE_VERSION_MAJOR "4")
set (CPACK_PACKAGE_VERSION_MINOR "0")

# Use this scheme for stable releases:
set (CPACK_PACKAGE_VERSION_PATCH "2${SVN_REVISION}")
set (CPACK_PACKAGE_VERSION "${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}")
# Use this scheme for +betaN and +rcN releases:
#set (CPACK_PACKAGE_VERSION_PATCH "+beta1${SVN_REVISION}")
#set (CPACK_PACKAGE_VERSION "${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}${CPACK_PACKAGE_VERSION_PATCH}")

set (CPACK_PACKAGE_FILE_NAME "${PROJECT_NAME}-${CPACK_PACKAGE_VERSION}")
set (CPACK_SOURCE_PACKAGE_FILE_NAME "${PROJECT_NAME}-${CPACK_PACKAGE_VERSION}")
set (CPACK_PACKAGE_VENDOR "The OpenVAS Project")
set (CPACK_SOURCE_IGNORE_FILES
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
"log.conf$"
"Doxyfile$"
"Doxyfile_full$"
"VERSION$"
"tools/openvas-scapdata-sync$"
"tools/openvas-certdata-sync$"
)

include (CPack)

## Variables

set (OPENVASMD_DATABASE_VERSION 74)

if (SYSCONF_INSTALL_DIR)
  set (SYSCONFDIR "${SYSCONF_INSTALL_DIR}")
endif (SYSCONF_INSTALL_DIR)

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

set (OPENVAS_DATA_DIR     "${DATADIR}/openvas")
set (OPENVAS_STATE_DIR    "${LOCALSTATEDIR}/lib/openvas")
set (OPENVAS_LOG_DIR      "${LOCALSTATEDIR}/log/openvas")
set (OPENVAS_PID_DIR      "${LOCALSTATEDIR}/run")
set (OPENVAS_SYSCONF_DIR  "${SYSCONFDIR}/openvas")
set (OPENVAS_SCAP_RES_DIR "${OPENVAS_DATA_DIR}/scap")
set (OPENVAS_SCAP_DATA_DIR "${OPENVAS_STATE_DIR}/scap-data")
set (OPENVAS_CERT_RES_DIR "${OPENVAS_DATA_DIR}/cert")
set (OPENVAS_CERT_DATA_DIR "${OPENVAS_STATE_DIR}/cert-data")

set (OPENVAS_SCANNER_CERTIFICATE "${OPENVAS_STATE_DIR}/CA/servercert.pem")
set (OPENVAS_SCANNER_KEY         "${OPENVAS_STATE_DIR}/private/CA/serverkey.pem")
set (OPENVAS_CLIENT_CERTIFICATE  "${OPENVAS_STATE_DIR}/CA/clientcert.pem")
set (OPENVAS_CLIENT_KEY          "${OPENVAS_STATE_DIR}/private/CA/clientkey.pem")
set (OPENVAS_CA_CERTIFICATE      "${OPENVAS_STATE_DIR}/CA/cacert.pem")

set (OPENVAS_USERS_DIR           "${OPENVAS_STATE_DIR}/users/")
set (OPENVAS_NVT_DIR             "${OPENVAS_STATE_DIR}/plugins/")

message ("-- Install prefix: ${CMAKE_INSTALL_PREFIX}")

## Dependency checks
##
## TODO Also check for headers where needed.
## Improve for workflow: First collect list of missing libs, then print the
## list and throw an error, otherwise long install-cmake-install-cmake cycles
## might occur.

pkg_check_modules (LIBOPENVAS REQUIRED libopenvas>=6.0.0)
pkg_check_modules (GNUTLS REQUIRED gnutls>=2.8)
pkg_check_modules (GLIB REQUIRED glib-2.0>=2.16)
pkg_check_modules (SQLITE3 REQUIRED sqlite3)
pkg_check_modules (UUID REQUIRED uuid)

message (STATUS "Looking for pcap...")
find_library (PCAP pcap)
message (STATUS "Looking for pcap... ${PCAP}")
if (NOT PCAP)
  message (FATAL_ERROR "The pcap library is required.")
endif (NOT PCAP)

message (STATUS "Looking for gpgme...")
find_library (GPGME gpgme)
message (STATUS "Looking for gpgme... ${GPGME}")
if (NOT GPGME)
  message (FATAL_ERROR "The gpgme library is required.")
endif (NOT GPGME)

execute_process (COMMAND pkg-config --cflags glib-2.0
  OUTPUT_VARIABLE GLIB_CFLAGS
  OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process (COMMAND pkg-config --libs glib-2.0
  OUTPUT_VARIABLE GLIB_LDFLAGS
  OUTPUT_STRIP_TRAILING_WHITESPACE)

execute_process (COMMAND pkg-config --cflags libopenvas
  OUTPUT_VARIABLE OPENVAS_CFLAGS
  OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process (COMMAND pkg-config --libs libopenvas
  OUTPUT_VARIABLE OPENVAS_LDFLAGS
  OUTPUT_STRIP_TRAILING_WHITESPACE)

execute_process (COMMAND pkg-config --cflags gnutls
  OUTPUT_VARIABLE GNUTLS_CFLAGS
  OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process (COMMAND pkg-config --libs gnutls
  OUTPUT_VARIABLE GNUTLS_LDFLAGS
  OUTPUT_STRIP_TRAILING_WHITESPACE)

execute_process (COMMAND pkg-config --cflags sqlite3
  OUTPUT_VARIABLE SQLITE3_CFLAGS
  OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process (COMMAND pkg-config --libs sqlite3
  OUTPUT_VARIABLE SQLITE3_LDFLAGS
  OUTPUT_STRIP_TRAILING_WHITESPACE)

execute_process (COMMAND pkg-config --cflags uuid
  OUTPUT_VARIABLE UUID_CFLAGS
  OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process (COMMAND pkg-config --libs uuid
  OUTPUT_VARIABLE UUID_LDFLAGS
  OUTPUT_STRIP_TRAILING_WHITESPACE)

## Version

string (REPLACE "
" "" OPENVASMD_VERSION ${CPACK_PACKAGE_VERSION})

# Configure Doxyfile with version number
configure_file (doc/Doxyfile.in doc/Doxyfile)
configure_file (doc/Doxyfile_full.in doc/Doxyfile_full)
configure_file (VERSION.in VERSION)
configure_file (src/openvasmd_log_conf.cmake_in src/openvasmd_log.conf)
configure_file (tools/openvas-scapdata-sync.in tools/openvas-scapdata-sync @ONLY)
configure_file (tools/openvas-certdata-sync.in tools/openvas-certdata-sync @ONLY)

## Program

set (HARDENING_FLAGS            "-Wformat -Wformat-security -O2 -D_FORTIFY_SOURCE=2 -fstack-protector -Wl,-z,relro -Wl,-z,now")

set (CMAKE_C_FLAGS_DEBUG        "${CMAKE_C_FLAGS_DEBUG} -Werror")
set (CMAKE_C_FLAGS              "${CMAKE_C_FLAGS} ${HARDENING_FLAGS} -Wall -D_BSD_SOURCE -D_ISOC99_SOURCE -D_SVID_SOURCE -D_FILE_OFFSET_BITS=64")

add_subdirectory (src)

## Documentation

add_subdirectory (doc)

## Install

install (CODE "file (MAKE_DIRECTORY \$ENV{DESTDIR}${OPENVAS_STATE_DIR}/openvasmd/report_formats)")

install (FILES ${CMAKE_BINARY_DIR}/src/openvasmd_log.conf
         DESTINATION ${OPENVAS_SYSCONF_DIR})

install (FILES src/report_formats/ARF/generate
               src/report_formats/ARF/ARF.xsl
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/global_report_formats/910200ca-dc05-11e1-954f-406186ea4fc5/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/report_formats/CPE/generate
               src/report_formats/CPE/CPE.xsl
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/global_report_formats/5ceff8ba-1f62-11e1-ab9f-406186ea4fc5/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/report_formats/HTML/generate
               src/report_formats/HTML/HTML.xsl
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/global_report_formats/6c248850-1f62-11e1-b082-406186ea4fc5
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/report_formats/ITG/generate
               src/report_formats/ITG/ITG.xsl
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/global_report_formats/77bd6c4a-1f62-11e1-abf0-406186ea4fc5/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/report_formats/LaTeX/generate
               src/report_formats/LaTeX/latex.xsl
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/global_report_formats/a684c02c-b531-11e1-bdc2-406186ea4fc5/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/report_formats/NBE/generate
               src/report_formats/NBE/NBE.xsl
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/global_report_formats/9ca6fe72-1f62-11e1-9e7c-406186ea4fc5/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/report_formats/PDF/generate
               src/report_formats/LaTeX/latex.xsl
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/global_report_formats/c402cc3e-b531-11e1-9163-406186ea4fc5/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/report_formats/TXT/generate src/report_formats/TXT/TXT.xsl
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/global_report_formats/a3810a62-1f62-11e1-9219-406186ea4fc5/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/report_formats/XML/generate
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/global_report_formats/a994b278-1f62-11e1-96ac-406186ea4fc5/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/schema_formats/HTML/generate
               src/schema_formats/RNC/rnc.xsl
               src/schema_formats/HTML/HTML.xsl
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/global_schema_formats/02052818-dab6-11df-9be4-002264764cea/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/schema_formats/RNC/generate
               src/schema_formats/RNC/rnc.xsl
               src/schema_formats/RNC/RNC.xsl
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/global_schema_formats/787a4a18-dabc-11df-9486-002264764cea/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/schema_formats/XML/generate
         src/schema_formats/XML/OMP.xml
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/global_schema_formats/18e826fc-dab6-11df-b913-002264764cea/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/schema_formats/XML-brief/generate
         src/schema_formats/XML-brief/OMP.xsl
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/global_schema_formats/d6cf255e-947c-11e1-829a-406186ea4fc5/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/alert_methods/Sourcefire/alert
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/global_alert_methods/cd1f5a34-6bdc-11e0-9827-002264764cea/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/alert_methods/verinice/alert
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/global_alert_methods/f9d97653-f89b-41af-9ba1-0f6ee00e9c1a/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (CODE "file (MAKE_DIRECTORY \$ENV{DESTDIR}${OPENVAS_DATA_DIR}/openvasmd/wizards)")

install (FILES src/wizards/quick_first_scan.xml
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/wizards/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES tools/scap_db_init.sql tools/cpe_update.xsl
         tools/cpe_youngerthan.xsl tools/cve_update.xsl
         tools/cve_youngerthan.xsl tools/cpe_getbyname.xsl
         tools/cve_getbyname.xsl tools/oval_update.xsl
         tools/oval_timestamp.xsl tools/ovaldef_getbyname.xsl
         tools/oval_verify.xsl tools/ovaldef_list_ids.xsl
         DESTINATION ${OPENVAS_SCAP_RES_DIR}
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES tools/cert_db_init.sql tools/dfn_cert_update.xsl
         tools/dfn_cert_getbyname.xsl
         DESTINATION ${OPENVAS_CERT_RES_DIR}
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES ${CMAKE_BINARY_DIR}/tools/openvas-scapdata-sync
         DESTINATION ${SBINDIR}
         PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE
                     GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES ${CMAKE_BINARY_DIR}/tools/openvas-certdata-sync
         DESTINATION ${SBINDIR}
         PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE
                     GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES tools/greenbone-scapdata-sync
         DESTINATION ${SBINDIR}
         PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE
                     GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES tools/greenbone-certdata-sync
         DESTINATION ${SBINDIR}
         PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE
                     GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

## End
