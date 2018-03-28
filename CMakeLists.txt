# OpenVAS
# $Id$
# Description: Top-level cmake control for the Manager.
#
# Authors:
# Matthew Mundell <matthew.mundell@greenbone.net>
# Timo Pollmeier <timo.pollmeier@greenbone.net>
#
# Copyright:
# Copyright (C) 2009-2016 Greenbone Networks GmbH
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

message ("-- Configuring the Manager...")

project (openvas-manager C)

cmake_minimum_required (VERSION 2.8)

if (POLICY CMP0005)
  cmake_policy (SET CMP0005 OLD)
endif (POLICY CMP0005)

SET(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)

include (FindPkgConfig)

if (NOT CMAKE_BUILD_TYPE)
  set (CMAKE_BUILD_TYPE Debug)
endif (NOT CMAKE_BUILD_TYPE)

if (NOT BACKEND STREQUAL POSTGRESQL)
  set (BACKEND SQLITE3)
endif (NOT BACKEND STREQUAL POSTGRESQL)

## Retrieve git revision (at configure time)
include (GetGit)

if (NOT CMAKE_BUILD_TYPE MATCHES "Release")
  if (EXISTS "${CMAKE_SOURCE_DIR}/.git/")
    if (GIT_EXECUTABLE)
      Git_GET_REVISION(. ProjectRevision)
      set (GIT_REVISION "~git-${ProjectRevision}")
    endif (GIT_EXECUTABLE)
  endif (EXISTS "${CMAKE_SOURCE_DIR}/.git/")
endif (NOT CMAKE_BUILD_TYPE MATCHES "Release")

## Project version
# The following three variables should be set through the project command once
# we require CMake >= 3.0
set (PROJECT_VERSION_MAJOR 7)
set (PROJECT_VERSION_MINOR 0)
set (PROJECT_VERSION_PATCH 3)

# Set beta version if this is a beta release series,
# unset if this is a stable release series.
#set (PROJECT_BETA_RELEASE 1)

if (GIT_REVISION)
  set (PROJECT_VERSION_GIT "${GIT_REVISION}")
else (GIT_REVISION)
  set (PROJECT_VERSION_GIT "~git")
endif (GIT_REVISION)

# If PROJECT_BETA_RELEASE is set, the version string will be set to:
#   "major.minor+beta${PROJECT_BETA_RELEASE}"
# If PROJECT_BETA_RELEASE is NOT set, the version string will be set to:
#   "major.minor.patch"
if (PROJECT_BETA_RELEASE)
  set (PROJECT_VERSION_SUFFIX "+beta${PROJECT_BETA_RELEASE}")
else (PROJECT_BETA_RELEASE)
  set (PROJECT_VERSION_SUFFIX ".${PROJECT_VERSION_PATCH}")
endif (PROJECT_BETA_RELEASE)

set (PROJECT_VERSION_STRING "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}${PROJECT_VERSION_SUFFIX}")

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

set (CPACK_PACKAGE_VERSION "${PROJECT_VERSION_STRING}${PROJECT_VERSION_GIT}")

set (CPACK_PACKAGE_FILE_NAME "${PROJECT_NAME}-${CPACK_PACKAGE_VERSION}")
set (CPACK_SOURCE_PACKAGE_FILE_NAME "${PROJECT_NAME}-${CPACK_PACKAGE_VERSION}")
set (CPACK_PACKAGE_VENDOR "The OpenVAS Project")
set (CPACK_SOURCE_IGNORE_FILES
"${CMAKE_BINARY_DIR}"
"/.git/"
"swp$"
)

include (CPack)

## Variables

set (OPENVASMD_DATABASE_VERSION 184)

set (OPENVASMD_SCAP_DATABASE_VERSION 15)

set (OPENVASMD_CERT_DATABASE_VERSION 6)

set (OMP_VERSION "7.0")

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

# The maximum number of seconds the SQLite backend will sleep
# before retrying an SQL operation that is getting a busy response.
#
# 0 means to not sleep at all, and let the db/libsqlite do its own thing.
#
if (NOT DEFINED OPENVAS_SQLITE_SLEEP_MAX)
  set (OPENVAS_SQLITE_SLEEP_MAX 0)
endif (NOT DEFINED OPENVAS_SQLITE_SLEEP_MAX)

#if (NOT SYSCONFDIR)
#  set (SYSCONFDIR "${CMAKE_INSTALL_PREFIX}/etc")
#endif (NOT SYSCONFDIR)

set (OPENVAS_DATA_DIR     "${DATADIR}/openvas")
set (OPENVAS_STATE_DIR    "${LOCALSTATEDIR}/lib/openvas")
set (OPENVAS_LOG_DIR      "${LOCALSTATEDIR}/log/openvas")
set (OPENVAS_SYSCONF_DIR  "${SYSCONFDIR}/openvas")
set (OPENVAS_SCAP_RES_DIR "${OPENVAS_DATA_DIR}/scap")
set (OPENVAS_CERT_RES_DIR "${OPENVAS_DATA_DIR}/cert")
set (OPENVASMD_STATE_DIR  "${OPENVAS_STATE_DIR}/openvasmd")
set (OPENVAS_CA_DIR       "${OPENVASMD_STATE_DIR}/trusted_certs")
set (OPENVAS_LIB_INSTALL_DIR     "${LIBDIR}")

set (OPENVAS_SCANNER_CERTIFICATE "${OPENVAS_STATE_DIR}/CA/servercert.pem")
set (OPENVAS_SCANNER_KEY         "${OPENVAS_STATE_DIR}/private/CA/serverkey.pem")
set (OPENVAS_CLIENT_CERTIFICATE  "${OPENVAS_STATE_DIR}/CA/clientcert.pem")
set (OPENVAS_CLIENT_KEY          "${OPENVAS_STATE_DIR}/private/CA/clientkey.pem")
set (OPENVAS_CA_CERTIFICATE      "${OPENVAS_STATE_DIR}/CA/cacert.pem")

if (NOT OPENVAS_RUN_DIR)
  set (OPENVAS_RUN_DIR      "${LOCALSTATEDIR}/run")
endif (NOT OPENVAS_RUN_DIR)

if (NOT OPENVAS_NVT_DIR)
  set (OPENVAS_NVT_DIR "${OPENVAS_STATE_DIR}/plugins/")
endif (NOT OPENVAS_NVT_DIR)

if (NOT OPENVAS_CERT_DATA_DIR)
  set (OPENVAS_CERT_DATA_DIR "${OPENVAS_STATE_DIR}/cert-data")
endif (NOT OPENVAS_CERT_DATA_DIR)

if (NOT OPENVAS_SCAP_DATA_DIR)
  set (OPENVAS_SCAP_DATA_DIR "${OPENVAS_STATE_DIR}/scap-data")
endif (NOT OPENVAS_SCAP_DATA_DIR)

# System username to use when dropping privileges
if (NOT OPENVAS_DEFAULT_DROP_USER)
  set (OPENVAS_DEFAULT_DROP_USER "")
endif (NOT OPENVAS_DEFAULT_DROP_USER)

message ("-- Install prefix: ${CMAKE_INSTALL_PREFIX}")

## Dependency checks
##
## TODO Also check for headers where needed.
## Improve for workflow: First collect list of missing libs, then print the
## list and throw an error, otherwise long install-cmake-install-cmake cycles
## might occur.

pkg_check_modules (LIBOPENVAS_OMP REQUIRED libopenvas_omp>=9.0.0)
pkg_check_modules (LIBOPENVAS_MISC REQUIRED libopenvas_misc>=9.0.0)
pkg_check_modules (LIBOPENVAS_BASE REQUIRED libopenvas_base>=9.0.0)
pkg_check_modules (LIBOPENVAS_OSP REQUIRED libopenvas_osp>=9.0.0)
pkg_check_modules (GNUTLS REQUIRED gnutls>=3.2.15)
pkg_check_modules (GLIB REQUIRED glib-2.0>=2.32)

if (BACKEND STREQUAL SQLITE3)
  pkg_check_modules (SQLITE3 REQUIRED sqlite3)
else (BACKEND STREQUAL SQLITE3)
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
endif (BACKEND STREQUAL SQLITE3)

message (STATUS "Looking for libgcrypt...")
find_library (LIBGCRYPT gcrypt)
if (NOT LIBGCRYPT)
  message (SEND_ERROR "The libgcrypt library is required.")
else (NOT LIBGCRYPT)
  message (STATUS "Looking for libgcrypt... ${LIBGCRYPT}")
  execute_process (COMMAND libgcrypt-config --cflags
    OUTPUT_VARIABLE GCRYPT_CFLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE)
endif (NOT LIBGCRYPT)

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

## Version

set (OPENVASMD_VERSION "${PROJECT_VERSION_STRING}")

# Configure Doxyfile with version number
configure_file (doc/Doxyfile.in doc/Doxyfile)
configure_file (doc/Doxyfile_full.in doc/Doxyfile_full)
configure_file (doc/example-openvas-manage-certs.conf.in doc/example-openvas-manage-certs.conf @ONLY)
configure_file (VERSION.in VERSION)
configure_file (src/openvasmd_log_conf.cmake_in src/openvasmd_log.conf)
configure_file (src/schema_formats/XML/OMP.xml.in src/schema_formats/XML/OMP.xml @ONLY)
configure_file (tools/greenbone-scapdata-sync.in tools/greenbone-scapdata-sync @ONLY)
configure_file (tools/greenbone-certdata-sync.in tools/greenbone-certdata-sync @ONLY)
configure_file (tools/openvas-portnames-update.in tools/openvas-portnames-update @ONLY)
configure_file (tools/openvas-migrate-to-postgres.in tools/openvas-migrate-to-postgres @ONLY)
configure_file (tools/openvas-manage-certs.in tools/openvas-manage-certs @ONLY)

## Program

set (HARDENING_FLAGS            "-Wformat -Wformat-security -O2 -D_FORTIFY_SOURCE=2 -fstack-protector")
set (LINKER_HARDENING_FLAGS     "-Wl,-z,relro -Wl,-z,now")

set (CMAKE_C_FLAGS_DEBUG        "${CMAKE_C_FLAGS_DEBUG} -Werror")
set (CMAKE_C_FLAGS              "${CMAKE_C_FLAGS} ${HARDENING_FLAGS} -Wall -D_BSD_SOURCE -D_ISOC99_SOURCE -D_SVID_SOURCE -D_DEFAULT_SOURCE -D_FILE_OFFSET_BITS=64")

add_subdirectory (src)

## Documentation

add_subdirectory (doc)

## Install

install (CODE "file (MAKE_DIRECTORY \$ENV{DESTDIR}${OPENVAS_DATA_DIR}/openvasmd/report_formats)")

install (DIRECTORY DESTINATION ${OPENVASMD_STATE_DIR})

install (FILES ${CMAKE_BINARY_DIR}/src/openvasmd_log.conf
               ${CMAKE_SOURCE_DIR}/src/pwpolicy.conf
         DESTINATION ${OPENVAS_SYSCONF_DIR})

# Report formats.

install (FILES src/report_formats/Anonymous_XML/report_format.xml
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/5057e5cc-b825-11e4-9d0e-28d24461215b
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/report_formats/Anonymous_XML/Anonymous_XML.xsl
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/5057e5cc-b825-11e4-9d0e-28d24461215b
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/report_formats/Anonymous_XML/generate
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/5057e5cc-b825-11e4-9d0e-28d24461215b
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES src/report_formats/ARF/report_format.xml
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/910200ca-dc05-11e1-954f-406186ea4fc5/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/report_formats/ARF/ARF.xsl
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/910200ca-dc05-11e1-954f-406186ea4fc5/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/report_formats/ARF/generate
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/910200ca-dc05-11e1-954f-406186ea4fc5/
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES src/report_formats/CPE/report_format.xml
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/5ceff8ba-1f62-11e1-ab9f-406186ea4fc5/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/report_formats/CPE/CPE.xsl
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/5ceff8ba-1f62-11e1-ab9f-406186ea4fc5/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/report_formats/CPE/generate
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/5ceff8ba-1f62-11e1-ab9f-406186ea4fc5/
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES src/report_formats/CSV_Results/report_format.xml
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/c1645568-627a-11e3-a660-406186ea4fc5
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/report_formats/CSV_Results/CSV_Results.xsl
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/c1645568-627a-11e3-a660-406186ea4fc5
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/report_formats/CSV_Results/generate
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/c1645568-627a-11e3-a660-406186ea4fc5
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES src/report_formats/CSV_Hosts/report_format.xml
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/9087b18c-626c-11e3-8892-406186ea4fc5
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/report_formats/CSV_Hosts/CSV_Hosts.xsl
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/9087b18c-626c-11e3-8892-406186ea4fc5
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/report_formats/CSV_Hosts/generate
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/9087b18c-626c-11e3-8892-406186ea4fc5
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES src/report_formats/HTML/report_format.xml
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/6c248850-1f62-11e1-b082-406186ea4fc5
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/report_formats/HTML/HTML.xsl
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/6c248850-1f62-11e1-b082-406186ea4fc5
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/report_formats/HTML/generate
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/6c248850-1f62-11e1-b082-406186ea4fc5
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES src/report_formats/ITG/report_format.xml
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/77bd6c4a-1f62-11e1-abf0-406186ea4fc5/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/report_formats/ITG/ITG.xsl
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/77bd6c4a-1f62-11e1-abf0-406186ea4fc5/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/report_formats/ITG/generate
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/77bd6c4a-1f62-11e1-abf0-406186ea4fc5/
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES src/report_formats/LaTeX/report_format.xml
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/a684c02c-b531-11e1-bdc2-406186ea4fc5/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/report_formats/LaTeX/latex.xsl
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/a684c02c-b531-11e1-bdc2-406186ea4fc5/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/report_formats/LaTeX/generate
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/a684c02c-b531-11e1-bdc2-406186ea4fc5/
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES src/report_formats/NBE/report_format.xml
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/9ca6fe72-1f62-11e1-9e7c-406186ea4fc5/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/report_formats/NBE/NBE.xsl
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/9ca6fe72-1f62-11e1-9e7c-406186ea4fc5/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/report_formats/NBE/generate
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/9ca6fe72-1f62-11e1-9e7c-406186ea4fc5/
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES src/report_formats/LaTeX/latex.xsl
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/c402cc3e-b531-11e1-9163-406186ea4fc5/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/report_formats/PDF/report_format.xml
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/c402cc3e-b531-11e1-9163-406186ea4fc5/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/report_formats/PDF/generate
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/c402cc3e-b531-11e1-9163-406186ea4fc5/
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES src/report_formats/Topology/report_format.xml
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/9e5e5deb-879e-4ecc-8be6-a71cd0875cdd/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/report_formats/Topology/hostvisdot-summary.xsl
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/9e5e5deb-879e-4ecc-8be6-a71cd0875cdd/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/report_formats/Topology/generate
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/9e5e5deb-879e-4ecc-8be6-a71cd0875cdd/
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES src/report_formats/TXT/report_format.xml
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/a3810a62-1f62-11e1-9219-406186ea4fc5/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/report_formats/TXT/TXT.xsl
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/a3810a62-1f62-11e1-9219-406186ea4fc5/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/report_formats/TXT/generate
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/a3810a62-1f62-11e1-9219-406186ea4fc5/
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES src/report_formats/XML/report_format.xml
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/a994b278-1f62-11e1-96ac-406186ea4fc5/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/report_formats/XML/generate
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/a994b278-1f62-11e1-96ac-406186ea4fc5/
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES src/report_formats/Verinice_ISM/report_format.xml
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/c15ad349-bd8d-457a-880a-c7056532ee15/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/report_formats/Verinice_ISM/Verinice_ISM.xsl
               src/report_formats/Verinice_ISM/classification.xsl
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/c15ad349-bd8d-457a-880a-c7056532ee15/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/report_formats/Verinice_ISM/generate
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/c15ad349-bd8d-457a-880a-c7056532ee15/
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES src/report_formats/Verinice_ITG/report_format.xml
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/50c9950a-f326-11e4-800c-28d24461215b/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/report_formats/Verinice_ITG/Verinice_ITG.xsl
               src/report_formats/Verinice_ITG/classification-helpers.xsl
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/50c9950a-f326-11e4-800c-28d24461215b/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/report_formats/Verinice_ITG/generate
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/report_formats/50c9950a-f326-11e4-800c-28d24461215b/
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

# Schema formats.

install (FILES src/schema_formats/RNC/rnc.xsl
               src/schema_formats/HTML/HTML.xsl
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/global_schema_formats/02052818-dab6-11df-9be4-002264764cea/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/schema_formats/HTML/generate
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/global_schema_formats/02052818-dab6-11df-9be4-002264764cea/
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES src/schema_formats/RNC/rnc.xsl
               src/schema_formats/RNC/RNC.xsl
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/global_schema_formats/787a4a18-dabc-11df-9486-002264764cea/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/schema_formats/RNC/generate
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/global_schema_formats/787a4a18-dabc-11df-9486-002264764cea/
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES ${CMAKE_BINARY_DIR}/src/schema_formats/XML/OMP.xml
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/global_schema_formats/18e826fc-dab6-11df-b913-002264764cea/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/schema_formats/XML/generate
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/global_schema_formats/18e826fc-dab6-11df-b913-002264764cea/
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES src/schema_formats/XML-brief/OMP.xsl
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/global_schema_formats/d6cf255e-947c-11e1-829a-406186ea4fc5/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES src/schema_formats/XML-brief/generate
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/global_schema_formats/d6cf255e-947c-11e1-829a-406186ea4fc5/
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

# Alert methods.

install (FILES src/alert_methods/SCP/alert
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/global_alert_methods/2db07698-ec49-11e5-bcff-28d24461215b/
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES src/alert_methods/Send/alert
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/global_alert_methods/4a398d42-87c0-11e5-a1c0-28d24461215b/
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
 
install (FILES src/alert_methods/SMB/alert
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/global_alert_methods/c427a688-b653-40ab-a9d0-d6ba842a9d63/
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES src/alert_methods/SNMP/alert
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/global_alert_methods/9d435134-15d3-11e6-bf5c-28d24461215b/
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES src/alert_methods/Sourcefire/alert
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/global_alert_methods/cd1f5a34-6bdc-11e0-9827-002264764cea/
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES src/alert_methods/TippingPoint/alert
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/global_alert_methods/5b39c481-9137-4876-b734-263849dd96ce/
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES src/alert_methods/TippingPoint/report-convert.py
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/global_alert_methods/5b39c481-9137-4876-b734-263849dd96ce/
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES src/alert_methods/verinice/alert
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/global_alert_methods/f9d97653-f89b-41af-9ba1-0f6ee00e9c1a/
         PERMISSIONS OWNER_WRITE OWNER_READ OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (CODE "file (MAKE_DIRECTORY \$ENV{DESTDIR}${OPENVAS_DATA_DIR}/openvasmd/wizards)")

install (FILES src/wizards/quick_first_scan.xml
               src/wizards/get_tasks_deep.xml
               src/wizards/delete_task_deep.xml
               src/wizards/quick_auth_scan.xml
               src/wizards/quick_task.xml
               src/wizards/reset_task.xml
               src/wizards/modify_task.xml
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/wizards/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES tools/portnames_update.xsl
         DESTINATION ${OPENVAS_DATA_DIR}/openvasmd/
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

install (FILES tools/cpe_youngerthan.xsl tools/cve_youngerthan.xsl
         tools/cpe_getbyname.xsl tools/cve_getbyname.xsl
         tools/oval_timestamp.xsl tools/ovaldef_getbyname.xsl
         tools/oval_verify.xsl tools/ovaldef_list_ids.xsl
         DESTINATION ${OPENVAS_SCAP_RES_DIR}
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

if (BACKEND STREQUAL SQLITE3)
  install (FILES tools/scap_db_init.sql tools/cpe_update.xsl
           tools/cve_update.xsl tools/oval_update.xsl
		   DESTINATION ${OPENVAS_SCAP_RES_DIR}
		   PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)
else (BACKEND STREQUAL SQLITE3)
  install (FILES tools/scap_db_init_pg.sql
           RENAME scap_db_init.sql
		   DESTINATION ${OPENVAS_SCAP_RES_DIR}
		   PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)
  install (FILES tools/cpe_update_pg.xsl
           RENAME cpe_update.xsl
		   DESTINATION ${OPENVAS_SCAP_RES_DIR}
		   PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)
  install (FILES tools/cve_update_pg.xsl
           RENAME cve_update.xsl
		   DESTINATION ${OPENVAS_SCAP_RES_DIR}
		   PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)
  install (FILES tools/oval_update_pg.xsl
           RENAME oval_update.xsl
		   DESTINATION ${OPENVAS_SCAP_RES_DIR}
		   PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)
endif (BACKEND STREQUAL SQLITE3)

install (FILES tools/cert_bund_getbyname.xsl tools/dfn_cert_getbyname.xsl
         DESTINATION ${OPENVAS_CERT_RES_DIR}
         PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)

if (BACKEND STREQUAL SQLITE3)
  install (FILES tools/cert_db_init.sql tools/cert_bund_update.xsl
           tools/dfn_cert_update.xsl
		   DESTINATION ${OPENVAS_CERT_RES_DIR}
		   PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)
else (BACKEND STREQUAL SQLITE3)
  install (FILES tools/cert_db_init_pg.sql
           RENAME cert_db_init.sql
		   DESTINATION ${OPENVAS_CERT_RES_DIR}
		   PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)
  install (FILES tools/cert_bund_update_pg.xsl
           RENAME cert_bund_update.xsl
		   DESTINATION ${OPENVAS_CERT_RES_DIR}
		   PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)
  install (FILES tools/dfn_cert_update_pg.xsl
           RENAME dfn_cert_update.xsl
		   DESTINATION ${OPENVAS_CERT_RES_DIR}
		   PERMISSIONS OWNER_WRITE OWNER_READ GROUP_READ WORLD_READ)
endif (BACKEND STREQUAL SQLITE3)

install (FILES ${CMAKE_BINARY_DIR}/tools/openvas-portnames-update
         DESTINATION ${SBINDIR}
         PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE
                     GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES ${CMAKE_BINARY_DIR}/tools/greenbone-scapdata-sync
         DESTINATION ${SBINDIR}
         PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE
                     GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES ${CMAKE_BINARY_DIR}/tools/greenbone-certdata-sync
         DESTINATION ${SBINDIR}
         PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE
                     GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES ${CMAKE_SOURCE_DIR}/tools/openvas-lsc-rpm-creator.sh
         DESTINATION ${OPENVAS_DATA_DIR}
         PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE
                     GROUP_READ GROUP_EXECUTE
                     WORLD_READ WORLD_EXECUTE)

install (FILES ${CMAKE_BINARY_DIR}/tools/openvas-migrate-to-postgres
         DESTINATION ${SBINDIR}
         PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE
                     GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES ${CMAKE_SOURCE_DIR}/tools/extra/xml_split
         DESTINATION ${OPENVAS_SCAP_RES_DIR}
         PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE
                     GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

if (BACKEND STREQUAL SQLITE3)
  install (FILES ${CMAKE_SOURCE_DIR}/tools/database-statistics-sqlite
           DESTINATION ${SBINDIR}
           PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE
                       GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
endif (BACKEND STREQUAL SQLITE3)

install (FILES ${CMAKE_BINARY_DIR}/tools/openvas-manage-certs
         DESTINATION ${BINDIR}
         PERMISSIONS OWNER_EXECUTE OWNER_READ OWNER_WRITE
                     GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

install (FILES ${CMAKE_SOURCE_DIR}/doc/openvas-manage-certs.1
          DESTINATION ${DATADIR}/man/man1 )

install (FILES ${CMAKE_BINARY_DIR}/doc/example-openvas-manage-certs.conf
         DESTINATION ${DATADIR}/doc/openvas-manager/ )

## End
