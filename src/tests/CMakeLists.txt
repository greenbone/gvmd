# OpenVAS
# $Id$
# Description: CMakefile for the tests of the OpenVAS Manager program
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

## Config

exec_program (pkg-config
              ARGS --cflags glib-2.0
			  OUTPUT_VARIABLE GLIB_CFLAGS)

exec_program (pkg-config
              ARGS --libs glib-2.0
			  OUTPUT_VARIABLE GLIB_LDFLAGS)

## Libraries

add_library (common common.c)
set_target_properties (common PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")

## Programs

include_directories (${COMMON_SOURCE_DIRECTORY}/common)
link_directories (${COMMON_BINARY_DIRECTORY}/string)

add_executable (omp_modify_task_0 omp_modify_task_0.c)
target_link_libraries (omp_modify_task_0 string)
set_target_properties (omp_modify_task_0 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_modify_task_0 PROPERTIES LINK_FLAGS "-lgnutls ${GLIB_LDFLAGS}")
target_link_libraries (omp_modify_task_0 common)
ADD_TEST (omp_modify_task_0 omp_modify_task_0)

add_executable (omp_new_task_0 omp_new_task_0.c)
target_link_libraries (omp_new_task_0 string)
set_target_properties (omp_new_task_0 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_new_task_0 PROPERTIES LINK_FLAGS "-lgnutls ${GLIB_LDFLAGS}")
target_link_libraries (omp_new_task_0 common)
ADD_TEST (omp_new_task_0 omp_new_task_0)

add_executable (omp_version_0 omp_version_0.c)
target_link_libraries (omp_version_0 string)
set_target_properties (omp_version_0 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_version_0 PROPERTIES LINK_FLAGS "-lgnutls ${GLIB_LDFLAGS}")
target_link_libraries (omp_version_0 common)
ADD_TEST (omp_version_0 omp_version_0)

add_executable (strip_space_0 strip_space_0.c)
target_link_libraries (strip_space_0 string)
set_target_properties (strip_space_0 PROPERTIES COMPILE_FLAGS "-I ..")
ADD_TEST (strip_space_0 strip_space_0)

add_executable (strip_space_1 strip_space_1.c)
target_link_libraries (strip_space_1 string)
set_target_properties (strip_space_1 PROPERTIES COMPILE_FLAGS "-I ..")
ADD_TEST (strip_space_1 strip_space_1)

add_executable (strip_space_2 strip_space_2.c)
target_link_libraries (strip_space_2 string)
set_target_properties (strip_space_2 PROPERTIES COMPILE_FLAGS "-I ..")
ADD_TEST (strip_space_2 strip_space_2)

add_executable (strip_space_3 strip_space_3.c)
target_link_libraries (strip_space_3 string)
set_target_properties (strip_space_3 PROPERTIES COMPILE_FLAGS "-I ..")
ADD_TEST (strip_space_3 strip_space_3)

## End
