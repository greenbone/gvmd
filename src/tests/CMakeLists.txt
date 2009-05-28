# OpenVAS
# $Id$
# Description: CMakefile for the tests of the OpenVAS Manager program
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

if (OPENVAS_LIB_INSTALL_DIR)
  set (LIB_TEMP "-L${OPENVAS_LIB_INSTALL_DIR}")
else (OPENVAS_LIB_INSTALL_DIR)
  set (LIB_TEMP "")
endif (OPENVAS_LIB_INSTALL_DIR)

#set (OVAS_LDFLAG "${LIB_TEMP} -lgnutls")
set (OVAS_LDFLAG "${LIB_TEMP} -lsqlite3 -lgnutls -lopenvas")

MARK_AS_ADVANCED (LIB_TEMP)

exec_program (pkg-config
              ARGS --cflags glib-2.0
			  OUTPUT_VARIABLE GLIB_CFLAGS)

exec_program (pkg-config
              ARGS --libs glib-2.0
			  OUTPUT_VARIABLE GLIB_LDFLAGS)

## Libraries

add_library (common common.c)
set_target_properties (common PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")

## Tests of support libraries

include_directories (${COMMON_SOURCE_DIRECTORY}/common)
link_directories (${COMMON_BINARY_DIRECTORY}/string)
link_directories (${COMMON_BINARY_DIRECTORY}/file)

add_executable (make_report_uuid_0 make_report_uuid_0.c)
target_link_libraries (make_report_uuid_0 manage ovas-mngr-comm string file)
set_target_properties (make_report_uuid_0 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (make_report_uuid_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS} -lossp-uuid")
ADD_TEST (make_report_uuid_0 make_report_uuid_0)

add_executable (rmdir_recursively_0 rmdir_recursively_0.c)
target_link_libraries (rmdir_recursively_0 file)
set_target_properties (rmdir_recursively_0 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (rmdir_recursively_0 PROPERTIES LINK_FLAGS "${GLIB_LDFLAGS}")
ADD_TEST (rmdir_recursively_0 rmdir_recursively_0)

add_executable (rmdir_recursively_1 rmdir_recursively_1.c)
target_link_libraries (rmdir_recursively_1 file)
set_target_properties (rmdir_recursively_1 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (rmdir_recursively_1 PROPERTIES LINK_FLAGS "${GLIB_LDFLAGS}")
ADD_TEST (rmdir_recursively_1 rmdir_recursively_1)

add_executable (report_path_task_uuid_0 report_path_task_uuid_0.c)
target_link_libraries (report_path_task_uuid_0 manage ovas-mngr-comm string file)
set_target_properties (report_path_task_uuid_0 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (report_path_task_uuid_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS} -lossp-uuid")
ADD_TEST (report_path_task_uuid_0 report_path_task_uuid_0)

add_executable (report_path_task_uuid_1 report_path_task_uuid_1.c)
target_link_libraries (report_path_task_uuid_1 manage ovas-mngr-comm string file)
set_target_properties (report_path_task_uuid_1 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (report_path_task_uuid_1 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS} -lossp-uuid")
ADD_TEST (report_path_task_uuid_1 report_path_task_uuid_1)

add_executable (report_path_task_uuid_2 report_path_task_uuid_2.c)
target_link_libraries (report_path_task_uuid_2 manage ovas-mngr-comm string file)
set_target_properties (report_path_task_uuid_2 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (report_path_task_uuid_2 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS} -lossp-uuid")
ADD_TEST (report_path_task_uuid_2 report_path_task_uuid_2)

add_executable (strip_space_0 strip_space_0.c)
target_link_libraries (strip_space_0 string)
set_target_properties (strip_space_0 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (strip_space_0 PROPERTIES LINK_FLAGS "${GLIB_LDFLAGS}")
ADD_TEST (strip_space_0 strip_space_0)

add_executable (strip_space_1 strip_space_1.c)
target_link_libraries (strip_space_1 string)
set_target_properties (strip_space_1 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (strip_space_1 PROPERTIES LINK_FLAGS "${GLIB_LDFLAGS}")
ADD_TEST (strip_space_1 strip_space_1)

add_executable (strip_space_2 strip_space_2.c)
target_link_libraries (strip_space_2 string)
set_target_properties (strip_space_2 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (strip_space_2 PROPERTIES LINK_FLAGS "${GLIB_LDFLAGS}")
ADD_TEST (strip_space_2 strip_space_2)

add_executable (strip_space_3 strip_space_3.c)
target_link_libraries (strip_space_3 string)
set_target_properties (strip_space_3 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (strip_space_3 PROPERTIES LINK_FLAGS "${GLIB_LDFLAGS}")
ADD_TEST (strip_space_3 strip_space_3)

## Tests of the manager

add_executable (read_protocol_0 read_protocol_0.c)
target_link_libraries (read_protocol_0 string)
set_target_properties (read_protocol_0 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (read_protocol_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (read_protocol_0 common)
ADD_TEST (read_protocol_0 read_protocol_0)

## Tests of OMP

add_executable (omp_abort_task_0 omp_abort_task_0.c)
target_link_libraries (omp_abort_task_0 string)
set_target_properties (omp_abort_task_0 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_abort_task_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_abort_task_0 common)
ADD_TEST (omp_abort_task_0 omp_abort_task_0)

add_executable (omp_delete_report_0 omp_delete_report_0.c)
target_link_libraries (omp_delete_report_0 string)
set_target_properties (omp_delete_report_0 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_delete_report_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_delete_report_0 common)
ADD_TEST (omp_delete_report_0 omp_delete_report_0)

add_executable (omp_delete_report_1 omp_delete_report_1.c)
target_link_libraries (omp_delete_report_1 string)
set_target_properties (omp_delete_report_1 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_delete_report_1 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_delete_report_1 common)
ADD_TEST (omp_delete_report_1 omp_delete_report_1)

add_executable (omp_delete_task_0 omp_delete_task_0.c)
target_link_libraries (omp_delete_task_0 string)
set_target_properties (omp_delete_task_0 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_delete_task_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_delete_task_0 common)
ADD_TEST (omp_delete_task_0 omp_delete_task_0)

add_executable (omp_delete_task_1 omp_delete_task_1.c)
target_link_libraries (omp_delete_task_1 string)
set_target_properties (omp_delete_task_1 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_delete_task_1 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_delete_task_1 common)
ADD_TEST (omp_delete_task_1 omp_delete_task_1)

add_executable (omp_delete_task_2 omp_delete_task_2.c)
target_link_libraries (omp_delete_task_2 string)
set_target_properties (omp_delete_task_2 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_delete_task_2 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_delete_task_2 common)
ADD_TEST (omp_delete_task_2 omp_delete_task_2)

add_executable (omp_get_dependencies_0 omp_get_dependencies_0.c)
target_link_libraries (omp_get_dependencies_0 string)
set_target_properties (omp_get_dependencies_0 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_get_dependencies_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_dependencies_0 common)
ADD_TEST (omp_get_dependencies_0 omp_get_dependencies_0)

add_executable (omp_get_dependencies_1 omp_get_dependencies_1.c)
target_link_libraries (omp_get_dependencies_1 string)
set_target_properties (omp_get_dependencies_1 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_get_dependencies_1 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_dependencies_1 common)
ADD_TEST (omp_get_dependencies_1 omp_get_dependencies_1)

add_executable (omp_get_nvt_feed_all_0 omp_get_nvt_feed_all_0.c)
target_link_libraries (omp_get_nvt_feed_all_0 string)
set_target_properties (omp_get_nvt_feed_all_0 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_get_nvt_feed_all_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_nvt_feed_all_0 common)
ADD_TEST (omp_get_nvt_feed_all_0 omp_get_nvt_feed_all_0)

add_executable (omp_get_nvt_feed_all_1 omp_get_nvt_feed_all_1.c)
target_link_libraries (omp_get_nvt_feed_all_1 string)
set_target_properties (omp_get_nvt_feed_all_1 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_get_nvt_feed_all_1 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_nvt_feed_all_1 common)
ADD_TEST (omp_get_nvt_feed_all_1 omp_get_nvt_feed_all_1)

add_executable (omp_get_nvt_feed_checksum_0 omp_get_nvt_feed_checksum_0.c)
target_link_libraries (omp_get_nvt_feed_checksum_0 string)
set_target_properties (omp_get_nvt_feed_checksum_0 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_get_nvt_feed_checksum_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_nvt_feed_checksum_0 common)
ADD_TEST (omp_get_nvt_feed_checksum_0 omp_get_nvt_feed_checksum_0)

add_executable (omp_get_nvt_feed_checksum_1 omp_get_nvt_feed_checksum_1.c)
target_link_libraries (omp_get_nvt_feed_checksum_1 string)
set_target_properties (omp_get_nvt_feed_checksum_1 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_get_nvt_feed_checksum_1 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_nvt_feed_checksum_1 common)
ADD_TEST (omp_get_nvt_feed_checksum_1 omp_get_nvt_feed_checksum_1)

add_executable (omp_get_nvt_feed_details_0 omp_get_nvt_feed_details_0.c)
target_link_libraries (omp_get_nvt_feed_details_0 string)
set_target_properties (omp_get_nvt_feed_details_0 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_get_nvt_feed_details_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_nvt_feed_details_0 common)
ADD_TEST (omp_get_nvt_feed_details_0 omp_get_nvt_feed_details_0)

add_executable (omp_get_nvt_feed_details_1 omp_get_nvt_feed_details_1.c)
target_link_libraries (omp_get_nvt_feed_details_1 string)
set_target_properties (omp_get_nvt_feed_details_1 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_get_nvt_feed_details_1 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_nvt_feed_details_1 common)
ADD_TEST (omp_get_nvt_feed_details_1 omp_get_nvt_feed_details_1)

add_executable (omp_get_nvt_feed_details_2 omp_get_nvt_feed_details_2.c)
target_link_libraries (omp_get_nvt_feed_details_2 string)
set_target_properties (omp_get_nvt_feed_details_2 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_get_nvt_feed_details_2 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_nvt_feed_details_2 common)
ADD_TEST (omp_get_nvt_feed_details_2 omp_get_nvt_feed_details_2)

add_executable (omp_get_nvt_feed_details_3 omp_get_nvt_feed_details_3.c)
target_link_libraries (omp_get_nvt_feed_details_3 string)
set_target_properties (omp_get_nvt_feed_details_3 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_get_nvt_feed_details_3 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_nvt_feed_details_3 common)
ADD_TEST (omp_get_nvt_feed_details_3 omp_get_nvt_feed_details_3)

add_executable (omp_get_nvt_feed_details_4 omp_get_nvt_feed_details_4.c)
target_link_libraries (omp_get_nvt_feed_details_4 string)
set_target_properties (omp_get_nvt_feed_details_4 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_get_nvt_feed_details_4 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_nvt_feed_details_4 common)
ADD_TEST (omp_get_nvt_feed_details_4 omp_get_nvt_feed_details_4)

add_executable (omp_get_preferences_0 omp_get_preferences_0.c)
target_link_libraries (omp_get_preferences_0 string)
set_target_properties (omp_get_preferences_0 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_get_preferences_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_preferences_0 common)
ADD_TEST (omp_get_preferences_0 omp_get_preferences_0)

add_executable (omp_get_preferences_1 omp_get_preferences_1.c)
target_link_libraries (omp_get_preferences_1 string)
set_target_properties (omp_get_preferences_1 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_get_preferences_1 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_preferences_1 common)
ADD_TEST (omp_get_preferences_1 omp_get_preferences_1)

add_executable (omp_get_report_0 omp_get_report_0.c)
target_link_libraries (omp_get_report_0 string)
set_target_properties (omp_get_report_0 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_get_report_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_report_0 common)
ADD_TEST (omp_get_report_0 omp_get_report_0)

add_executable (omp_get_rules_0 omp_get_rules_0.c)
target_link_libraries (omp_get_rules_0 string)
set_target_properties (omp_get_rules_0 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_get_rules_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_rules_0 common)
ADD_TEST (omp_get_rules_0 omp_get_rules_0)

add_executable (omp_help_0 omp_help_0.c)
target_link_libraries (omp_help_0 string)
set_target_properties (omp_help_0 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_help_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_help_0 common)
ADD_TEST (omp_help_0 omp_help_0)

add_executable (omp_get_rules_1 omp_get_rules_1.c)
target_link_libraries (omp_get_rules_1 string)
set_target_properties (omp_get_rules_1 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_get_rules_1 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_rules_1 common)
ADD_TEST (omp_get_rules_1 omp_get_rules_1)

add_executable (omp_modify_report_0 omp_modify_report_0.c)
target_link_libraries (omp_modify_report_0 string)
set_target_properties (omp_modify_report_0 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_modify_report_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_modify_report_0 common)
ADD_TEST (omp_modify_report_0 omp_modify_report_0)

add_executable (omp_modify_task_0 omp_modify_task_0.c)
target_link_libraries (omp_modify_task_0 string)
set_target_properties (omp_modify_task_0 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_modify_task_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_modify_task_0 common)
ADD_TEST (omp_modify_task_0 omp_modify_task_0)

add_executable (omp_modify_task_1 omp_modify_task_1.c)
target_link_libraries (omp_modify_task_1 string)
set_target_properties (omp_modify_task_1 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_modify_task_1 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_modify_task_1 common)
ADD_TEST (omp_modify_task_1 omp_modify_task_1)

add_executable (omp_new_task_0 omp_new_task_0.c)
target_link_libraries (omp_new_task_0 string)
set_target_properties (omp_new_task_0 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_new_task_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_new_task_0 common)
ADD_TEST (omp_new_task_0 omp_new_task_0)

add_executable (omp_start_task_0 omp_start_task_0.c)
target_link_libraries (omp_start_task_0 string)
set_target_properties (omp_start_task_0 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_start_task_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_start_task_0 common)
ADD_TEST (omp_start_task_0 omp_start_task_0)

add_executable (omp_start_task_1 omp_start_task_1.c)
target_link_libraries (omp_start_task_1 string)
set_target_properties (omp_start_task_1 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_start_task_1 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_start_task_1 common)
ADD_TEST (omp_start_task_1 omp_start_task_1)

add_executable (omp_start_task_2 omp_start_task_2.c)
target_link_libraries (omp_start_task_2 string)
set_target_properties (omp_start_task_2 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_start_task_2 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_start_task_2 common)
ADD_TEST (omp_start_task_2 omp_start_task_2)

add_executable (omp_status_0 omp_status_0.c)
target_link_libraries (omp_status_0 string)
set_target_properties (omp_status_0 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_status_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_status_0 common)
ADD_TEST (omp_status_0 omp_status_0)

add_executable (omp_status_1 omp_status_1.c)
target_link_libraries (omp_status_1 string)
set_target_properties (omp_status_1 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_status_1 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_status_1 common)
ADD_TEST (omp_status_1 omp_status_1)

add_executable (omp_status_2 omp_status_2.c)
target_link_libraries (omp_status_2 string)
set_target_properties (omp_status_2 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_status_2 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_status_2 common)
ADD_TEST (omp_status_2 omp_status_2)

add_executable (omp_status_3 omp_status_3.c)
target_link_libraries (omp_status_3 string)
set_target_properties (omp_status_3 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_status_3 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_status_3 common)
ADD_TEST (omp_status_3 omp_status_3)

add_executable (omp_status_4 omp_status_4.c)
target_link_libraries (omp_status_4 string)
set_target_properties (omp_status_4 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_status_4 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_status_4 common)
ADD_TEST (omp_status_4 omp_status_4)

add_executable (omp_version_0 omp_version_0.c)
target_link_libraries (omp_version_0 string)
set_target_properties (omp_version_0 PROPERTIES COMPILE_FLAGS "-I .. ${GLIB_CFLAGS}")
set_target_properties (omp_version_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_version_0 common)
ADD_TEST (omp_version_0 omp_version_0)

## End
