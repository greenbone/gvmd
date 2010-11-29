# OpenVAS
# $Id$
# Description: CMakefile for the tests of the OpenVAS Manager program
#
# Authors:
# Matthew Mundell <matthew.mundell@greenbone.net>
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

add_definitions (-DTASKS_SQL)

exec_program (libopenvas-config
              ARGS --cflags
			  OUTPUT_VARIABLE OPENVAS_CFLAGS)
exec_program (libopenvas-config
              ARGS --libs
			  OUTPUT_VARIABLE OPENVAS_LDFLAGS)

if (OPENVAS_HEADER_INSTALL_DIR)
  set (OVAS_CFLAGS "-I${OPENVAS_HEADER_INSTALL_DIR} ${OPENVAS_CFLAGS}")
else (OPENVAS_HEADER_INSTALL_DIR)
  set (OVAS_CFLAGS "")
endif (OPENVAS_HEADER_INSTALL_DIR)

if (OPENVAS_LIB_INSTALL_DIR)
  set (LIB_TEMP "-L${OPENVAS_LIB_INSTALL_DIR}")
else (OPENVAS_LIB_INSTALL_DIR)
  set (LIB_TEMP "")
endif (OPENVAS_LIB_INSTALL_DIR)

set (OVAS_LDFLAG "${LIB_TEMP} -lsqlite3 -lgnutls ${OPENVAS_LDFLAGS}")

MARK_AS_ADVANCED (LIB_TEMP)

exec_program (pkg-config
              ARGS --cflags glib-2.0
			  OUTPUT_VARIABLE GLIB_CFLAGS)

exec_program (pkg-config
              ARGS --libs glib-2.0
			  OUTPUT_VARIABLE GLIB_LDFLAGS)

link_libraries (openvas_omp openvas_base openvas_misc)

## Libraries

add_library (common common.c)
set_target_properties (common PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")

## Tests of support libraries

include_directories (${COMMON_SOURCE_DIRECTORY}/common)

add_executable (make_report_uuid_0 make_report_uuid_0.c)
target_link_libraries (make_report_uuid_0 manage ovas-mngr-comm)
set_target_properties (make_report_uuid_0 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (make_report_uuid_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS} -luuid")
add_test (make_report_uuid_0 make_report_uuid_0)

add_executable (strip_space_0 strip_space_0.c)
set_target_properties (strip_space_0 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (strip_space_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (strip_space_0 common)
add_test (strip_space_0 strip_space_0)

add_executable (strip_space_1 strip_space_1.c)
set_target_properties (strip_space_1 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (strip_space_1 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (strip_space_1 common)
add_test (strip_space_1 strip_space_1)

add_executable (strip_space_2 strip_space_2.c)
set_target_properties (strip_space_2 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (strip_space_2 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (strip_space_2 common)
add_test (strip_space_2 strip_space_2)

add_executable (strip_space_3 strip_space_3.c)
set_target_properties (strip_space_3 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (strip_space_3 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (strip_space_3 common)
add_test (strip_space_3 strip_space_3)

add_executable (lsc_user_0 lsc_user_0.c ../lsc_user.c)
set_target_properties (lsc_user_0 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (lsc_user_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
add_test (lsc_user_0_base  lsc_user_0)
add_test (lsc_user_1_alnum lsc_user_0 "abc123")

## Tests of OMP

add_executable (omp_abort_task_0 omp_abort_task_0.c)
set_target_properties (omp_abort_task_0 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_abort_task_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_abort_task_0 common)
add_test (omp_abort_task_0 omp_abort_task_0)

add_executable (omp_authenticate_0 omp_authenticate_0.c)
set_target_properties (omp_authenticate_0 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_authenticate_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_authenticate_0 common)
add_test (omp_authenticate_0 omp_authenticate_0)

add_executable (omp_bogus_0 omp_bogus_0.c)
set_target_properties (omp_bogus_0 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_bogus_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_bogus_0 common)
add_test (omp_bogus_0 omp_bogus_0)

add_executable (omp_bogus_1 omp_bogus_1.c)
set_target_properties (omp_bogus_1 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_bogus_1 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_bogus_1 common)
add_test (omp_bogus_1 omp_bogus_1)

add_executable (omp_commands_0 omp_commands_0.c)
set_target_properties (omp_commands_0 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_commands_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_commands_0 common)
add_test (omp_commands_0 omp_commands_0)

add_executable (omp_create_config_0 omp_create_config_0.c)
set_target_properties (omp_create_config_0 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_create_config_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_create_config_0 common)
add_test (omp_create_config_0 omp_create_config_0)

add_executable (omp_create_config_1 omp_create_config_1.c)
set_target_properties (omp_create_config_1 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_create_config_1 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_create_config_1 common)
add_test (omp_create_config_1 omp_create_config_1)

add_executable (omp_create_lsc_credential_0 omp_create_lsc_credential_0.c)
set_target_properties (omp_create_lsc_credential_0 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_create_lsc_credential_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_create_lsc_credential_0 common)
add_test (omp_create_lsc_credential_0 omp_create_lsc_credential_0)

add_executable (omp_create_lsc_credential_1 omp_create_lsc_credential_1.c)
set_target_properties (omp_create_lsc_credential_1 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_create_lsc_credential_1 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_create_lsc_credential_1 common)
add_test (omp_create_lsc_credential_1 omp_create_lsc_credential_1)

add_executable (omp_create_target_0 omp_create_target_0.c)
set_target_properties (omp_create_target_0 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_create_target_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_create_target_0 common)
add_test (omp_create_target_0 omp_create_target_0)

add_executable (omp_create_target_1 omp_create_target_1.c)
set_target_properties (omp_create_target_1 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_create_target_1 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_create_target_1 common)
add_test (omp_create_target_1 omp_create_target_1)

add_executable (omp_create_task_0 omp_create_task_0.c)
set_target_properties (omp_create_task_0 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_create_task_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_create_task_0 common)
add_test (omp_create_task_0 omp_create_task_0)

add_executable (omp_create_task_1 omp_create_task_1.c)
set_target_properties (omp_create_task_1 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_create_task_1 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_create_task_1 common)
add_test (omp_create_task_1 omp_create_task_1)

add_executable (omp_create_task_2 omp_create_task_2.c)
set_target_properties (omp_create_task_2 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_create_task_2 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_create_task_2 common)
add_test (omp_create_task_2 omp_create_task_2)

add_executable (omp_create_task_3 omp_create_task_3.c)
set_target_properties (omp_create_task_3 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_create_task_3 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_create_task_3 common)
add_test (omp_create_task_3 omp_create_task_3)

add_executable (omp_create_task_4 omp_create_task_4.c)
set_target_properties (omp_create_task_4 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_create_task_4 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_create_task_4 common)
add_test (omp_create_task_4 omp_create_task_4)

add_executable (omp_delete_config_0 omp_delete_config_0.c)
set_target_properties (omp_delete_config_0 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_delete_config_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_delete_config_0 common)
add_test (omp_delete_config_0 omp_delete_config_0)

add_executable (omp_delete_config_1 omp_delete_config_1.c)
set_target_properties (omp_delete_config_1 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_delete_config_1 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_delete_config_1 common)
add_test (omp_delete_config_1 omp_delete_config_1)

add_executable (omp_delete_lsc_credential_0 omp_delete_lsc_credential_0.c)
set_target_properties (omp_delete_lsc_credential_0 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_delete_lsc_credential_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_delete_lsc_credential_0 common)
add_test (omp_delete_lsc_credential_0 omp_delete_lsc_credential_0)

add_executable (omp_delete_report_0 omp_delete_report_0.c)
set_target_properties (omp_delete_report_0 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_delete_report_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_delete_report_0 common)
add_test (omp_delete_report_0 omp_delete_report_0)

add_executable (omp_delete_report_1 omp_delete_report_1.c)
set_target_properties (omp_delete_report_1 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_delete_report_1 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_delete_report_1 common)
add_test (omp_delete_report_1 omp_delete_report_1)

add_executable (omp_delete_target_0 omp_delete_target_0.c)
set_target_properties (omp_delete_target_0 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_delete_target_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_delete_target_0 common)
add_test (omp_delete_target_0 omp_delete_target_0)

add_executable (omp_delete_target_1 omp_delete_target_1.c)
set_target_properties (omp_delete_target_1 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_delete_target_1 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_delete_target_1 common)
add_test (omp_delete_target_1 omp_delete_target_1)

add_executable (omp_delete_task_0 omp_delete_task_0.c)
set_target_properties (omp_delete_task_0 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_delete_task_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_delete_task_0 common)
add_test (omp_delete_task_0 omp_delete_task_0)

add_executable (omp_delete_task_1 omp_delete_task_1.c)
set_target_properties (omp_delete_task_1 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_delete_task_1 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_delete_task_1 common)
add_test (omp_delete_task_1 omp_delete_task_1)

add_executable (omp_delete_task_2 omp_delete_task_2.c)
set_target_properties (omp_delete_task_2 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_delete_task_2 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_delete_task_2 common)
add_test (omp_delete_task_2 omp_delete_task_2)

add_executable (omp_get_certificates_0 omp_get_certificates_0.c)
set_target_properties (omp_get_certificates_0 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_certificates_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_certificates_0 common)
add_test (omp_get_certificates_0 omp_get_certificates_0)

add_executable (omp_get_certificates_1 omp_get_certificates_1.c)
set_target_properties (omp_get_certificates_1 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_certificates_1 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_certificates_1 common)
add_test (omp_get_certificates_1 omp_get_certificates_1)

add_executable (omp_get_configs_0 omp_get_configs_0.c)
set_target_properties (omp_get_configs_0 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_configs_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_configs_0 common)
add_test (omp_get_configs_0 omp_get_configs_0)

add_executable (omp_get_configs_1 omp_get_configs_1.c)
set_target_properties (omp_get_configs_1 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_configs_1 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_configs_1 common)
add_test (omp_get_configs_1 omp_get_configs_1)

add_executable (omp_get_configs_2 omp_get_configs_2.c)
set_target_properties (omp_get_configs_2 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_configs_2 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_configs_2 common)
add_test (omp_get_configs_2 omp_get_configs_2)

add_executable (omp_get_configs_3 omp_get_configs_3.c)
set_target_properties (omp_get_configs_3 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_configs_3 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_configs_3 common)
add_test (omp_get_configs_3 omp_get_configs_3)

add_executable (omp_get_dependencies_0 omp_get_dependencies_0.c)
set_target_properties (omp_get_dependencies_0 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_dependencies_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_dependencies_0 common)
add_test (omp_get_dependencies_0 omp_get_dependencies_0)

add_executable (omp_get_dependencies_1 omp_get_dependencies_1.c)
set_target_properties (omp_get_dependencies_1 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_dependencies_1 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_dependencies_1 common)
add_test (omp_get_dependencies_1 omp_get_dependencies_1)

add_executable (omp_get_lsc_credentials_0 omp_get_lsc_credentials_0.c)
set_target_properties (omp_get_lsc_credentials_0 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_lsc_credentials_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_lsc_credentials_0 common)
add_test (omp_get_lsc_credentials_0 omp_get_lsc_credentials_0)

add_executable (omp_get_lsc_credentials_1 omp_get_lsc_credentials_1.c)
set_target_properties (omp_get_lsc_credentials_1 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_lsc_credentials_1 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_lsc_credentials_1 common)
add_test (omp_get_lsc_credentials_1 omp_get_lsc_credentials_1)

add_executable (omp_get_lsc_credentials_2 omp_get_lsc_credentials_2.c)
set_target_properties (omp_get_lsc_credentials_2 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_lsc_credentials_2 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_lsc_credentials_2 common)
add_test (omp_get_lsc_credentials_2 omp_get_lsc_credentials_2)

add_executable (omp_get_targets_0 omp_get_targets_0.c)
set_target_properties (omp_get_targets_0 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_targets_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_targets_0 common)
add_test (omp_get_targets_0 omp_get_targets_0)

add_executable (omp_get_targets_1 omp_get_targets_1.c)
set_target_properties (omp_get_targets_1 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_targets_1 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_targets_1 common)
add_test (omp_get_targets_1 omp_get_targets_1)

add_executable (omp_get_nvt_all_0 omp_get_nvt_all_0.c)
set_target_properties (omp_get_nvt_all_0 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_nvt_all_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_nvt_all_0 common)
add_test (omp_get_nvt_all_0 omp_get_nvt_all_0)

add_executable (omp_get_nvt_all_1 omp_get_nvt_all_1.c)
set_target_properties (omp_get_nvt_all_1 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_nvt_all_1 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_nvt_all_1 common)
add_test (omp_get_nvt_all_1 omp_get_nvt_all_1)

add_executable (omp_get_nvt_details_0 omp_get_nvt_details_0.c)
set_target_properties (omp_get_nvt_details_0 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_nvt_details_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_nvt_details_0 common)
add_test (omp_get_nvt_details_0 omp_get_nvt_details_0)

add_executable (omp_get_nvt_details_1 omp_get_nvt_details_1.c)
set_target_properties (omp_get_nvt_details_1 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_nvt_details_1 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_nvt_details_1 common)
add_test (omp_get_nvt_details_1 omp_get_nvt_details_1)

add_executable (omp_get_nvt_details_2 omp_get_nvt_details_2.c)
set_target_properties (omp_get_nvt_details_2 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_nvt_details_2 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_nvt_details_2 common)
add_test (omp_get_nvt_details_2 omp_get_nvt_details_2)

add_executable (omp_get_nvt_details_3 omp_get_nvt_details_3.c)
set_target_properties (omp_get_nvt_details_3 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_nvt_details_3 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_nvt_details_3 common)
add_test (omp_get_nvt_details_3 omp_get_nvt_details_3)

add_executable (omp_get_nvt_details_4 omp_get_nvt_details_4.c)
set_target_properties (omp_get_nvt_details_4 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_nvt_details_4 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_nvt_details_4 common)
add_test (omp_get_nvt_details_4 omp_get_nvt_details_4)

add_executable (omp_get_nvt_feed_checksum_0 omp_get_nvt_feed_checksum_0.c)
set_target_properties (omp_get_nvt_feed_checksum_0 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_nvt_feed_checksum_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_nvt_feed_checksum_0 common)
add_test (omp_get_nvt_feed_checksum_0 omp_get_nvt_feed_checksum_0)

add_executable (omp_get_nvt_feed_checksum_1 omp_get_nvt_feed_checksum_1.c)
set_target_properties (omp_get_nvt_feed_checksum_1 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_nvt_feed_checksum_1 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_nvt_feed_checksum_1 common)
add_test (omp_get_nvt_feed_checksum_1 omp_get_nvt_feed_checksum_1)

add_executable (omp_get_nvt_feed_checksum_2 omp_get_nvt_feed_checksum_2.c)
set_target_properties (omp_get_nvt_feed_checksum_2 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_nvt_feed_checksum_2 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_nvt_feed_checksum_2 common)
add_test (omp_get_nvt_feed_checksum_2 omp_get_nvt_feed_checksum_2)

add_executable (omp_get_nvt_feed_checksum_3 omp_get_nvt_feed_checksum_3.c)
set_target_properties (omp_get_nvt_feed_checksum_3 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_nvt_feed_checksum_3 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_nvt_feed_checksum_3 common)
add_test (omp_get_nvt_feed_checksum_3 omp_get_nvt_feed_checksum_3)

add_executable (omp_get_nvt_feed_checksum_4 omp_get_nvt_feed_checksum_4.c)
set_target_properties (omp_get_nvt_feed_checksum_4 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_nvt_feed_checksum_4 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_nvt_feed_checksum_4 common)
add_test (omp_get_nvt_feed_checksum_4 omp_get_nvt_feed_checksum_4)

add_executable (omp_get_nvt_feed_checksum_5 omp_get_nvt_feed_checksum_5.c)
set_target_properties (omp_get_nvt_feed_checksum_5 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_nvt_feed_checksum_5 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_nvt_feed_checksum_5 common)
add_test (omp_get_nvt_feed_checksum_5 omp_get_nvt_feed_checksum_5)

add_executable (omp_get_preferences_0 omp_get_preferences_0.c)
set_target_properties (omp_get_preferences_0 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_preferences_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_preferences_0 common)
add_test (omp_get_preferences_0 omp_get_preferences_0)

add_executable (omp_get_preferences_1 omp_get_preferences_1.c)
set_target_properties (omp_get_preferences_1 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_preferences_1 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_preferences_1 common)
add_test (omp_get_preferences_1 omp_get_preferences_1)

add_executable (omp_get_preferences_2 omp_get_preferences_2.c)
set_target_properties (omp_get_preferences_2 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_preferences_2 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_preferences_2 common)
add_test (omp_get_preferences_2 omp_get_preferences_2)

add_executable (omp_get_report_0 omp_get_report_0.c)
set_target_properties (omp_get_report_0 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_report_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_report_0 common)
add_test (omp_get_report_0 omp_get_report_0)

add_executable (omp_get_report_1 omp_get_report_1.c)
set_target_properties (omp_get_report_1 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_report_1 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_report_1 common)
add_test (omp_get_report_1 omp_get_report_1)

add_executable (omp_get_report_2 omp_get_report_2.c)
set_target_properties (omp_get_report_2 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_report_2 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_report_2 common)
add_test (omp_get_report_2 omp_get_report_2)

add_executable (omp_get_report_3 omp_get_report_3.c)
set_target_properties (omp_get_report_3 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_report_3 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_report_3 common)
add_test (omp_get_report_3 omp_get_report_3)

add_executable (omp_get_report_4 omp_get_report_4.c)
set_target_properties (omp_get_report_4 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_report_4 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_report_4 common)
add_test (omp_get_report_4 omp_get_report_4)

add_executable (omp_get_report_5 omp_get_report_5.c)
set_target_properties (omp_get_report_5 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_report_5 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_report_5 common)
add_test (omp_get_report_5 omp_get_report_5)

add_executable (omp_get_report_6 omp_get_report_6.c)
set_target_properties (omp_get_report_6 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_report_6 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_report_6 common)
add_test (omp_get_report_6 omp_get_report_6)

add_executable (omp_get_report_7 omp_get_report_7.c)
set_target_properties (omp_get_report_7 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_report_7 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_report_7 common)
add_test (omp_get_report_7 omp_get_report_7)

add_executable (omp_get_report_8 omp_get_report_8.c)
set_target_properties (omp_get_report_8 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_report_8 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_report_8 common)
add_test (omp_get_report_8 omp_get_report_8)

add_executable (omp_get_rules_0 omp_get_rules_0.c)
set_target_properties (omp_get_rules_0 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_rules_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_rules_0 common)
add_test (omp_get_rules_0 omp_get_rules_0)

add_executable (omp_get_rules_1 omp_get_rules_1.c)
set_target_properties (omp_get_rules_1 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_rules_1 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_rules_1 common)
add_test (omp_get_rules_1 omp_get_rules_1)

add_executable (omp_get_status_0 omp_get_status_0.c)
set_target_properties (omp_get_status_0 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_status_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_status_0 common)
add_test (omp_get_status_0 omp_get_status_0)

add_executable (omp_get_status_1 omp_get_status_1.c)
set_target_properties (omp_get_status_1 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_status_1 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_status_1 common)
add_test (omp_get_status_1 omp_get_status_1)

add_executable (omp_get_status_2 omp_get_status_2.c)
set_target_properties (omp_get_status_2 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_status_2 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_status_2 common)
add_test (omp_get_status_2 omp_get_status_2)

add_executable (omp_get_status_3 omp_get_status_3.c)
set_target_properties (omp_get_status_3 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_status_3 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_status_3 common)
add_test (omp_get_status_3 omp_get_status_3)

add_executable (omp_get_status_4 omp_get_status_4.c)
set_target_properties (omp_get_status_4 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_status_4 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_status_4 common)
add_test (omp_get_status_4 omp_get_status_4)

add_executable (omp_get_status_5 omp_get_status_5.c)
set_target_properties (omp_get_status_5 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_status_5 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_status_5 common)
add_test (omp_get_status_5 omp_get_status_5)

add_executable (omp_get_version_0 omp_get_version_0.c)
set_target_properties (omp_get_version_0 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_get_version_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_get_version_0 common)
add_test (omp_get_version_0 omp_get_version_0)

add_executable (omp_help_0 omp_help_0.c)
set_target_properties (omp_help_0 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_help_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_help_0 common)
add_test (omp_help_0 omp_help_0)

add_executable (omp_help_1 omp_help_1.c)
set_target_properties (omp_help_1 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_help_1 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_help_1 common)
add_test (omp_help_1 omp_help_1)

add_executable (omp_modify_report_0 omp_modify_report_0.c)
set_target_properties (omp_modify_report_0 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_modify_report_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_modify_report_0 common)
add_test (omp_modify_report_0 omp_modify_report_0)

add_executable (omp_modify_task_0 omp_modify_task_0.c)
set_target_properties (omp_modify_task_0 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_modify_task_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_modify_task_0 common)
add_test (omp_modify_task_0 omp_modify_task_0)

add_executable (omp_modify_task_1 omp_modify_task_1.c)
set_target_properties (omp_modify_task_1 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_modify_task_1 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_modify_task_1 common)
add_test (omp_modify_task_1 omp_modify_task_1)

add_executable (omp_start_task_0 omp_start_task_0.c)
set_target_properties (omp_start_task_0 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_start_task_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_start_task_0 common)
add_test (omp_start_task_0 omp_start_task_0)

add_executable (omp_start_task_1 omp_start_task_1.c)
set_target_properties (omp_start_task_1 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_start_task_1 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_start_task_1 common)
add_test (omp_start_task_1 omp_start_task_1)

add_executable (omp_start_task_2 omp_start_task_2.c)
set_target_properties (omp_start_task_2 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_start_task_2 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_start_task_2 common)
add_test (omp_start_task_2 omp_start_task_2)

add_executable (omp_start_task_3 omp_start_task_3.c)
set_target_properties (omp_start_task_3 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_start_task_3 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_start_task_3 common)
add_test (omp_start_task_3 omp_start_task_3)

add_executable (omp_start_task_4 omp_start_task_4.c)
set_target_properties (omp_start_task_4 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_start_task_4 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_start_task_4 common)
add_test (omp_start_task_4 omp_start_task_4)

add_executable (omp_start_task_5 omp_start_task_5.c)
set_target_properties (omp_start_task_5 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (omp_start_task_5 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (omp_start_task_5 common)
add_test (omp_start_task_5 omp_start_task_5)

## Tests of the manager

add_executable (read_protocol_0 read_protocol_0.c)
set_target_properties (read_protocol_0 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (read_protocol_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (read_protocol_0 common)
add_test (read_protocol_0 read_protocol_0)

add_executable (timeout_0 timeout_0.c)
set_target_properties (timeout_0 PROPERTIES COMPILE_FLAGS "${GLIB_CFLAGS} ${OVAS_CFLAGS}")
set_target_properties (timeout_0 PROPERTIES LINK_FLAGS "${OVAS_LDFLAG} ${GLIB_LDFLAGS}")
target_link_libraries (timeout_0 common)
add_test (timeout_0 timeout_0)

## Report Format tests

add_subdirectory (report_formats)

## End
