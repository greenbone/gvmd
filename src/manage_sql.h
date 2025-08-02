/* Copyright (C) 2010-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * @file
 * @brief Manager Manage library: SQL backend headers.
 */

#ifndef _GVMD_MANAGE_SQL_H
#define _GVMD_MANAGE_SQL_H

#include <gvm/util/xmlutils.h>
#include <time.h>

#include "manage.h"
#include "manage_utils.h"


/* Internal types and preprocessor definitions. */

/**
 * @brief Location of a constituent of a trashcan resource.
 */
#define LOCATION_TABLE 0

/**
 * @brief Location of a constituent of a trashcan resource.
 */
#define LOCATION_TRASH 1

/**
 * @brief UUID of 'All' NVT selector.
 */
#define MANAGE_NVT_SELECTOR_UUID_ALL "54b45713-d4f4-4435-b20d-304c175ed8c5"

/**
 * @brief Predefined role UUID.
 */
#define PERMISSION_UUID_ADMIN_EVERYTHING "b3b56a8c-c2fd-11e2-a135-406186ea4fc5"

/**
 * @brief Predefined role UUID.
 */
#define PERMISSION_UUID_SUPER_ADMIN_EVERYTHING "a9801074-6fe2-11e4-9d81-406186ea4fc5"

/**
 * @brief Predefined role UUID.
 */
#define ROLE_UUID_ADMIN "7a8cb5b4-b74d-11e2-8187-406186ea4fc5"

/**
 * @brief Predefined role UUID.
 */
#define ROLE_UUID_GUEST "cc9cac5e-39a3-11e4-abae-406186ea4fc5"

/**
 * @brief Predefined role UUID.
 */
#define ROLE_UUID_INFO "5f8fd16c-c550-11e3-b6ab-406186ea4fc5"

/**
 * @brief Predefined role UUID.
 */
#define ROLE_UUID_MONITOR "12cdb536-480b-11e4-8552-406186ea4fc5"

/**
 * @brief Predefined role UUID.
 */
#define ROLE_UUID_USER "8d453140-b74d-11e2-b0be-406186ea4fc5"

/**
 * @brief Predefined role UUID.
 */
#define ROLE_UUID_SUPER_ADMIN "9c5a6ec6-6fe2-11e4-8cb6-406186ea4fc5"

/**
 * @brief Predefined role UUID.
 */
#define ROLE_UUID_OBSERVER "87a7ebce-b74d-11e2-a81f-406186ea4fc5"

/**
 * @brief UUID of 'OpenVAS Default' scanner.
 */
#define SCANNER_UUID_DEFAULT "08b69003-5fc2-4037-a479-93b440211c73"

/**
 * @brief UUID of 'openvasd Default' scanner.
 */
#define SCANNER_UUID_OPENVASD_DEFAULT "8154d8e3-30ee-4959-9151-1863c89a8e62"

/**
 * @brief UUID of 'CVE' scanner.
 */
#define SCANNER_UUID_CVE "6acd0832-df90-11e4-b9d5-28d24461215b"

/**
 * @brief Trust constant for error.
 */
#define TRUST_ERROR 0

/**
 * @brief Trust constant for yes.
 */
#define TRUST_YES 1

/**
 * @brief Trust constant for no.
 */
#define TRUST_NO 2

/**
 * @brief Trust constant for unknown.
 */
#define TRUST_UNKNOWN 3

/**
 * @brief Number of milliseconds between timevals a and b (performs a-b).
 */
#define TIMEVAL_SUBTRACT_MS(a,b) ((((a).tv_sec - (b).tv_sec) * 1000) + \
                                  ((a).tv_usec - (b).tv_usec) / 1000)

/**
 * @brief Database superuser role
 */
#define DB_SUPERUSER_ROLE "dba"


/* Macros. */

/**
 * @brief Write to a file or close stream and exit.
 *
 * @param[in]   stream    Stream to write to.
 * @param[in]   format    Format specification.
 * @param[in]   args      Arguments.
 */
#define PRINT(stream, format, args...)                                       \
  do                                                                         \
    {                                                                        \
      gchar *msg;                                                            \
      msg = g_markup_printf_escaped (format, ## args);                       \
      if (fprintf (stream, "%s", msg) < 0)                                   \
        {                                                                    \
          g_free (msg);                                                      \
          fclose (stream);                                                   \
          return -1;                                                         \
        }                                                                    \
      g_free (msg);                                                          \
    }                                                                        \
  while (0)


/* Iterator definitions. */

/**
 * @brief Delta results columns offset for result iterator.
 */
#define RESULT_ITERATOR_DELTA_COLUMN_OFFSET GET_ITERATOR_COLUMN_COUNT + 46


/* Variables */

extern db_conn_info_t gvmd_db_conn_info;

/**
 * @brief Function to fork a connection that will accept GMP requests.
 */
extern manage_connection_forker_t manage_fork_connection;


/* Function prototypes */

typedef long long int rowid_t;

int
manage_db_empty ();

gboolean
host_nthlast_report_host (const char *, report_host_t *, int);

char *
report_host_ip (const char *);

gchar *
report_host_hostname (report_host_t);

gchar *
report_host_best_os_cpe (report_host_t);

gchar *
report_host_best_os_txt (report_host_t);

gchar *
report_creation_time (report_t);

gchar *
report_modification_time (report_t);

gchar *
report_start_time (report_t);

gchar *
report_end_time (report_t);

void
trim_report (report_t);

int
delete_report_internal (report_t);

int
set_report_scan_run_status (report_t, task_status_t);

int
update_report_modification_time (report_t);

int
set_report_slave_progress (report_t, int);

void
init_task_file_iterator (iterator_t *, task_t, const char *);

const char *
task_file_iterator_name (iterator_t *);

const char *
task_file_iterator_content (iterator_t *);

void
set_task_schedule_next_time (task_t, time_t);

void
set_task_schedule_next_time_uuid (const gchar *, time_t);

void
init_preference_iterator (iterator_t *, config_t, const char *);

const char *
preference_iterator_name (iterator_t *);

const char *
preference_iterator_value (iterator_t *);

port_list_t
target_port_list (target_t);

credential_t
target_ssh_credential (target_t);

credential_t
target_smb_credential (target_t);

credential_t
target_esxi_credential (target_t);

credential_t
target_ssh_elevate_credential (target_t);

credential_t
target_krb5_credential (target_t);

int
create_current_report (task_t, char **, task_status_t);

int
init_task_schedule_iterator (iterator_t *);

void
cleanup_task_schedule_iterator (iterator_t *);

task_t
task_schedule_iterator_task (iterator_t *);

const char *
task_schedule_iterator_task_uuid (iterator_t *);

schedule_t task_schedule_iterator_schedule (iterator_t *);

const char *
task_schedule_iterator_icalendar (iterator_t *);

const char *
task_schedule_iterator_timezone (iterator_t *);

const char *
task_schedule_iterator_owner_uuid (iterator_t *);

const char *
task_schedule_iterator_owner_name (iterator_t *);

gboolean
task_schedule_iterator_timed_out (iterator_t *);

gboolean
task_schedule_iterator_start_due (iterator_t *);

gboolean
task_schedule_iterator_stop_due (iterator_t *);

time_t
task_schedule_iterator_initial_offset (iterator_t *);

int
set_task_schedule_uuid (const gchar*, schedule_t, int);

void
reinit_manage_process ();

int
manage_update_nvti_cache ();

int
manage_report_host_details (report_t, const char *, entity_t, GHashTable *);

const char *
run_status_name_internal (task_status_t);

void
update_config_cache_init (const char *);

alive_test_t
target_alive_tests (target_t);

void
manage_session_init (const char *);

void
check_generate_scripts ();

void
auto_delete_reports ();

int
parse_iso_time (const char *);

void
set_report_scheduled (report_t);

gchar *
resource_uuid (const gchar *, resource_t);

gboolean
find_resource_with_permission (const char *, const char *,
                                        resource_t *, const char *, int);

int
resource_predefined (const gchar *, resource_t);

void
parse_osp_report (task_t, report_t, const char *);

void
reschedule_task (const gchar *);

void
insert_port_range (port_list_t, port_protocol_t, int, int);

int
manage_cert_db_exists ();

int
manage_scap_db_exists ();

int
cert_check_time ();

int
scap_check_time ();

int
nvts_check_time ();

int
count (const char *, const get_data_t *, column_t *, column_t *, const char **,
       int, const char *, const char *, int);

int
init_get_iterator (iterator_t*, const char *, const get_data_t *, column_t *,
                   column_t *, const char **, int, const char *, const char *,
                   int);

int
openvasd_get_details_from_iterator (iterator_t *, char **, GSList **);

int
agent_control_get_details_from_iterator (iterator_t *, char **, GSList **);

gchar *
columns_build_select (column_t *);

gchar*
filter_term_sql (const char *);

gchar *
filter_clause (const char*, const char*, const char **, column_t *,
               column_t *, int, int, gchar **, int *, int *, array_t **,
               gchar **);

void
check_alerts ();

int
manage_option_setup (GSList *, const db_conn_info_t *, int);

void
manage_option_cleanup ();

void
update_all_config_caches ();

int
task_report_previous (task_t, report_t, report_t *);

int
task_last_report_any_status (task_t, report_t *);

int
task_second_last_report (task_t, report_t *);

double
task_severity_double (task_t, int, int, int);

gboolean
find_trash (const char *, const char *, resource_t *);

void
tags_remove_resource (const char *, resource_t, int);

void
tags_set_locations (const char *, resource_t, resource_t, int);

void
permissions_set_locations (const char *, resource_t, resource_t, int);

void
permissions_set_orphans (const char *, resource_t, int);

int
copy_resource (const char *, const char *, const char *, const char *,
               const char *, int, resource_t *, resource_t *);

gboolean
resource_with_name_exists (const char *, const char *, resource_t);

int
create_permission_internal (int, const char *, const char *, const char *,
                            const char *, const char *, const char *,
                            permission_t *);

int
create_permission_no_acl (const char *, const char *, const char *, const char *,
                          const char *, const char *, permission_t *);

int
copy_resource_lock (const char *, const char *, const char *, const char *,
                    const char *, int, resource_t *, resource_t *);

nvti_t *
lookup_nvti (const gchar *);

int
setting_value_sql (const char *, char **);

int
setting_value_int_sql (const char *, int *);

void
add_role_permission_resource (const gchar *, const gchar *, const gchar *,
                              const gchar *);

void
create_view_vulns ();

void
create_indexes_nvt ();

void
create_view_result_vt_epss ();

int
config_family_entire_and_growing (config_t, const char*);

void
reports_clear_count_cache_dynamic ();

int
cleanup_config_sequences ();

int
cleanup_port_list_sequences ();

int
cleanup_nvt_sequences ();

int
cleanup_ids_for_table (const char *);

void

create_indexes_cpe ();

void
drop_indexes_cpe ();

void
create_indexes_cve ();

void
drop_indexes_cve ();

void
report_set_processing_required (report_t, int, int);

int
process_report_import (report_t);

#if OPENVASD
void
parse_openvasd_report (task_t, report_t, GSList *, time_t, time_t);
#endif

#endif /* not _GVMD_MANAGE_SQL_H */
