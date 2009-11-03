/* OpenVAS Manager
 * $Id$
 * Description: Headers for OpenVAS Manager: the Manage library.
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
 *
 * Copyright:
 * Copyright (C) 2009 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * or, at your option, any later version as published by the Free
 * Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef OPENVAS_MANAGER_MANAGE_H
#define OPENVAS_MANAGER_MANAGE_H

#include <stdio.h>
#include <glib.h>
#include <ossp/uuid.h>

#include <openvas/base/certificate.h> /* for certificate_t */
#include <openvas/base/nvti.h> /* for nvti_t */

/**
 * @brief Structure of information about the scanner.
 */
typedef struct
{
  certificates_t* certificates;      ///< List of certificates.
  char* plugins_md5;                 ///< MD5 sum over all tests.
  GHashTable* plugins_dependencies;  ///< Dependencies between plugins.
  GPtrArray* rules;                  ///< Scanner rules.
  int rules_size;                    ///< Number of rules.
} scanner_t;

// FIX for omp.c,manage.c,otp.c access to server info (rules, prefs, ...)
/**
 * @brief Information about the server.
 */
extern scanner_t scanner;

int
init_manage (GSList*, int, const gchar*);

void
init_manage_process (int, const gchar*);

void
cleanup_manage_process ();


/* Credentials. */

/**
 * @brief A username password pair.
 */
typedef struct
{
  /*@null@*/ gchar* username; ///< Login name of user.
  /*@null@*/ gchar* password; ///< Password of user.
} credentials_t;

extern credentials_t current_credentials;

void
free_credentials (credentials_t*);

void
append_to_credentials_username (credentials_t*, const char*, gsize);

void
append_to_credentials_password (credentials_t*, const char*, gsize);

int
authenticate (credentials_t*);


/* Database migration. */

int
manage_db_supported_version ();

int
manage_db_version ();

int
manage_migrate (GSList*, const gchar*);


/* Task structures. */

extern short scanner_active;

// FIX should be in otp.c/h
/**
 * @brief Possible port types.
 */
typedef enum
{
  PORT_PROTOCOL_TCP,
  PORT_PROTOCOL_UDP,
  PORT_PROTOCOL_OTHER
} port_protocol_t;

// FIX should be in otp.c/h
/**
 * @brief A port.
 */
typedef struct
{
  unsigned int number;       ///< Port number.
  port_protocol_t protocol;  ///< Port protocol (TCP, UDP, ...).
  char* string;              ///< Original string describing port.
} port_t;

// FIX should be in otp.c/h
/**
 * @brief The record of a message.
 */
typedef struct
{
  char* subnet;         ///< Subnet message describes.
  char* host;           ///< Host message describes.
  port_t port;          ///< The port.
  char* description;    ///< Description of the message.
  char* oid;            ///< NVT identifier.
} message_t;

typedef enum
{
  TASK_STATUS_DELETE_REQUESTED,
  TASK_STATUS_DONE,
  TASK_STATUS_NEW,
  TASK_STATUS_REQUESTED,
  TASK_STATUS_RUNNING,
  TASK_STATUS_STOP_REQUESTED,
  TASK_STATUS_STOPPED,
  TASK_STATUS_INTERNAL_ERROR
} task_status_t;

#ifdef TASKS_SQL
typedef long long int task_t;
typedef long long int result_t;
typedef long long int report_t;
typedef long long int nvt_t;

#include <sqlite3.h>

// FIX use iterator_t
typedef struct
{
  sqlite3_stmt* stmt;
  gboolean done;
} task_iterator_t;

typedef struct
{
  sqlite3_stmt* stmt;
  gboolean done;
} iterator_t;
#else /* not TASKS_SQL */
typedef long long int task_t;
typedef long long int result_t;
typedef long long int report_t;
typedef long long int nvt_t;

typedef struct
{
  void* stmt;
  gboolean done;
} task_iterator_t;

typedef struct
{
  void* stmt;
  gboolean done;
} iterator_t;
#endif /* not TASKS_SQL */


/* Task global variables. */

/**
 * @brief The task currently running on the scanner.
 */
extern /*@null@*/ task_t current_scanner_task;

extern /*@null@*/ report_t current_report;


/* Task code specific to the representation of tasks. */

unsigned int
task_count ();

void
init_task_iterator (task_iterator_t*, int, const char*);

void
cleanup_task_iterator (task_iterator_t*);

gboolean
next_task (task_iterator_t*, task_t*);

unsigned int
task_id (task_t);

int
task_uuid (task_t, /*@out@*/ char **);

char*
task_name (task_t);

char*
task_comment (task_t);

char*
task_config (task_t);

void
set_task_config (task_t, const char*);

char*
task_target (task_t);

void
set_task_target (task_t, const char*);

char*
task_description (task_t);

void
set_task_description (task_t, char*, gsize);

task_status_t
task_run_status (task_t);

void
set_task_run_status (task_t, task_status_t);

report_t
task_running_report (task_t);

char*
task_start_time (task_t);

void
set_task_start_time (task_t task, char* time);

char*
task_end_time (task_t);

void
set_task_end_time (task_t task, char* time);

unsigned int
task_report_count (task_t);

unsigned int
task_finished_report_count (task_t);

void
set_scan_attack_state (report_t, const char*, const char*);

int
task_debugs_size (task_t);

int
task_holes_size (task_t);

int
task_infos_size (task_t);

int
task_logs_size (task_t);

int
task_warnings_size (task_t);

void
free_tasks ();

/*@null@*/ /*@dependent@*/ /*@special@*/
task_t
make_task (/*@only@*/ char*, unsigned int, /*@only@*/ char*)
  /*@defines result->open_ports@*/
  /*@ensures isnull result->description@*/;

int
load_tasks ();

int
save_tasks ();

/*@dependent@*/
gboolean
find_task (const char* id, task_t*);

void
reset_task (task_t);

int
set_task_parameter (task_t,
                    /*@null@*/ const char*,
                    /*@null@*/ /*@only@*/ char*);

int
request_delete_task (task_t*);

int
delete_task (task_t);

int
append_to_task_comment (task_t, const char*, int);

int
append_to_task_config (task_t, const char*, int);

int
append_to_task_name (task_t, const char*, int);

int
append_to_task_target (task_t, const char*, int);

int
add_task_description_line (task_t, const char*, size_t);

void
set_scan_ports (report_t, const char*, unsigned int, unsigned int);

void
append_task_open_port (task_t, unsigned int, char*);

int
make_task_rcfile (task_t);

void
manage_task_update_file (task_t, const char *, const void *);

int
manage_task_remove_file (task_t, const char *);

void
init_config_file_iterator (iterator_t*, const char*, const char*);

const char*
config_file_iterator_content (iterator_t*);

int
config_file_iterator_length (iterator_t*);


/* General task facilities. */

char*
make_task_uuid ();

const char*
run_status_name (task_status_t status);

const char*
task_run_status_name (task_t task);

int
start_task (task_t, char**);

int
stop_task (task_t);


/* Iteration. */

void
cleanup_iterator (iterator_t*);

gboolean
next (iterator_t*);


/* Reports. */

// FIX how is this doc'd?
#define OVAS_MANAGE_REPORT_ID_LENGTH UUID_LEN_STR

gboolean
find_report (const char*, report_t*);

result_t
make_result (task_t, const char*, const char*, const char*, const char*,
             const char*, const char*);

void
report_add_result (report_t, result_t);

char*
report_uuid (report_t);

int
report_holes (report_t, const char*, int*);

int
report_notes (report_t, const char*, int*);

int
report_warnings (report_t, const char*, int*);

/*@-exportlocal@*/
/*@only@*/ /*@null@*/
char*
make_report_uuid ();

gchar*
task_first_report_id (task_t);

gchar*
task_last_report_id (task_t);

gchar*
task_second_last_report_id (task_t);

gchar*
report_path_task_uuid (gchar*);

gboolean
report_task (report_t, task_t*);
/*@=exportlocal@*/

int
report_scan_run_status (report_t, int*);

int
report_scan_result_count (report_t, int*);

int
report_counts (const char*, int*, int*, int*, int*, int*);

char*
scan_start_time (report_t);

void
set_scan_start_time (report_t, const char*);

char*
scan_end_time (report_t);

void
set_scan_end_time (report_t, const char*);

void
set_scan_host_start_time (report_t, const char*, const char*);

void
set_scan_host_end_time (report_t, const char*, const char*);

int
report_timestamp (const char*, gchar**);

int
delete_report (report_t);

int
set_report_parameter (report_t, const char*, char*);

void
init_report_iterator (iterator_t*, task_t);

void
init_result_iterator (iterator_t*, task_t, const char*, int, int);

gboolean
next_report (iterator_t*, report_t*);

const char*
result_iterator_subnet (iterator_t*);

const char*
result_iterator_host (iterator_t*);

const char*
result_iterator_port (iterator_t*);

const char*
result_iterator_nvt (iterator_t*);

const char*
result_iterator_type (iterator_t*);

const char*
result_iterator_descr (iterator_t*);

void
init_host_iterator (iterator_t*, report_t);

const char*
host_iterator_host (iterator_t*);

const char*
host_iterator_start_time (iterator_t*);

const char*
host_iterator_end_time (iterator_t*);

const char*
host_iterator_attack_state (iterator_t*);

int
host_iterator_current_port (iterator_t*);

int
host_iterator_max_port (iterator_t*);


/* RC's. */

char*
rc_preference (const char*, const char*);


/* Targets. */

int
create_target (const char*, const char*, const char*);

int
delete_target (const char*);

void
init_target_iterator (iterator_t*, int, const char*);

const char*
target_iterator_name (iterator_t*);

const char*
target_iterator_hosts (iterator_t*);

const char*
target_iterator_comment (iterator_t*);

char*
target_hosts (const char*);

int
target_in_use (const char*);


/* Configs. */

int
create_config (const char*, const char*, char*);

int
delete_config (const char*);

void
init_config_iterator (iterator_t*, const char*, int, const char*);

const char*
config_iterator_name (iterator_t*);

const char*
config_iterator_nvt_selector (iterator_t*);

const char*
config_iterator_comment (iterator_t*);

int
config_iterator_nvts_growing (iterator_t*);

int
config_iterator_families_growing (iterator_t*);

char*
config_nvt_selector (const char*);

int
config_in_use (const char*);


/* NVT's. */

int
nvts_size ();

char*
nvts_md5sum ();

void
set_nvts_md5sum (const char*);

nvt_t
make_nvt_from_nvti (const nvti_t*);

gboolean
find_nvt (const char*, nvt_t*);

void
init_nvt_iterator (iterator_t*, nvt_t, const char*, const char*, int,
                   const char*);

const char*
nvt_iterator_oid (iterator_t*);

const char*
nvt_iterator_version (iterator_t*);

const char*
nvt_iterator_name (iterator_t*);

const char*
nvt_iterator_summary (iterator_t*);

const char*
nvt_iterator_description (iterator_t*);

const char*
nvt_iterator_copyright (iterator_t*);

const char*
nvt_iterator_cve (iterator_t*);

const char*
nvt_iterator_bid (iterator_t*);

const char*
nvt_iterator_xref (iterator_t*);

const char*
nvt_iterator_tag (iterator_t*);

const char*
nvt_iterator_sign_key_ids (iterator_t*);

int
nvt_iterator_category (iterator_t*);

const char*
nvt_iterator_family (iterator_t*);

int
family_nvt_count (const char *);


/* NVT selectors. */

int
nvt_selector_families_growing (const char*);

int
nvt_selector_nvts_growing (const char*);

int
nvt_selector_family_count (const char*, const char*);

int
nvt_selector_nvt_count (const char*, const char*);

void
init_family_iterator (iterator_t*, int, const char*, int);

const char*
family_iterator_name (iterator_t*);

int
nvt_selector_family_growing (const char *, const char *, int);

int
nvt_selector_family_selected_count (const char *, const char *, int);


/* NVT preferences. */

void
manage_nvt_preference_add (const char*, const char*);

void
manage_nvt_preferences_enable ();

void
init_nvt_preference_iterator (iterator_t*, const char*);

const char*
nvt_preference_iterator_name (iterator_t*);

const char*
nvt_preference_iterator_value (iterator_t*);

char*
nvt_preference_iterator_config_value (iterator_t*, const char*);

char*
nvt_preference_iterator_real_name (iterator_t*);

char*
nvt_preference_iterator_type (iterator_t*);

char*
nvt_preference_iterator_nvt (iterator_t*);

void
init_config_pref_iterator (iterator_t*, const char*, const char*);

const char*
config_pref_iterator_name (iterator_t*);

const char*
config_pref_iterator_value (iterator_t*);

int
nvt_preference_count (const char *);


/* LSC credentials. */

int
create_lsc_credential (const char*, const char*);

int
delete_lsc_credential (const char*);

void
init_lsc_credential_iterator (iterator_t*, const char*, int, const char*);

const char*
lsc_credential_iterator_name (iterator_t*);

const char*
lsc_credential_iterator_comment (iterator_t*);

const char*
lsc_credential_iterator_public_key (iterator_t*);

const char*
lsc_credential_iterator_private_key (iterator_t*);

const char*
lsc_credential_iterator_rpm (iterator_t*);

const char*
lsc_credential_iterator_deb (iterator_t*);

const char*
lsc_credential_iterator_exe (iterator_t*);


/* Scanner messaging. */

int
request_certificates ();

int
acknowledge_bye ();

int
acknowledge_md5sum ();

int
acknowledge_md5sum_sums ();

int
acknowledge_md5sum_info ();

int
manage_check_current_task ();

#endif /* not OPENVAS_MANAGER_MANAGE_H */
