/* OpenVAS Manager
 * $Id$
 * Description: Headers for OpenVAS Manager: the Manage library.
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
 *
 * Copyright:
 * Copyright (C) 2009, 2010 Greenbone Networks GmbH
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
#include <gnutls/gnutls.h>

#include <openvas/openvas_auth.h>
#include <openvas/base/array.h> /* for array_t */
#include <openvas/base/certificate.h> /* for certificate_t */
#include <openvas/base/credentials.h>
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
cleanup_manage_process (gboolean);

void
manage_cleanup_process_error (int);


/* Credentials. */

extern credentials_t current_credentials;

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


/**
 * @brief Task statuses, also used as scan/report statuses.
 *
 * These numbers are used in the database, so if the number associated with
 * any symbol changes then a migrator must be added to update existing data.
 */
typedef enum
{
  TASK_STATUS_DELETE_REQUESTED = 0,
  TASK_STATUS_DONE = 1,
  TASK_STATUS_NEW  = 2,
  TASK_STATUS_REQUESTED = 3,
  TASK_STATUS_RUNNING   = 4,
  TASK_STATUS_PAUSE_REQUESTED = 5,
  TASK_STATUS_PAUSE_WAITING   = 6,
  TASK_STATUS_PAUSED = 7,
  TASK_STATUS_RESUME_REQUESTED = 8,
  TASK_STATUS_RESUME_WAITING   = 9,
  TASK_STATUS_STOP_REQUESTED   = 10,
  TASK_STATUS_STOP_WAITING     = 11,
  TASK_STATUS_STOPPED = 12,
  TASK_STATUS_INTERNAL_ERROR = 13
} task_status_t;

typedef long long int agent_t;
typedef long long int config_t;
typedef long long int escalator_t;
typedef long long int target_t;
typedef long long int task_t;
typedef long long int result_t;
typedef long long int report_t;
typedef long long int note_t;
typedef long long int nvt_t;
typedef long long int lsc_credential_t;
typedef long long int schedule_t;

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


/* Events and Escalators. */

/**
 * @brief Types of task events.
 */
typedef enum
{
  EVENT_ERROR,
  EVENT_TASK_RUN_STATUS_CHANGED
} event_t;

/**
 * @brief Types of escalators.
 */
typedef enum
{
  ESCALATOR_METHOD_ERROR,
  ESCALATOR_METHOD_EMAIL
} escalator_method_t;

/**
 * @brief Types of escalator conditions.
 */
typedef enum
{
  ESCALATOR_CONDITION_ERROR,
  ESCALATOR_CONDITION_ALWAYS,
  ESCALATOR_CONDITION_THREAT_LEVEL_AT_LEAST,
  ESCALATOR_CONDITION_THREAT_LEVEL_CHANGED
} escalator_condition_t;

int
create_escalator (const char*, const char*, event_t, GPtrArray*,
                  escalator_condition_t, GPtrArray*, escalator_method_t,
                  GPtrArray*);

int
delete_escalator (escalator_t);

gboolean
find_escalator (const char*, escalator_t*);

int
escalate (escalator_t, task_t, event_t, const void*);

void
init_escalator_iterator (iterator_t*, escalator_t, task_t, event_t, int,
                         const char*);

escalator_t
escalator_iterator_escalator (iterator_t*);

const char*
escalator_iterator_name (iterator_t*);

int
escalator_iterator_in_use (iterator_t*);

const char *
escalator_iterator_comment (iterator_t*);

int
escalator_iterator_event (iterator_t*);

int
escalator_iterator_condition (iterator_t*);

int
escalator_iterator_method (iterator_t*);

const char*
escalator_condition_name (escalator_condition_t);

gchar*
escalator_condition_description (escalator_condition_t, escalator_t);

const char*
event_name (event_t);

gchar*
event_description (event_t, const void *);

const char*
escalator_method_name (escalator_method_t);

escalator_condition_t
escalator_condition_from_name (const char*);

event_t
event_from_name (const char*);

escalator_method_t
escalator_method_from_name (const char*);

void
init_escalator_data_iterator (iterator_t *, escalator_t, const char *);

const char*
escalator_data_iterator_name (iterator_t*);

const char*
escalator_data_iterator_data (iterator_t*);

void
init_escalator_task_iterator (iterator_t*, escalator_t, int);

const char*
escalator_task_iterator_name (iterator_t*);

const char*
escalator_task_iterator_uuid (iterator_t*);


/* Task global variables and preprocessor variables. */

/**
 * @brief The task currently running on the scanner.
 */
extern /*@null@*/ task_t current_scanner_task;

extern /*@null@*/ report_t current_report;

#define MANAGE_EXAMPLE_TASK_UUID "343435d6-91b0-11de-9478-ffd71f4c6f29"


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
task_owner_name (task_t);

char*
task_name (task_t);

char*
task_comment (task_t);

config_t
task_config (task_t);

char*
task_config_name (task_t);

void
set_task_config (task_t, config_t);

target_t
task_target (task_t);

void
set_task_target (task_t, config_t);

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

report_t
task_current_report (task_t);

char*
task_start_time (task_t);

void
set_task_start_time (task_t task, char* time);

char*
task_end_time (task_t);

void
set_task_end_time (task_t task, char* time);

char*
task_escalator_name (task_t);

escalator_t
task_escalator (task_t);

void
add_task_escalator (task_t, escalator_t);

void
set_task_escalator (task_t, escalator_t);

void
set_task_schedule (task_t, schedule_t);

unsigned int
task_report_count (task_t);

unsigned int
task_finished_report_count (task_t);

const char *
task_trend (task_t);

schedule_t
task_schedule (task_t);

int
task_schedule_next_time (task_t);

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
append_to_task_name (task_t, const char*, int);

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

void
init_config_task_iterator (iterator_t*, config_t, int);

const char*
config_task_iterator_name (iterator_t*);

const char*
config_task_iterator_uuid (iterator_t*);


/* General task facilities. */

const char*
run_status_name (task_status_t status);

const char*
task_run_status_name (task_t task);

int
start_task (task_t, char**);

int
stop_task (task_t);

int
pause_task (task_t);

int
resume_stopped_task (task_t, char **);

int
resume_or_start_task (task_t, char **);

int
resume_paused_task (task_t);


/* Iteration. */

void
cleanup_iterator (iterator_t*);

gboolean
next (iterator_t*);


/* Results. */

gboolean
find_result (const char*, result_t*);

int
result_uuid (result_t, /*@out@*/ char **);


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
gchar*
task_first_report_id (task_t);

int
task_last_stopped_report (task_t, report_t *);

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
report_scan_result_count (report_t, const char*, const char*, int*);

int
report_counts (const char*, int*, int*, int*, int*, int*);

int
report_counts_id (report_t, int*, int*, int*, int*, int*);

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
init_result_iterator (iterator_t*, task_t, result_t, const char*, int, int,
                      int, const char *, const char *, const char *);

gboolean
next_report (iterator_t*, report_t*);

result_t
result_iterator_result (iterator_t*);

const char*
result_iterator_subnet (iterator_t*);

const char*
result_iterator_host (iterator_t*);

const char*
result_iterator_port (iterator_t*);

const char*
result_iterator_nvt_oid (iterator_t*);

const char*
result_iterator_nvt_name (iterator_t *);

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

int
collate_message_type (void* data, int, const void*, int, const void*);

void
trim_partial_report (report_t);


/* RC's. */

char*
rc_preference (const char*, const char*);


/* Targets. */

gboolean
find_target (const char*, target_t*);

int
create_target (const char*, const char*, const char*, lsc_credential_t,
               target_t*);

int
delete_target (target_t);

void
init_target_iterator (iterator_t*, target_t, int, const char*);

target_t
target_iterator_target (iterator_t*);

const char*
target_iterator_name (iterator_t*);

const char*
target_iterator_hosts (iterator_t*);

const char*
target_iterator_comment (iterator_t*);

int
target_iterator_lsc_credential (iterator_t*);

char*
target_name (target_t);

char*
target_hosts (target_t);

int
target_in_use (target_t);

char*
target_lsc_credential_name (const char *);

void
init_target_task_iterator (iterator_t*, target_t, int);

const char*
target_task_iterator_name (iterator_t*);

const char*
target_task_iterator_uuid (iterator_t*);


/* Configs. */

typedef struct
{
  char *name;
  char *type;
  char *value;
  char *nvt_name;
  char *nvt_oid;
  array_t *alts;  /* gchar. */
} preference_t;

typedef struct
{
  char *name;
  char *type;
  int include;
  char *family_or_nvt;
} nvt_selector_t;

int
create_config (const char*, const char*, const array_t*, const array_t*,
               char**);

int
create_config_rc (const char*, const char*, char*, config_t*);

int
copy_config (const char*, const char*, config_t);

int
delete_config (config_t);

gboolean
find_config (const char*, config_t*);

char *
config_nvt_timeout (config_t, const char *);

void
init_config_iterator (iterator_t*, config_t, int, const char*);

config_t
config_iterator_config (iterator_t*);

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
config_nvt_selector (config_t);

int
config_in_use (config_t);

int
config_families_growing (config_t);

int
config_nvts_growing (config_t);

int
config_family_count (config_t);

int
config_nvt_count (config_t);

int
manage_set_config_preference (config_t, const char*, const char*,
                              const char*);

int
manage_set_config_nvts (config_t, const char*, GPtrArray*);

int
manage_set_config_families (config_t, GPtrArray*, GPtrArray*, GPtrArray*,
                            int);


/* NVT's. */

char *
nvt_oid (const char *);

int
nvts_size ();

char*
nvts_md5sum ();

void
set_nvts_md5sum (const char*);

nvt_t
make_nvt_from_nvti (const nvti_t*, int);

gboolean
find_nvt (const char*, nvt_t*);

void
init_nvt_iterator (iterator_t*, nvt_t, config_t, const char*, int,
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

void
manage_complete_nvt_cache_update (int);


/* NVT selectors. */

/**
 * @brief NVT selector type for "all" rule.
 */
#define NVT_SELECTOR_TYPE_ALL 0

/**
 * @brief NVT selector type for "family" rule.
 */
#define NVT_SELECTOR_TYPE_FAMILY 1

/**
 * @brief NVT selector type for "NVT" rule.
 */
#define NVT_SELECTOR_TYPE_NVT 2

/**
 * @brief Special NVT selector type for selecting all types in interfaces.
 */
#define NVT_SELECTOR_TYPE_ANY 999

void
init_family_iterator (iterator_t*, int, const char*, int);

const char*
family_iterator_name (iterator_t*);

int
nvt_selector_family_growing (const char *, const char *, int);

int
nvt_selector_nvt_count (const char *, const char *, int);

void
init_nvt_selector_iterator (iterator_t*, const char*, config_t, int);

const char*
nvt_selector_iterator_nvt (iterator_t*);

const char*
nvt_selector_iterator_name (iterator_t*);

int
nvt_selector_iterator_include (iterator_t*);

int
nvt_selector_iterator_type (iterator_t*);


/* NVT preferences. */

void
manage_nvt_preference_add (const char*, const char*, int);

void
manage_nvt_preferences_enable ();

void
init_nvt_preference_iterator (iterator_t*, const char*);

const char*
nvt_preference_iterator_name (iterator_t*);

const char*
nvt_preference_iterator_value (iterator_t*);

char*
nvt_preference_iterator_config_value (iterator_t*, config_t);

char*
nvt_preference_iterator_real_name (iterator_t*);

char*
nvt_preference_iterator_type (iterator_t*);

char*
nvt_preference_iterator_nvt (iterator_t*);

int
nvt_preference_count (const char *);


/* LSC credentials. */

gboolean
find_lsc_credential (const char*, lsc_credential_t*);

int
create_lsc_credential (const char*, const char*, const char*, const char*);

int
delete_lsc_credential (lsc_credential_t);

void
init_lsc_credential_iterator (iterator_t*, lsc_credential_t, int, const char*);

lsc_credential_t
lsc_credential_iterator_lsc_credential (iterator_t*);

const char*
lsc_credential_iterator_name (iterator_t*);

const char*
lsc_credential_iterator_login (iterator_t*);

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

int
lsc_credential_iterator_in_use (iterator_t*);

char*
lsc_credential_name (lsc_credential_t);

void
init_lsc_credential_target_iterator (iterator_t*, lsc_credential_t, int);

const char*
lsc_credential_target_iterator_name (iterator_t*);


/* Agents. */

gboolean
find_agent (const char*, agent_t*);

int
create_agent (const char*, const char*, const char*, const char*, const char*);

int
delete_agent (agent_t);

void
init_agent_iterator (iterator_t*, agent_t, int, const char*);

const char*
agent_iterator_name (iterator_t*);

const char*
agent_iterator_comment (iterator_t*);

const char*
agent_iterator_installer (iterator_t*);

const char*
agent_iterator_howto_install (iterator_t*);

const char*
agent_iterator_howto_use (iterator_t*);

char*
agent_name (lsc_credential_t);


/* Notes. */

gboolean
find_note (const char*, note_t*);

int
create_note (const char*, const char*, const char*, const char*, const char*,
             task_t, result_t);

int
delete_note (note_t);

int
modify_note (note_t, const char*, const char*, const char*, const char*,
             task_t, result_t);

void
init_note_iterator (iterator_t*, note_t, nvt_t, result_t, task_t, int,
                    const char*);

const char*
note_iterator_uuid (iterator_t*);

const char*
note_iterator_nvt_oid (iterator_t*);

time_t
note_iterator_creation_time (iterator_t*);

time_t
note_iterator_modification_time (iterator_t*);

const char*
note_iterator_text (iterator_t*);

const char*
note_iterator_hosts (iterator_t*);

const char*
note_iterator_port (iterator_t*);

const char*
note_iterator_threat (iterator_t*);

task_t
note_iterator_task (iterator_t*);

result_t
note_iterator_result (iterator_t*);

const char*
note_iterator_nvt_name (iterator_t *);


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


/* System reports. */

typedef struct
{
  gchar **start;
  gchar **current;
} report_type_iterator_t;

int
init_system_report_type_iterator (report_type_iterator_t*);

void
cleanup_report_type_iterator (report_type_iterator_t*);

gboolean
next_report_type (report_type_iterator_t*);

const char*
report_type_iterator_name (report_type_iterator_t*);

const char*
report_type_iterator_title (report_type_iterator_t*);

int
manage_system_report (const char *, const char *, char **);


/* Scheduling. */

gboolean
find_schedule (const char*, schedule_t*);

int
create_schedule (const char*, const char *, time_t, time_t, time_t,
                 time_t, schedule_t *);

int
delete_schedule (schedule_t);

void
manage_auth_allow_all ();

gchar*
get_scheduled_user_uuid ();

void
set_scheduled_user_uuid (gchar* uuid);

int
manage_schedule (int (*) (int *,
                          gnutls_session_t *,
                          gnutls_certificate_credentials_t *,
                          gchar*));

char *
schedule_uuid (schedule_t);

char *
schedule_name (schedule_t);

void
init_schedule_iterator (iterator_t*, schedule_t, int, const char*);

schedule_t
schedule_iterator_schedule (iterator_t*);

const char*
schedule_iterator_uuid (iterator_t *);

const char*
schedule_iterator_name (iterator_t *);

const char*
schedule_iterator_uuid (iterator_t *);

const char*
schedule_iterator_comment (iterator_t *);

time_t
schedule_iterator_first_time (iterator_t *);

time_t
schedule_iterator_next_time (iterator_t *);

time_t
schedule_iterator_period (iterator_t *);

time_t
schedule_iterator_period_months (iterator_t *);

time_t
schedule_iterator_duration (iterator_t *);

int
schedule_iterator_in_use (iterator_t*);

void
init_schedule_task_iterator (iterator_t*, schedule_t);

const char*
schedule_task_iterator_uuid (iterator_t *);

const char*
schedule_task_iterator_name (iterator_t *);

#endif /* not OPENVAS_MANAGER_MANAGE_H */
