/* OpenVAS Manager
 * $Id$
 * Description: Headers for OpenVAS Manager: the Manage library.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
 * Timo Pollmeier <timo.pollmeier@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2009-2013 Greenbone Networks GmbH
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

#include <openvas/misc/openvas_auth.h>
#include <openvas/base/array.h> /* for array_t */
#include <openvas/base/certificate.h> /* for certificate_t */
#include <openvas/base/credentials.h>
#include <openvas/base/nvti.h> /* for nvti_t */

/**
 * @brief Name value pair.
 */
typedef struct
{
  gchar *name;    ///< Name.
  gchar *value;   ///< Param value.
} name_value_t;

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

/** @todo Exported for omp.c, manage.c and otp.c access to server info (rules,
  *       prefs, ...). */
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


/* Database. */

int
manage_backup_db (const gchar *);

int
manage_db_supported_version ();

int
manage_db_version ();

gboolean
manage_migrate_needs_timezone (GSList *, const gchar *);

int
manage_migrate (GSList*, const gchar*);

int
manage_encrypt_all_credentials (const gchar *database, gboolean decrypt_mode);


/* Task structures. */

extern short scanner_up;
extern short scanner_active;

/**
 * @brief Possible port types.
 *
 * These numbers are used in the database, so if the number associated with
 * any symbol changes then a migrator must be added to update existing data.
 */
typedef enum
{
  PORT_PROTOCOL_TCP = 0,
  PORT_PROTOCOL_UDP = 1,
  PORT_PROTOCOL_OTHER = 2
} port_protocol_t;

/** @todo Should be in otp.c/h. */
/**
 * @brief A port.
 */
typedef struct
{
  unsigned int number;       ///< Port number.
  port_protocol_t protocol;  ///< Port protocol (TCP, UDP, ...).
  char* string;              ///< Original string describing port.
} port_t;

/** @todo Should be in otp.c/h. */
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
  TASK_STATUS_INTERNAL_ERROR = 13,
  TASK_STATUS_DELETE_ULTIMATE_REQUESTED = 14,
  TASK_STATUS_STOP_REQUESTED_GIVEUP = 15,
  TASK_STATUS_DELETE_WAITING = 16,
  TASK_STATUS_DELETE_ULTIMATE_WAITING = 17
} task_status_t;

typedef long long int agent_t;
typedef long long int config_t;
typedef long long int alert_t;
typedef long long int filter_t;
typedef long long int slave_t;
typedef long long int target_t;
typedef long long int task_t;
typedef long long int result_t;
typedef long long int report_t;
typedef long long int report_host_t;
typedef long long int report_format_t;
typedef long long int report_format_param_t;
typedef long long int resource_t;
typedef long long int note_t;
typedef long long int nvt_t;
typedef long long int override_t;
typedef long long int port_list_t;
typedef long long int port_range_t;
typedef long long int lsc_credential_t;
typedef long long int schedule_t;
typedef long long int setting_t;

#include <sqlite3.h>

#include "lsc_crypt.h"  /* (lsc_crypt_ctx_t) */

/**
 * @brief A generic SQL iterator.
 */
typedef struct
{
  sqlite3_stmt* stmt;        ///< SQL statement.
  gboolean done;             ///< End flag.
  int prepared;              ///< Prepared flag.
  lsc_crypt_ctx_t crypt_ctx; ///< Encryption context.
} iterator_t;


/* OMP GET. */

/**
 * @brief Command data for a get command.
 */
typedef struct
{
  char *actions;       ///< Actions.
  int details;         ///< Boolean.  Whether to include full details.
  char *filt_id;       ///< Filter ID.  Overrides "filter".
  char *filter;        ///< Filter term.
  int first;           ///< Skip over items before this number.
  char *id;            ///< ID of single item to get.
  int max;             ///< Maximum number of items returned.
  int trash;           ///< Boolean.  Whether to return from trashcan.
  gchar *type;         ///< Type of resource.
  gchar *subtype;      ///< Subtype, or NULL.
} get_data_t;

resource_t
get_iterator_resource (iterator_t*);

const char*
get_iterator_uuid (iterator_t*);

const char*
get_iterator_name (iterator_t*);

const char*
get_iterator_comment (iterator_t*);

const char*
get_iterator_creation_time (iterator_t*);

const char*
get_iterator_modification_time (iterator_t*);


/* Resources. */

int
resource_count (const char *, const get_data_t *);


/* Events and Alerts. */

/**
 * @brief Types of task events.
 */
typedef enum
{
  EVENT_ERROR,
  EVENT_TASK_RUN_STATUS_CHANGED
} event_t;

/**
 * @brief Types of alerts.
 */
typedef enum
{
  ALERT_METHOD_ERROR,
  ALERT_METHOD_EMAIL,
  ALERT_METHOD_HTTP_GET,
  ALERT_METHOD_SOURCEFIRE,
  ALERT_METHOD_SYSLOG,
  ALERT_METHOD_VERINICE
} alert_method_t;

/**
 * @brief Types of alert conditions.
 */
typedef enum
{
  ALERT_CONDITION_ERROR,
  ALERT_CONDITION_ALWAYS,
  ALERT_CONDITION_THREAT_LEVEL_AT_LEAST,
  ALERT_CONDITION_THREAT_LEVEL_CHANGED
} alert_condition_t;

int
create_alert (const char*, const char*, const char*, event_t, GPtrArray*,
              alert_condition_t, GPtrArray*, alert_method_t, GPtrArray*,
              alert_t*);

int
copy_alert (const char*, const char*, const char*, alert_t*);

int
modify_alert (const char*, const char*, const char*, const char*,
              event_t, GPtrArray*, alert_condition_t, GPtrArray*,
              alert_method_t, GPtrArray*);

int
delete_alert (const char *, int);

char *
alert_uuid (alert_t);

gboolean
find_alert (const char*, alert_t*);

int
manage_alert (alert_t, task_t, event_t, const void*);

int
alert_in_use (alert_t);

int
trash_alert_in_use (alert_t);

int
alert_writable (alert_t);

int
trash_alert_writable (alert_t);

int
alert_count (const get_data_t *);

int
init_alert_iterator (iterator_t*, const get_data_t*);

alert_t
alert_iterator_alert (iterator_t*);

const char*
alert_iterator_uuid (iterator_t*);

const char*
alert_iterator_name (iterator_t*);

const char *
alert_iterator_comment (iterator_t*);

int
alert_iterator_event (iterator_t*);

int
alert_iterator_condition (iterator_t*);

int
alert_iterator_method (iterator_t*);

char *
alert_iterator_filter_uuid (iterator_t*);

char *
alert_iterator_filter_name (iterator_t*);

int
alert_iterator_filter_trash (iterator_t*);

const char*
alert_condition_name (alert_condition_t);

gchar*
alert_condition_description (alert_condition_t, alert_t);

const char*
event_name (event_t);

gchar*
event_description (event_t, const void *, const char *);

const char*
alert_method_name (alert_method_t);

alert_condition_t
alert_condition_from_name (const char*);

event_t
event_from_name (const char*);

alert_method_t
alert_method_from_name (const char*);

void
init_alert_data_iterator (iterator_t *, alert_t, int, const char *);

const char*
alert_data_iterator_name (iterator_t*);

const char*
alert_data_iterator_data (iterator_t*);

void
init_alert_task_iterator (iterator_t*, alert_t, int);

const char*
alert_task_iterator_name (iterator_t*);

const char*
alert_task_iterator_uuid (iterator_t*);

void
init_task_alert_iterator (iterator_t*, task_t, event_t event);

alert_t
task_alert_iterator_alert (iterator_t*);

const char*
task_alert_iterator_uuid (iterator_t*);

const char*
task_alert_iterator_name (iterator_t*);


/* Task global variables and preprocessor variables. */

/**
 * @brief The task currently running on the scanner.
 */
extern /*@null@*/ task_t current_scanner_task;

extern /*@null@*/ report_t current_report;

#define MANAGE_EXAMPLE_TASK_UUID "343435d6-91b0-11de-9478-ffd71f4c6f29"


/* Task code specific to the representation of tasks. */

unsigned int
task_count (const get_data_t *);

unsigned int
trash_task_count ();

int
init_task_iterator (iterator_t*, const get_data_t *);

task_t
task_iterator_task (iterator_t*);

const char *
task_iterator_uuid (iterator_t*);

task_status_t
task_iterator_run_status (iterator_t*);

unsigned int
task_id (task_t);

int
task_uuid (task_t, /*@out@*/ char **);

int
task_in_trash (task_t);

int
task_in_use (task_t);

int
trash_task_in_use (task_t);

int
task_writable (task_t);

int
trash_task_writable (task_t);

char*
task_owner_name (task_t);

char*
task_name (task_t);

char*
task_comment (task_t);

config_t
task_config (task_t);

char*
task_config_uuid (task_t);

char*
task_config_name (task_t);

int
task_config_in_trash (task_t);

void
set_task_config (task_t, config_t);

target_t
task_target (task_t);

int
task_target_in_trash (task_t);

void
set_task_target (task_t, target_t);

target_t
task_slave (task_t);

void
set_task_slave (task_t, target_t);

int
task_slave_in_trash (task_t);

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

int
task_upload_progress (task_t);

char*
task_start_time (task_t);

void
set_task_start_time (task_t, char*);

void
set_task_start_time_otp (task_t, char*);

char*
task_end_time (task_t);

void
set_task_end_time (task_t task, char* time);

void
add_task_alert (task_t, alert_t);

int
set_task_alerts (task_t, array_t*, gchar**);

int
set_task_schedule (task_t, schedule_t);

unsigned int
task_report_count (task_t);

unsigned int
task_finished_report_count (task_t);

int
task_last_report (task_t, report_t*);

const char *
task_trend_counts (task_t, int, int, int, int, int, int);

const char *
task_trend (task_t, int);

const char *
task_threat_level (task_t, int);

schedule_t
task_schedule (task_t);

int
task_schedule_in_trash (task_t);

int
task_schedule_next_time_tz (task_t);

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

int
task_false_positive_size (task_t);

void
free_tasks ();

/*@null@*/ /*@dependent@*/ /*@special@*/
task_t
make_task (/*@only@*/ char*, unsigned int, /*@only@*/ char*)
  /*@defines result->open_ports@*/
  /*@ensures isnull result->description@*/;

void
make_task_complete (const char *);

int
copy_task (const char*, const char*, const char *, task_t*);

int
load_tasks ();

int
save_tasks ();

/*@dependent@*/
gboolean
find_task (const char* id, task_t*);

gboolean
find_task_for_actions (const char*, task_t*, const char *);

void
reset_task (task_t);

int
set_task_parameter (task_t,
                    /*@null@*/ const char*,
                    /*@null@*/ /*@only@*/ char*);

char*
task_observers (task_t);

int
set_task_observers (task_t, const gchar *);

int
request_delete_task_uuid (const char *, int);

int
request_delete_task (task_t*);

int
delete_task (task_t, int);

/* For otp.c. */
int
delete_task_lock (task_t, int);

void
append_to_task_comment (task_t, const char*, int);

void
append_to_task_name (task_t, const char*, int);

void
add_task_description_line (task_t, const char*, size_t);

void
set_scan_ports (report_t, const char*, unsigned int, unsigned int);

void
append_task_open_port (task_t task, const char *, const char*);

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


/* Access control. */

/**
 * @brief Actions.
 */
typedef enum
{
  MANAGE_ACTION_GET = 1,
  MANAGE_ACTION_MODIFY = 2,
  MANAGE_ACTION_USE = 3
} action_t;


/* Results. */

gboolean
find_result (const char*, result_t*);

gboolean
find_result_for_actions (const char*, result_t*, const char *);

int
result_uuid (result_t, /*@out@*/ char **);

int
result_detection_reference (result_t, char **, char **, char **, char **,
                            char **);

const char*
manage_result_type_threat (const char*);


/* Reports. */

/** @todo How is this documented? */
#define OVAS_MANAGE_REPORT_ID_LENGTH UUID_LEN_STR

gboolean
find_report (const char*, report_t*);

gboolean
find_report_for_actions (const char*, report_t*, const char *);

result_t
make_result (task_t, const char*, const char*, const char*, const char*,
             const char*, const char*);

/**
 * @brief A CREATE_REPORT result.
 */
typedef struct
{
  char *description;       ///< Description of NVT.
  char *host;              ///< Host.
  char *nvt_oid;           ///< OID of NVT.
  char *port;              ///< Port.
  char *subnet;            ///< Subnet.
  char *threat;            ///< Threat.
} create_report_result_t;

/**
 * @brief A host detail for create_report.
 */
typedef struct
{
  char *ip;           ///< IP.
  char *name;         ///< Detail name.
  char *source_desc;  ///< Source description.
  char *source_name;  ///< Source name.
  char *source_type;  ///< Source type.
  char *value;        ///< Detail value.
} host_detail_t;

void
host_detail_free (host_detail_t *);

int
create_report (array_t*, const char *, const char *, const char *, const char *,
               const char *, array_t*, array_t*, array_t*, char **);

void
report_add_result (report_t, result_t);

char*
report_uuid (report_t);

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
report_slave_progress (report_t);

char *
report_slave_task_uuid (report_t);

int
report_scan_result_count (report_t, const char*, const char*, int, const char*,
                          int, int, int*);

int
report_counts (const char*, int*, int*, int*, int*, int*, int*, int, int);

int
report_counts_id (report_t, int*, int*, int*, int*, int*, int*, int,
                  const char*, int);

char*
scan_start_time (report_t);

void
set_scan_start_time (report_t, const char*);

void
set_scan_start_time_otp (report_t, const char*);

char*
scan_end_time (report_t);

void
set_scan_end_time (report_t, const char*);

void
set_scan_end_time_otp (report_t, const char*);

void
set_scan_host_start_time (report_t, const char*, const char*);

void
set_scan_host_start_time_otp (report_t, const char*, const char*);

void
set_scan_host_end_time (report_t, const char*, const char*);

void
set_scan_host_end_time_otp (report_t, const char*, const char*);

int
report_timestamp (const char*, gchar**);

int
manage_delete_report (report_t);

int
set_report_parameter (report_t, const char*, const char*);

void
init_report_iterator (iterator_t*, task_t, report_t);

const char*
report_iterator_uuid (iterator_t*);

void
init_result_iterator (iterator_t*, task_t, result_t, int, int, int,
                      const char *, const char *, int, const char *, int,
                      const char *, int);

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
result_iterator_nvt_family (iterator_t *);

const char*
result_iterator_nvt_cvss_base (iterator_t *);

const char*
result_iterator_nvt_risk_factor (iterator_t *);

const char*
result_iterator_nvt_cve (iterator_t *);

const char*
result_iterator_nvt_bid (iterator_t *);

const char*
result_iterator_nvt_xref (iterator_t *);

const char*
result_iterator_nvt_tag (iterator_t *);

const char*
result_iterator_type (iterator_t*);

const char*
result_iterator_original_type (iterator_t*);

const char*
result_iterator_descr (iterator_t*);

void
init_host_iterator (iterator_t*, report_t, const char *, report_host_t);

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
manage_report_host_has_results (report_t, const char *);

int
collate_message_type (void* data, int, const void*, int, const void*);

void
trim_partial_report (report_t);

gchar *
manage_report (report_t, report_format_t, const char *, int, const char*, int,
               const char *, const char *, int, const char *, int, int, int,
               int, int, int, int, int, const char *, gsize *, gchar **,
               gchar **);

int
manage_send_report (report_t, report_t, report_format_t, const get_data_t *,
                    int, const char*, int, const char *, const char *,
                    const char *, int, const char *, int, int, int, int, int,
                    int, int, int, int,
                    gboolean (*) (const char *,
                                  int (*) (const char*, void*),
                                  void*),
                    int (*) (const char *, void*), void *, const char *,
                    const char *, const char *, int, const char *,
                    const char *, int, int, const gchar *);


/* RC's. */

char*
rc_preference (const char*, const char*);


/* Targets. */

/**
 * @brief Maximum number of hosts a target may specify.
 */
#define MANAGE_MAX_HOSTS 4095

void
manage_filter_controls (const gchar *, int *, int *, gchar **, int *);

void
manage_report_filter_controls (const gchar *, int *, int *, gchar **, int *,
                               int *, gchar **, gchar **, gchar **, gchar **,
                               int *, int *, int *, int *, int *);

gchar *
manage_clean_filter (const gchar *);

int
manage_max_hosts (const char *);

gboolean
find_target (const char*, target_t*);

gboolean
find_target_for_actions (const char*, target_t*, const char *);

int
create_target (const char*, const char*, const char*, const char*, const char*,
               lsc_credential_t, const char*, lsc_credential_t, const char*,
               const char*, const char*, int, target_t*);

int
copy_target (const char*, const char*, const char *, target_t*);

int
modify_target (const char*, const char*, const char*, const char*, const char*,
               const char*, const char*, const char*, const char*,
               const char*, const char*);

int
delete_target (const char*, int);

int
target_count (const get_data_t *);

void
init_user_target_iterator (iterator_t*, target_t, int, const char*, int, int);

int
init_target_iterator (iterator_t*, const get_data_t *);

target_t
target_iterator_target (iterator_t*);

const char*
target_iterator_uuid (iterator_t*);

const char*
target_iterator_name (iterator_t*);

const char*
target_iterator_hosts (iterator_t*);

const char*
target_iterator_comment (iterator_t*);

int
target_iterator_ssh_credential (iterator_t*);

const char*
target_iterator_ssh_port (iterator_t*);

int
target_iterator_smb_credential (iterator_t*);

int
target_iterator_ssh_trash (iterator_t*);

int
target_iterator_smb_trash (iterator_t*);

const char*
target_iterator_port_list_uuid (iterator_t*);

const char*
target_iterator_port_list_name (iterator_t*);

int
target_iterator_port_list_trash (iterator_t*);

char*
target_uuid (target_t);

char*
trash_target_uuid (target_t);

char*
target_name (target_t);

char*
trash_target_name (target_t);

char*
target_hosts (target_t);

char*
target_port_range (target_t);

char*
target_ssh_port (target_t);

char*
trash_target_hosts (target_t);

int
target_in_use (target_t);

int
trash_target_in_use (target_t);

int
target_writable (target_t);

int
trash_target_writable (target_t);

char*
target_lsc_credential_name (const char *);

void
init_target_task_iterator (iterator_t*, target_t);

const char*
target_task_iterator_name (iterator_t*);

const char*
target_task_iterator_uuid (iterator_t*);


/* Configs. */

/**
 * @brief An NVT preference.
 */
typedef struct
{
  char *name;      ///< Name of preference.
  char *type;      ///< Type of preference (radio, password, ...).
  char *value;     ///< Value of preference.
  char *nvt_name;  ///< Name of NVT preference affects.
  char *nvt_oid;   ///< OID of NVT preference affects.
  array_t *alts;   ///< Array of gchar's.  Alternate values for radio type.
} preference_t;

/**
 * @brief An NVT selector.
 */
typedef struct
{
  char *name;           ///< Name of NVT selector.
  char *type;           ///< Name of NVT selector.
  int include;          ///< Whether family/NVT is included or excluded.
  char *family_or_nvt;  ///< Family or NVT that this selector selects.
} nvt_selector_t;

int
create_config (const char*, const char*, const array_t*, const array_t*,
               config_t*, char**);

int
create_config_rc (const char*, const char*, char*, config_t*);

int
copy_config (const char*, const char*, config_t, config_t*);

int
delete_config (const char*, int);

gboolean
find_config_for_actions (const char*, config_t*, const char*);

gboolean
find_config (const char*, config_t*);

int
config_uuid (config_t, char **);

char *
config_nvt_timeout (config_t, const char *);

void
init_user_config_iterator (iterator_t*, config_t, int, int, const char*);

int
init_config_iterator (iterator_t*, const get_data_t*);

config_t
config_iterator_config (iterator_t*);

const char*
config_iterator_uuid (iterator_t*);

const char*
config_iterator_name (iterator_t*);

const char*
config_iterator_nvt_selector (iterator_t*);

const char*
config_iterator_comment (iterator_t*);

int
config_iterator_nvt_count (iterator_t*);

int
config_iterator_family_count (iterator_t*);

int
config_iterator_nvts_growing (iterator_t*);

int
config_iterator_families_growing (iterator_t*);

char*
config_nvt_selector (config_t);

int
config_in_use (config_t);

int
config_writable (config_t);

int
config_count (const get_data_t *);

int
trash_config_in_use (config_t);

int
trash_config_writable (config_t);

int
config_families_growing (config_t);

int
config_nvts_growing (config_t);

int
config_family_count (config_t);

int
trash_config_family_count (config_t);

int
config_nvt_count (config_t);

int
trash_config_nvt_count (config_t);

int
manage_set_config_preference (config_t, const char*, const char*,
                              const char*);

int
manage_set_config_comment (config_t, const char*);

int
manage_set_config_name (config_t, const char*);

int
manage_set_config_name_comment (config_t, const char*, const char*);

int
manage_set_config_nvts (config_t, const char*, GPtrArray*);

int
manage_set_config_families (config_t, GPtrArray*, GPtrArray*, GPtrArray*,
                            int);


/* NVT's. */

char *
manage_nvt_name (nvt_t);

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

int
init_nvt_info_iterator (iterator_t*, get_data_t*, const char*);

int
nvt_info_count (const get_data_t *);

void
init_nvt_iterator (iterator_t*, nvt_t, config_t, const char*, const char*, int,
                   const char*);

void
init_cve_nvt_iterator (iterator_t*, const char *, int, const char*);

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

const char*
nvt_iterator_cvss_base (iterator_t*);

const char*
nvt_iterator_risk_factor (iterator_t*);

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

gchar*
get_nvti_xml (iterator_t*, int, int, const char*, int);

void
init_task_preference_iterator (iterator_t*);

const char*
task_preference_iterator_name (iterator_t*);

const char*
task_preference_iterator_value (iterator_t*);

char*
task_preference_iterator_task_value (iterator_t*, task_t);

char*
task_preference_value (task_t, const char *);

void
set_task_preferences (task_t, array_t *);


/* LSC credentials. */

gboolean
find_lsc_credential (const char*, lsc_credential_t*);

gboolean
find_lsc_credential_for_actions (const char*, lsc_credential_t*, const char *);

int
create_lsc_credential (const char*, const char*, const char*, const char*,
                       const char*, const char*, lsc_credential_t*);
int
copy_lsc_credential (const char*, const char*, const char*,
                     lsc_credential_t*);

int
delete_lsc_credential (const char *, int);

int
lsc_credential_count (const get_data_t *);

int
lsc_credential_packaged (lsc_credential_t);

void
set_lsc_credential_name (lsc_credential_t, const char *);

void
set_lsc_credential_comment (lsc_credential_t, const char *);

void
set_lsc_credential_login (lsc_credential_t, const char *);

void
set_lsc_credential_password (lsc_credential_t, const char *);

void
init_user_lsc_credential_iterator (iterator_t*, lsc_credential_t, int, int,
                                   const char*);

int
init_lsc_credential_iterator (iterator_t*, const get_data_t *);

lsc_credential_t
lsc_credential_iterator_lsc_credential (iterator_t*);

const char*
lsc_credential_iterator_uuid (iterator_t*);

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

char*
lsc_credential_uuid (lsc_credential_t);

char*
trash_lsc_credential_uuid (lsc_credential_t);

char*
lsc_credential_name (lsc_credential_t);

char*
trash_lsc_credential_name (lsc_credential_t);

void
init_lsc_credential_target_iterator (iterator_t*, lsc_credential_t, int);

const char*
lsc_credential_target_iterator_uuid (iterator_t*);

const char*
lsc_credential_target_iterator_name (iterator_t*);

int
trash_lsc_credential_in_use (lsc_credential_t);

int
lsc_credential_in_use (lsc_credential_t);

int
trash_lsc_credential_writable (lsc_credential_t);

int
lsc_credential_writable (lsc_credential_t);


/* Agents. */

gboolean
find_agent (const char*, agent_t*);

int
create_agent (const char*, const char*, const char*, const char*, const char*,
              const char*, const char*, agent_t*);

int
copy_agent (const char*, const char*, const char *, agent_t *);

int
modify_agent (const char*, const char*, const char*);

int
delete_agent (const char *, int);

int
agent_in_use (agent_t);

int
trash_agent_in_use (agent_t);

int
trash_agent_writable (agent_t);

int
agent_writable (agent_t);

int
verify_agent (agent_t);

char *
agent_uuid (agent_t);

int
agent_count (const get_data_t *);

int
init_agent_iterator (iterator_t*, const get_data_t *);

const char*
agent_iterator_uuid (iterator_t*);

const char*
agent_iterator_name (iterator_t*);

const char*
agent_iterator_comment (iterator_t*);

const char*
agent_iterator_installer (iterator_t*);

gsize
agent_iterator_installer_size (iterator_t*);

const char*
agent_iterator_installer_64 (iterator_t*);

const char*
agent_iterator_installer_filename (iterator_t*);

const char*
agent_iterator_installer_signature_64 (iterator_t*);

const char*
agent_iterator_trust (iterator_t*);

time_t
agent_iterator_trust_time (iterator_t*);

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
             const char*, task_t, result_t, note_t*);

int
copy_note (const char*, note_t*);

int
delete_note (const char *, int);

int
note_uuid (note_t, char **);

int
modify_note (note_t, const char*, const char*, const char*, const char*,
             const char*, task_t, result_t);

int
note_count (const get_data_t *, nvt_t, result_t, task_t);

int
init_note_iterator (iterator_t*, const get_data_t*, nvt_t, result_t, task_t);

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

time_t
note_iterator_end_time (iterator_t*);

int
note_iterator_active (iterator_t*);

const char*
note_iterator_nvt_name (iterator_t *);


/* Overrides. */

gboolean
find_override (const char*, override_t*);

int
create_override (const char*, const char*, const char*, const char*,
                 const char*, const char*, const char*, task_t, result_t,
                 override_t*);

int
override_uuid (override_t, char **);

int
copy_override (const char*, override_t*);

int
delete_override (const char *, int);

int
modify_override (override_t, const char*, const char*, const char*, const char*,
                 const char*, const char*, task_t, result_t);

int
override_count (const get_data_t *, nvt_t, result_t, task_t);

int
init_override_iterator (iterator_t*, const get_data_t*, nvt_t, result_t,
                        task_t);

const char*
override_iterator_uuid (iterator_t*);

const char*
override_iterator_nvt_oid (iterator_t*);

time_t
override_iterator_creation_time (iterator_t*);

time_t
override_iterator_modification_time (iterator_t*);

const char*
override_iterator_text (iterator_t*);

const char*
override_iterator_hosts (iterator_t*);

const char*
override_iterator_port (iterator_t*);

const char*
override_iterator_threat (iterator_t*);

const char*
override_iterator_new_threat (iterator_t*);

task_t
override_iterator_task (iterator_t*);

result_t
override_iterator_result (iterator_t*);

time_t
override_iterator_end_time (iterator_t*);

int
override_iterator_active (iterator_t*);

const char*
override_iterator_nvt_name (iterator_t *);


/* Scanner messaging. */

int
request_certificates ();

int
acknowledge_bye ();

int
acknowledge_md5sum_info ();

int
manage_check_current_task ();


/* System reports. */

/**
 * @brief A system report type iterator.
 */
typedef struct
{
  gchar **start;        ///< First type.
  gchar **current;      ///< Current type.
} report_type_iterator_t;

int
init_system_report_type_iterator (report_type_iterator_t*, const char*,
                                  const char*);

void
cleanup_report_type_iterator (report_type_iterator_t*);

gboolean
next_report_type (report_type_iterator_t*);

const char*
report_type_iterator_name (report_type_iterator_t*);

const char*
report_type_iterator_title (report_type_iterator_t*);

int
manage_system_report (const char *, const char *, const char *, char **);


/* Scheduling. */

long
time_offset (const char *, time_t);

long
current_offset (const char *);

gboolean
find_schedule (const char*, schedule_t*);

int
create_schedule (const char*, const char *, time_t, time_t, time_t,
                 time_t, schedule_t *);

int
copy_schedule (const char*, const char*, const char *, schedule_t *);

int
delete_schedule (const char*, int);

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

int
init_schedule_iterator (iterator_t*, const get_data_t *);

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

const char*
schedule_iterator_timezone (iterator_t *);

time_t
schedule_iterator_initial_offset (iterator_t *);

int
trash_schedule_in_use (schedule_t);

int
schedule_in_use (schedule_t);

int
trash_schedule_writable (schedule_t);

int
schedule_writable (schedule_t);

int
schedule_count (const get_data_t *);

void
init_schedule_task_iterator (iterator_t*, schedule_t);

const char*
schedule_task_iterator_uuid (iterator_t *);

const char*
schedule_task_iterator_name (iterator_t *);

int
modify_schedule (const char*, const char*, const char *, time_t, time_t, time_t,
                 time_t, const char *);


/* Report Formats. */

gboolean
find_report_format (const char*, report_format_t*);

gboolean
lookup_report_format (const char*, report_format_t*);

/**
 * @brief Struct for defining a report format param.
 */
typedef struct
{
  gchar *fallback;  ///< Fallback value.
  gchar *name;      ///< Name.
  gchar *type;      ///< Type (boolean, string, integer, ...).
  gchar *type_max;  ///< Maximum value for integer type.
  gchar *type_min;  ///< Minimum value for integer type.
  gchar *value;     ///< Value of param.
} create_report_format_param_t;

int
create_report_format (const char *, const char *, const char *, const char *,
                      const char *, const char *, int, array_t *, array_t *,
                      array_t *, const char *, report_format_t *);

int
copy_report_format (const char *, const char *, report_format_t*);

int
delete_report_format (const char *, int);

int
verify_report_format (report_format_t);

char *
report_format_uuid (report_format_t);

void
set_report_format_active (report_format_t, int);

char *
report_format_name (report_format_t);

char *
report_format_content_type (report_format_t);

char *
report_format_extension (report_format_t);

void
set_report_format_name (report_format_t, const char *);

void
set_report_format_summary (report_format_t, const char *);

int
set_report_format_param (report_format_t, const char *, const char *);

int
report_format_global (report_format_t);

int
report_format_predefined (report_format_t);

int
report_format_active (report_format_t);

int
report_format_trust (report_format_t);

int
report_format_in_use (report_format_t);

int
trash_report_format_in_use (report_format_t);

int
trash_report_format_writable (report_format_t);

int
report_format_writable (report_format_t);

int
report_format_count (const get_data_t *);

int
init_report_format_iterator (iterator_t*, const get_data_t *);

report_format_t
report_format_iterator_report_format (iterator_t*);

const char*
report_format_iterator_uuid (iterator_t *);

const char*
report_format_iterator_name (iterator_t *);

const char*
report_format_iterator_extension (iterator_t *);

const char*
report_format_iterator_content_type (iterator_t *);

const char*
report_format_iterator_description (iterator_t *);

int
report_format_iterator_active (iterator_t *);

const char*
report_format_iterator_signature (iterator_t *);

const char*
report_format_iterator_trust (iterator_t *);

const char*
report_format_iterator_summary (iterator_t *);

time_t
report_format_iterator_trust_time (iterator_t *);

void
init_report_format_alert_iterator (iterator_t*, report_format_t);

const char*
report_format_alert_iterator_name (iterator_t*);

const char*
report_format_alert_iterator_uuid (iterator_t*);

/**
 * @brief A report format file iterator.
 */
typedef struct
{
  GPtrArray *start;    ///< Array of files.
  gpointer *current;   ///< Current file.
  gchar *dir_name;     ///< Dir holding files.
} file_iterator_t;

int
init_report_format_file_iterator (file_iterator_t*, report_format_t);

void
cleanup_file_iterator (file_iterator_t*);

gboolean
next_file (file_iterator_t*);

const char*
file_iterator_name (file_iterator_t*);

gchar*
file_iterator_content_64 (file_iterator_t*);

/**
 * @brief Report format param types.
 *
 * These numbers are used in the database, so if the number associated with
 * any symbol changes then a migrator must be added to update existing data.
 */
typedef enum
{
  REPORT_FORMAT_PARAM_TYPE_BOOLEAN = 0,
  REPORT_FORMAT_PARAM_TYPE_INTEGER = 1,
  REPORT_FORMAT_PARAM_TYPE_SELECTION = 2,
  REPORT_FORMAT_PARAM_TYPE_STRING = 3,
  REPORT_FORMAT_PARAM_TYPE_TEXT = 4,
  REPORT_FORMAT_PARAM_TYPE_ERROR = 100
} report_format_param_type_t;

const char *
report_format_param_type_name (report_format_param_type_t);

report_format_param_type_t
report_format_param_type_from_name (const char *);

void
init_report_format_param_iterator (iterator_t*, report_format_t, int,
                                   int, const char*);

report_format_param_t
report_format_param_iterator_param (iterator_t*);

const char*
report_format_param_iterator_name (iterator_t *);

const char*
report_format_param_iterator_value (iterator_t *);

const char*
report_format_param_iterator_type_name (iterator_t *);

report_format_param_type_t
report_format_param_iterator_type (iterator_t *);

long long int
report_format_param_iterator_type_min (iterator_t *);

long long int
report_format_param_iterator_type_max (iterator_t *);

const char*
report_format_param_iterator_fallback (iterator_t *);

const char*
report_format_param_iterator_type_regex (iterator_t *);

void
init_param_option_iterator (iterator_t*, report_format_param_t, int,
                            const char *);

const char*
param_option_iterator_value (iterator_t *);


/* Slaves. */

gboolean
find_slave (const char*, slave_t*);

int
create_slave (const char*, const char*, const char*, const char*,
              const char*, const char*, slave_t*);

int
copy_slave (const char*, const char*, const char *, slave_t *);

int
modify_slave (const char*, const char*, const char*, const char*, const char*,
              const char*, const char*);

int
delete_slave (const char*, int);

int
init_slave_iterator (iterator_t*, const get_data_t *);

slave_t
slave_iterator_slave (iterator_t*);

const char*
slave_iterator_uuid (iterator_t*);

const char*
slave_iterator_name (iterator_t*);

const char*
slave_iterator_comment (iterator_t*);

const char*
slave_iterator_host (iterator_t*);

const char*
slave_iterator_port (iterator_t*);

const char*
slave_iterator_login (iterator_t*);

const char*
slave_iterator_password (iterator_t*);

char*
slave_uuid (slave_t);

char*
trash_slave_uuid (slave_t);

char*
slave_name (slave_t);

char*
trash_slave_name (slave_t);

char*
slave_host (slave_t);

char*
slave_login (slave_t);

char*
slave_password (slave_t);

int
slave_port (slave_t);

int
slave_in_use (slave_t);

int
trash_slave_in_use (slave_t);

int
trash_slave_writable (slave_t);

int
slave_writable (slave_t);

int
slave_count (const get_data_t *);

void
init_slave_task_iterator (iterator_t*, slave_t);

const char*
slave_task_iterator_name (iterator_t*);

const char*
slave_task_iterator_uuid (iterator_t*);


/* Port lists. */

/**
 * @brief A port range.
 */
struct range
{
  gchar *comment;       ///< Comment.
  int end;              ///< End port.  0 for single port.
  int exclude;          ///< Whether to exclude range.
  gchar *id;            ///< UUID.
  int start;            ///< Start port.
  int type;             ///< Port protocol.
};
typedef struct range range_t;

gboolean
find_port_list (const char*, port_list_t*);

gboolean
find_port_range (const char*, port_list_t*);

int
create_port_list (const char*, const char*, const char*, const char*,
                  array_t *, port_list_t*);

int
copy_port_list (const char*, const char*, const char*, port_list_t*);

int
modify_port_list (const char*, const char*, const char*);

int
create_port_range (const char *, const char *, const char *, const char *,
                   const char *, port_range_t *);

int
delete_port_list (const char*, int);

int
delete_port_range (const char *);

int
port_list_count (const get_data_t *);

int
init_port_list_iterator (iterator_t*, const get_data_t *);

port_list_t
port_list_iterator_port_list (iterator_t*);

const char*
port_list_iterator_uuid (iterator_t*);

const char*
port_list_iterator_name (iterator_t*);

const char*
port_list_iterator_comment (iterator_t*);

int
port_list_iterator_count_all (iterator_t*);

int
port_list_iterator_count_tcp (iterator_t*);

int
port_list_iterator_count_udp (iterator_t*);

char*
port_list_uuid (port_list_t);

char*
port_range_uuid (port_range_t);

int
port_list_is_predefined (port_list_t);

int
port_list_in_use (port_list_t);

int
trash_port_list_in_use (port_list_t);

int
trash_port_list_writable (port_list_t);

int
port_list_writable (port_list_t);

#if 0
int
trash_port_list_in_use (port_list_t);
#endif

void
init_port_range_iterator (iterator_t*, port_range_t, int, int, const char*);

const char*
port_range_iterator_uuid (iterator_t*);

const char*
port_range_iterator_comment (iterator_t*);

const char*
port_range_iterator_start (iterator_t*);

const char*
port_range_iterator_end (iterator_t*);

const char*
port_range_iterator_type (iterator_t*);

port_protocol_t
port_range_iterator_type_int (iterator_t* iterator);

int
port_range_iterator_exclude (iterator_t*);

void
init_port_list_target_iterator (iterator_t*, port_list_t, int);

const char*
port_list_target_iterator_uuid (iterator_t*);

const char*
port_list_target_iterator_name (iterator_t*);


/* Filters. */

gboolean
find_filter (const char*, filter_t*);

gboolean
find_filter_for_actions (const char*, filter_t*, const char*);

char*
filter_uuid (filter_t);

char*
trash_filter_uuid (filter_t);

char*
filter_name (filter_t);

char*
trash_filter_name (filter_t);

gchar*
filter_term (const char *);

gchar*
filter_term_value (const char *, const char *);

int
create_filter (const char*, const char*, const char*, const char*, int,
               filter_t*);

int
copy_filter (const char*, const char*, const char*, filter_t*);

int
delete_filter (const char *, int);

int
trash_filter_in_use (filter_t);

int
filter_in_use (filter_t);

int
trash_filter_writable (filter_t);

int
filter_writable (filter_t);

int
filter_count (const get_data_t*);

int
init_filter_iterator (iterator_t*, const get_data_t*);

const char*
filter_iterator_type (iterator_t*);

const char*
filter_iterator_term (iterator_t*);

void
init_filter_alert_iterator (iterator_t*, filter_t);

const char*
filter_alert_iterator_name (iterator_t*);

const char*
filter_alert_iterator_uuid (iterator_t*);

int
modify_filter (const char*, const char*, const char*, const char*, const char*);


/* Schema. */

int
manage_schema (gchar *, gchar **, gsize *, gchar **, gchar **);


/* Trashcan. */

int
manage_restore (const char *);

int
manage_empty_trashcan ();


/* Tags. */

void
parse_tags (const char *, gchar **, gchar **, gchar **);


/* SecInfo */

int
manage_read_info (gchar *, gchar *, gchar **);

/* SCAP. */

int
manage_scap_loaded ();

char *
manage_scap_update_time ();

/* CPE. */

void
init_cpe_cve_iterator (iterator_t *, const char *, int, const char *);

int
init_cpe_info_iterator (iterator_t*, get_data_t*, const char*);

int
cpe_info_count (const get_data_t *get);

const char*
cpe_info_iterator_title (iterator_t*);

const char*
cpe_info_iterator_status (iterator_t*);

const char*
cpe_info_iterator_max_cvss (iterator_t*);

const char*
cpe_info_iterator_deprecated_by_id (iterator_t*);

const char*
cpe_info_iterator_cve_refs (iterator_t*);

/* CVE. */

const char*
cve_iterator_name (iterator_t*);

const char*
cve_iterator_cvss (iterator_t*);

const char*
cve_info_iterator_cvss (iterator_t*);

const char*
cve_info_iterator_vector (iterator_t*);

const char*
cve_info_iterator_complexity (iterator_t*);

const char*
cve_info_iterator_authentication (iterator_t*);

const char*
cve_info_iterator_confidentiality_impact (iterator_t*);

const char*
cve_info_iterator_integrity_impact (iterator_t*);

const char*
cve_info_iterator_availability_impact (iterator_t*);

const char*
cve_info_iterator_description (iterator_t*);

const char*
cve_info_iterator_products (iterator_t*);

int
init_cve_info_iterator (iterator_t*, get_data_t*, const char*);

int
cve_info_count (const get_data_t *get);

/* OVAL defintions */
int
init_ovaldef_info_iterator (iterator_t*, get_data_t*, const char*);

int
ovaldef_info_count (const get_data_t *get);

const char*
ovaldef_info_iterator_version (iterator_t*);

const char*
ovaldef_info_iterator_deprecated (iterator_t*);

const char*
ovaldef_info_iterator_def_class (iterator_t*);

const char*
ovaldef_info_iterator_title (iterator_t*);

const char*
ovaldef_info_iterator_description (iterator_t*);

const char*
ovaldef_info_iterator_xml_file (iterator_t*);

const char*
ovaldef_info_iterator_status (iterator_t*);

/* CERT data */
int
manage_cert_loaded ();

char *
manage_cert_update_time ();

/* DFN-CERT */

int
init_dfn_cert_adv_info_iterator (iterator_t*, get_data_t*, const char*);

int
dfn_cert_adv_info_count (const get_data_t *get);

const char*
dfn_cert_adv_info_iterator_title (iterator_t*);

const char*
dfn_cert_adv_info_iterator_summary (iterator_t*);

const char*
dfn_cert_adv_info_iterator_cve_refs (iterator_t*);

void
init_cve_dfn_cert_adv_iterator (iterator_t*, const char*, int, const char*);

void
init_nvt_dfn_cert_adv_iterator (iterator_t*, const char*, int, const char*);


/* Settings. */

int
setting_count (const char *);

char *
setting_filter (const char *);

void
init_setting_iterator (iterator_t *, const char *, const char *, int, int, int,
                       const char *);

const char*
setting_iterator_uuid (iterator_t*);

const char*
setting_iterator_name (iterator_t*);

const char*
setting_iterator_comment (iterator_t*);

const char*
setting_iterator_value (iterator_t*);

int
setting_value_int (const char *, int *);

int
manage_set_setting (const gchar *, const gchar *, const gchar *, gchar **);


/* Wizards. */

int
manage_run_wizard (const gchar *, int (*) (void*, gchar*, gchar**),
                   void *, array_t *, gchar **);


/* Helpers. */

char *
iso_time (time_t *);

char *
iso_time_tz (time_t *, const char *);

gchar *
xsl_transform (gchar *, gchar *, gchar **, gchar **);

#endif /* not OPENVAS_MANAGER_MANAGE_H */
