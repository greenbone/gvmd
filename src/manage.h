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

#include <openvas/certificate.h>
#include <openvas/nvti.h>

/**
 * @brief Structure of information about the server.
 */
typedef struct
{
  certificates_t* certificates;      ///< List of certificates.
  char* plugins_md5;                 ///< MD5 sum over all tests.
  GHashTable* plugins_dependencies;  ///< Dependencies between plugins.
  nvtis_t* plugins;                  ///< Plugin meta-information.
  GHashTable* preferences;           ///< Server preference.
  GPtrArray* rules;                  ///< Server rules.
  int rules_size;                    ///< Number of rules.
} server_t;

// FIX for omp.c,manage.c,otp.c access to server info (rules, prefs, ...)
/**
 * @brief Information about the server.
 */
extern server_t server;

int
init_manage (GSList*);

void
init_manage_process ();

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


/* Task structures. */

short server_active;

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
  TASK_STATUS_STOPPED
} task_status_t;

#ifdef TASKS_SQL
typedef long long int task_t;
typedef long long int result_t;
typedef long long int report_t;

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
#endif


/* Task global variables. */

/**
 * @brief The task currently running on the server.
 */
extern /*@null@*/ task_t current_server_task;

extern /*@null@*/ report_t current_report;


/* Task code specific to the representation of tasks. */

unsigned int
task_count ();

void
init_task_iterator (task_iterator_t*);

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

char*
task_target (task_t);

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
task_notes_size (task_t);

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


/* General task facilities. */

char*
make_task_uuid ();

const char*
task_run_status_name (task_t task);

int
start_task (task_t);

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
task_last_report_id (task_t);

gchar*
task_second_last_report_id (task_t);

gchar*
report_path_task_uuid (gchar*);

gboolean
report_task (const char*, task_t* task);
/*@=exportlocal@*/

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
init_result_iterator (iterator_t*, task_t, const char*);

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
host_iterator_end_time (iterator_t*);

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
init_target_iterator (iterator_t*);

const char*
target_iterator_name (iterator_t*);

const char*
target_iterator_hosts (iterator_t*);

const char*
target_iterator_comment (iterator_t*);

char*
target_hosts (const char*);


/* Configs. */

int
create_config (const char*, const char*, char*);

int
delete_config (const char*);

void
init_config_iterator (iterator_t*);

const char*
config_iterator_name (iterator_t*);

const char*
config_iterator_nvt_selector (iterator_t*);

const char*
config_iterator_comment (iterator_t*);

char*
config_nvt_selector (const char*);


/* NVT selectors. */

int
nvt_selector_families_growing (const char*);

int
nvt_selector_nvts_growing (const char*);

int
nvt_selector_family_count (const char*);

int
nvt_selector_nvt_count (const char*);


/* Server messaging. */

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

#endif /* not OPENVAS_MANAGER_MANAGE_H */
