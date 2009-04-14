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
authenticate (credentials_t);


/* Tasks. */

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
} port_t;

// FIX should be in otp.c/h
/**
 * @brief The record of a message.
 */
typedef struct
{
  port_t port;          ///< The port.
  char* description;    ///< Description of the message.
  char* oid;            ///< NVT identifier.
} message_t;

typedef enum
{
  TASK_STATUS_NEW,
  TASK_STATUS_REQUESTED,
  TASK_STATUS_RUNNING,
  TASK_STATUS_DONE
} task_status_t;

/**
 * @brief A task.
 */
typedef struct
{
  unsigned int id;            ///< Unique ID.
  char* name;                 ///< Name.  NULL if free.
  unsigned int time;          ///< Repetition period, in seconds.
  char* comment;              ///< Comment associated with task.
  /*@null@*/
  char* description;          ///< Description.
  gsize description_length;   ///< Length of description.
  gsize description_size;     ///< Actual size allocated for description.
  task_status_t run_status;   ///< Run status of task.
  char* start_time;           ///< Time the task last started.
  char* end_time;             ///< Time the task last ended.
  unsigned int report_count;  ///< The number of existing reports on the task.
  /* The rest are for the current scan. */
  /*@null@*/
  FILE* current_report;       ///< Report stream during the task.
  char* attack_state;         ///< Attack status.
  unsigned int current_port;  ///< Port currently under test.
  unsigned int max_port;      ///< Last port to test.
  /*@null@*/
  GArray *open_ports;         ///< Open ports that the server has found.
  int open_ports_size;        ///< Number of open ports.
  int debugs_size;            ///< Number of debugs.
  int holes_size;             ///< Number of holes.
  int infos_size;             ///< Number of infos.
  int logs_size;              ///< Number of logs.
  int notes_size;             ///< Number of notes.
} fs_task_t;

//typedef fs_task_t task_t;
typedef fs_task_t* task_t;
//typedef long long int task_t;

typedef struct
{
  task_t index;
  task_t end;
} task_iterator_t;

/**
 * @brief The task currently running on the server.
 */
extern /*@null@*/ task_t current_server_task;

unsigned int
task_count ();

void
init_task_iterator (task_iterator_t*);

gboolean
next_task (task_iterator_t*, task_t*);

int
task_id_string (task_t, /*@out@*/ const char **);

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
task_t
find_task (unsigned int id);

int
set_task_parameter (task_t,
                    /*@null@*/ const char*,
                    /*@null@*/ /*@only@*/ char*);

int
start_task (task_t);

int
stop_task (task_t);

int
delete_task (task_t*);

int
append_to_task_comment (task_t, const char*, int);

int
append_to_task_identifier (task_t, const char*, int);

int
add_task_description_line (task_t, const char*, size_t);

void
set_task_ports (task_t, unsigned int, unsigned int);

void
append_task_open_port (task_t, unsigned int, char*);


/* Reports. */

// FIX how is this doc'd?
#define OVAS_MANAGE_REPORT_ID_LENGTH UUID_LEN_STR

/*@-exportlocal@*/
/*@only@*/ /*@null@*/
char*
make_report_id ();

gchar*
report_path_task_name (gchar*);

/*@shared@*/ /*@null@*/
task_t
report_task (const char*);
/*@=exportlocal@*/

int
delete_report (const char*);

int
set_report_parameter (char*, const char*, char*);

#endif
