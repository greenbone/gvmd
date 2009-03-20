/* OpenVAS Manager
 * $Id$
 * Description: Headers for OpenVAS Manager: the Manage library.
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
 *
 * Copyright:
 * Copyright (C) 2009 Intevation GmbH
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

#include <glib.h>


/* Credentials. */

/**
 * @brief A username password pair.
 */
typedef struct
{
  gchar* username;  ///< Login name of user.
  gchar* password;  ///< Password of user.
} credentials_t;

extern credentials_t current_credentials;

void
free_credentials (credentials_t* credentials);

void
append_to_credentials_username (credentials_t*, const char*, int);

void
append_to_credentials_password (credentials_t*, const char*, int);

int
authenticate (credentials_t);


/* Reports. */

int
delete_report (const char*);

int
set_report_parameter (char*, const char*, char*);


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
  int number;                ///< Port number.
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
  char* description;          ///< Description.
  int description_length;     ///< Length of description.
  int description_size;       ///< Actual size allocated for description.
  short run_status;           ///< Run status of task.
  char* start_time;           ///< Time the task last started.
  char* end_time;             ///< Time the task last ended.
  unsigned int report_count;  ///< The number of existing reports on the task.
  /* The rest are for the current scan. */
  char* attack_state;         ///< Attack status.
  unsigned int current_port;  ///< Port currently under test.
  unsigned int max_port;      ///< Last port to test.
  GArray *open_ports;         ///< Open ports that the server has found.
  int open_ports_size;        ///< Number of open ports.
  GPtrArray *debugs;          ///< Identified messages of class "debug".
  int debugs_size;            ///< Number of debugs.
  GPtrArray *holes;           ///< Identified messages of class "hole".
  int holes_size;             ///< Number of holes.
  GPtrArray *infos;           ///< Identified messages of class "info".
  int infos_size;             ///< Number of infos.
  GPtrArray *logs;            ///< Identified messages of class "log".
  int logs_size;              ///< Number of logs.
  GPtrArray *notes;           ///< Identified messages of class "note".
  int notes_size;             ///< Number of notes.
} task_t;

// FIX only for STATUS response in omp.c
#if 1
extern task_t* tasks;

extern unsigned int num_tasks;

extern unsigned int tasks_size;
#endif

/**
 * @brief The task currently running on the server.
 */
extern task_t* current_server_task;

int
task_id_string (task_t*, const char **);

void
free_tasks ();

task_t*
make_task (char*, unsigned int, char*);

int
load_tasks ();

int
save_tasks ();

task_t*
find_task (unsigned int id);

int
set_task_parameter (task_t*, const char*, char*);

int
start_task (task_t*);

int
stop_task (task_t*);

int
delete_task (task_t*);

int
append_to_task_comment (task_t*, const char*, int);

int
append_to_task_identifier (task_t*, const char*, int);

int
add_task_description_line (task_t*, const char*, int);

void
set_task_ports (task_t*, unsigned int, unsigned int);

void
append_task_open_port (task_t*, unsigned int, char*);

#endif
