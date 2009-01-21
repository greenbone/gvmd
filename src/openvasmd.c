/* OpenVAS Manager
 * $Id$
 * Description: Main module for OpenVAS Manager: the system daemon.
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
 *
 * Copyright:
 * Copyright (C) 2008, 2009 Intevation GmbH
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

/**
 * @file  openvasmd.c
 * @brief The OpenVAS Manager
 *
 * This file defines the OpenVAS Manager, a daemon that is layered between
 * the real OpenVAS Server (openvasd) and a client (such as
 * OpenVAS-Client).
 */

/**
 * \mainpage
 *
 * \section Introduction
 * \verbinclude README
 *
 * \section manpages Manual Pages
 * \subpage manpage
 *
 * \section Installation
 * \verbinclude INSTALL
 *
 * \section Implementation
 *
 * \ref openvasmd.c
 *
 * \ref ovas-mngr-comm.c
 */

/**
 * \page manpage openvasmd
 * \htmlinclude openvasmd.html
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <gnutls/gnutls.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openvas/network.h>
#include <openvas/plugutils.h>

#include "string.h"
#include "ovas-mngr-comm.h"

/**
 * @brief Installation prefix.
 */
#ifndef PREFIX
#define PREFIX ""
#endif

/**
 * @brief The name of this program.
 *
 * \todo Use `program_invocation[_short]_name'?
 */
#define PROGNAME "openvasmd"

/**
 * @brief The version number of this program.
 */
#ifndef OPENVASMD_VERSION
#define OPENVASMD_VERSION "FIX"
#endif

/**
 * @brief The name of the underlying Operating System.
 */
#ifndef OPENVAS_OS_NAME
#define OPENVAS_OS_NAME "FIX"
#endif

/**
 * @brief Server (openvasd) address.
 */
#define OPENVASD_ADDRESS "127.0.0.1"

/**
 * @brief Location of server certificate.
 */
#ifndef SERVERCERT
#define SERVERCERT "/var/lib/openvas/CA/servercert.pem"
#endif

/**
 * @brief Location of server certificate private key.
 */
#ifndef SERVERKEY
#define SERVERKEY  "/var/lib/openvas/private/CA/serverkey.pem"
#endif

/**
 * @brief Location of Certificate Authority certificate.
 */
#ifndef CACERT
#define CACERT     "/var/lib/openvas/CA/cacert.pem"
#endif

/**
 * @brief Server port.
 *
 * Used if /etc/services "openvas" and -port missing.
 */
#define OPENVASD_PORT 1241

/**
 * @brief Manager port.
 *
 * Used if /etc/services "omp" and -sport are missing.
 */
#define OPENVASMD_PORT 1241

/**
 * @brief The size of the data buffers.
 *
 * When the client/server buffer is full `select' stops watching for input
 * from the client/server.
 */
#define BUFFER_SIZE 8192

/**
 * @brief Second argument to `listen'.
 */
#define MAX_CONNECTIONS 512

/**
 * @brief OMP flag.
 *
 * Enables handling of OpenVAS Management Protocol. If 0 then OMP is turned off.
 */
#define OMP 1

/**
 * @brief Logging flag.
 *
 * All data transfered to and from the client is logged to a file.  If 0 then
 * logging is turned off.
 */
#define LOG 1

/**
 * @brief Name of log file.
 */
#define LOG_FILE PREFIX "/var/log/openvas/openvasmd.log"

/**
 * @brief Trace flag.
 *
 * 0 to turn off all tracing messages.
 */
#define TRACE 1
#include "tracef.h"

/**
 * @brief Trace text flag.
 *
 * 0 to turn off echoing of actual data transfered (requires TRACE).
 */
#define TRACE_TEXT 1

#if BUFFER_SIZE > SSIZE_MAX
#error BUFFER_SIZE too big for `read'
#endif

#if LOG
/**
 * @brief Formatted logging output.
 *
 * Print the printf style \a args to log_stream, preceded by the process ID.
 */
#define logf(args...)                         \
  do {                                        \
    fprintf (log_stream, "%7i  ", getpid());  \
    fprintf (log_stream, args);               \
    fflush (log_stream);                      \
  } while (0)
#else
/**
 * @brief Dummy macro, enabled with LOG.
 */
#define logf(format, args...)
#endif

/**
 * @brief The socket accepting OMP connections from clients.
 */
int manager_socket = -1;

/**
 * @brief The IP address of this program, "the manager".
 */
struct sockaddr_in manager_address;

/**
 * @brief The IP address of openvasd, "the server".
 */
struct sockaddr_in server_address;

#if LOG
/**
 * @brief The log stream.
 */
FILE* log_stream = NULL;
#endif

/**
 * @brief The server context.
 */
static ovas_server_context_t server_context = NULL;

/**
 * @brief Client input parsing context.
 */
GMarkupParseContext* xml_context;

/**
 * @brief File descriptor set mask: selecting on client read.
 */
#define FD_CLIENT_READ  1
/**
 * @brief File descriptor set mask: selecting on client write.
 */
#define FD_CLIENT_WRITE 2
/**
 * @brief File descriptor set mask: selecting on server read.
 */
#define FD_SERVER_READ  4
/**
 * @brief File descriptor set mask: selecting on server write.
 */
#define FD_SERVER_WRITE 8

/**
 * @brief The type of the return value from \ref read_protocol.
 */
typedef enum
{
  PROTOCOL_OTP,
  PROTOCOL_OMP,
  PROTOCOL_CLOSE,
  PROTOCOL_FAIL
} protocol_read_t;

/**
 * @brief Buffer of input from the client.
 */
char from_client[BUFFER_SIZE];
/**
 * @brief Buffer of input from the server.
 */
char from_server[BUFFER_SIZE];
/**
 * @brief Buffer of output to the client.
 */
char to_client[BUFFER_SIZE];

// FIX just make these pntrs?
/**
 * @brief The start of the data in the \ref from_client buffer.
 */
int from_client_start = 0;
/**
 * @brief The start of the data in the \ref from_server buffer.
 */
int from_server_start = 0;
/**
 * @brief The end of the data in the \ref from_client buffer.
 */
int from_client_end = 0;
/**
 * @brief The end of the data in the \ref from_server buffer.
 */
int from_server_end = 0;
/**
 * @brief The start of the data in the \ref to_client buffer.
 */
int to_client_start = 0;
/**
 * @brief The start of the data in the \ref to_server buffer.
 */
int to_server_start = 0;
/**
 * @brief The end of the data in the \ref to_client buffer.
 */
int to_client_end = 0;

/**
 * @brief Client login name, from OMP LOGIN.
 */
char* login = NULL;

/**
 * @brief Client credentials, from OMP LOGIN.
 */
char* credentials = NULL;


/* Helper functions. */

/**
 * @brief Free a GPtrArray.
 *
 * Wrapper for g_ptr_array_free; passed to g_hash_table_new_full.
 *
 * @param[in]  array  A pointer to a GPtrArray.
 */
void
free_g_ptr_array (gpointer array)
{
  g_ptr_array_free (array, TRUE);
}


/* Client state. */

/**
 * @brief Possible states of the client.
 */
typedef enum
{
  CLIENT_DONE,
  CLIENT_MODIFY_TASK,
  CLIENT_MODIFY_TASK_TASK_ID,
  CLIENT_MODIFY_TASK_PARAMETER,
  CLIENT_MODIFY_TASK_VALUE,
  CLIENT_NEW_TASK,
  CLIENT_NEW_TASK_COMMENT,
  CLIENT_NEW_TASK_IDENTIFIER,
  CLIENT_NEW_TASK_TASK_FILE,
  CLIENT_START_TASK,
  CLIENT_START_TASK_TASK_ID,
  CLIENT_STATUS,
  CLIENT_STATUS_TASK_ID,
  CLIENT_TOP,
  CLIENT_VERSION
} client_state_t;

/**
 * @brief The state of the client.
 */
client_state_t client_state = CLIENT_TOP;

/**
 * @brief Set the client state.
 */
void
set_client_state (client_state_t state)
{
  client_state = state;
  tracef ("   client state set: %i\n", client_state);
}


/* Server state. */

/**
 * @brief Structure of information about the server.
 */
typedef struct
{
  char* plugins_md5;                 ///< MD5 sum over all tests.
  GHashTable* plugins_dependencies;  ///< Dependencies between plugins.
  GHashTable* preferences;           ///< Server preference.
  GPtrArray* rules;                  ///< Server rules.
} server_t;

/**
 * @brief Information about the server.
 */
server_t server;

/**
 * @brief Possible states of the server.
 */
typedef enum
{
  SERVER_BYE,
  SERVER_DONE,
  SERVER_PLUGINS_MD5,
  SERVER_PLUGIN_DEPENDENCY_NAME,
  SERVER_PLUGIN_DEPENDENCY_DEPENDENCY,
  SERVER_PORT_HOST,
  SERVER_PORT_NUMBER,
  SERVER_PREFERENCE_NAME,
  SERVER_PREFERENCE_VALUE,
  SERVER_RULE,
  SERVER_SERVER,
  SERVER_STATUS,
  SERVER_STATUS_ATTACK_STATE,
  SERVER_STATUS_HOST,
  SERVER_STATUS_PORTS,
  SERVER_TIME,
  SERVER_TIME_HOST_START_HOST,
  SERVER_TIME_HOST_START_TIME,
  SERVER_TIME_HOST_END_HOST,
  SERVER_TIME_HOST_END_TIME,
  SERVER_TIME_SCAN_START,
  SERVER_TIME_SCAN_END,
  SERVER_TOP
} server_state_t;

/**
 * @brief The state of the server.
 */
server_state_t server_state = SERVER_TOP;

/**
 * @brief Set the server state.
 */
void
set_server_state (server_state_t state)
{
  server_state = state;
  tracef ("   server state set: %i\n", server_state);
}

/**
 * @brief Possible initialisation states of the server.
 */
typedef enum
{
  SERVER_INIT_CONNECT_INTR,    /* `connect' to server interrupted. */
  SERVER_INIT_CONNECTED,
  SERVER_INIT_DONE,
  SERVER_INIT_GOT_PASSWORD,
  SERVER_INIT_GOT_USER,
  SERVER_INIT_GOT_VERSION,
  SERVER_INIT_SENT_USER,
  SERVER_INIT_SENT_VERSION,
  SERVER_INIT_TOP
} server_init_state_t;

/**
 * @brief The initialisation state of the server.
 */
server_init_state_t server_init_state = SERVER_INIT_TOP;

/**
 * @brief Offset into initialisation string being sent to server.
 */
int server_init_offset = 0;

/**
 * @brief Set the server initialisation state.
 */
void
set_server_init_state (server_init_state_t state)
{
  server_init_state = state;
  tracef ("   server init state set: %i\n", server_init_state);
}


/* Server preferences. */

/**
 * @brief The current server preference, during reading of server preferences.
 */
char* current_server_preference = NULL;

/**
 * @brief Free any server preferences.
 */
void
maybe_free_server_preferences ()
{
  if (server.preferences) g_hash_table_destroy (server.preferences);
}

/**
 * @brief Create the server preferences.
 */
void
make_server_preferences ()
{
  server.preferences = g_hash_table_new_full (g_str_hash,
                                              g_str_equal,
                                              g_free,
                                              g_free);
}

/**
 * @brief Add a preference to the server preferences.
 *
 * Both parameters are used directly (versus copying), and are freed when
 * the preferences are freed.
 *
 * @param[in]  preference  The preference.
 * @param[in]  value       The value of the preference.
 */
void
add_server_preference (char* preference, char* value)
{
  g_hash_table_insert (server.preferences, preference, value);
}


/* Server plugin dependencies. */

/**
 * @brief The current server plugin, during reading of server plugin dependencies.
 */
char* current_server_plugin_dependency_name = NULL;

/**
 * @brief The plugins required by the current server plugin.
 */
GPtrArray* current_server_plugin_dependency_dependencies = NULL;

/**
 * @brief Free any server plugins dependencies.
 */
void
maybe_free_server_plugins_dependencies ()
{
  if (server.plugins_dependencies)
    {
      g_hash_table_destroy (server.plugins_dependencies);
      server.plugins_dependencies = NULL;
    }
}

/**
 * @brief Make the server plugins dependencies.
 */
void
make_server_plugins_dependencies ()
{
  assert (server.plugins_dependencies == NULL);
  server.plugins_dependencies = g_hash_table_new_full (g_str_hash,
                                                       g_str_equal,
                                                       g_free,
                                                       free_g_ptr_array);
}

/**
 * @brief Add a plugin to the server dependencies.
 *
 * @param[in]  name          The name of the plugin.
 * @param[in]  dependencies  The plugins required by the plugin.
 */
void
add_server_plugins_dependency (char* name, GPtrArray* dependencies)
{
  assert (server.plugins_dependencies);
  tracef ("   server new dependency name: %s\n", name);
  g_hash_table_insert (server.plugins_dependencies, name, dependencies);
}

/**
 * @brief Set the current plugin.
 *
 * @param[in]  name  The name of the plugin.
 */
void
make_current_server_plugin_dependency (char* name)
{
  assert (current_server_plugin_dependency_name == NULL);
  assert (current_server_plugin_dependency_dependencies == NULL);
  current_server_plugin_dependency_name = name;
  current_server_plugin_dependency_dependencies = g_ptr_array_new ();
}

/**
 * @brief Append a requirement to the current plugin.
 *
 * @param[in]  dependency  The name of the required plugin.
 */
void
append_to_current_server_plugin_dependency (char* dependency)
{
  assert (current_server_plugin_dependency_dependencies);
  tracef ("   server appending plugin dependency: %s\n", dependency);
  g_ptr_array_add (current_server_plugin_dependency_dependencies, dependency);
}

/**
 * @brief Free any current server plugin dependency information.
 */
void
maybe_free_current_server_plugin_dependency ()
{
  if (current_server_plugin_dependency_name)
    free (current_server_plugin_dependency_name);
  if (current_server_plugin_dependency_dependencies)
    g_ptr_array_free (current_server_plugin_dependency_dependencies, TRUE);
}

/**
 * @brief Add the current plugin to the server dependencies.
 */
void
finish_current_server_plugin_dependency ()
{
  assert (current_server_plugin_dependency_name);
  assert (current_server_plugin_dependency_dependencies);
  add_server_plugins_dependency (current_server_plugin_dependency_name,
                                 current_server_plugin_dependency_dependencies);
  current_server_plugin_dependency_name = NULL;
  current_server_plugin_dependency_dependencies = NULL;
}


/* Server rules. */

/**
 * @brief Free a server rule.
 *
 * @param[in]  rule   The server rule.
 * @param[in]  dummy  Dummy parameter, to please g_ptr_array_foreach.
 */
void
free_rule (void* rule, void* dummy)
{
  free (rule);
}

/**
 * @brief Free any server rules.
 */
void
maybe_free_server_rules ()
{
  if (server.rules)
    {
      g_ptr_array_foreach (server.rules, free_rule, NULL);
      g_ptr_array_free (server.rules, TRUE);
    }
}

/**
 * @brief Create the server rules.
 */
void
make_server_rules ()
{
  server.rules = g_ptr_array_new ();
}

/**
 * @brief Add a rule to the server rules.
 *
 * The rule is used directly (versus using a copy) and is freed with the
 * other server rules.
 *
 * @param[in]  rule  The rule.
 */
void
add_server_rule (char* rule)
{
  g_ptr_array_add (server.rules, rule);
}


/* Tasks. */

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
  short running;              ///< Flag: 0 initially, 1 if running.
  char* start_time;           ///< Time the task last started.
  char* end_time;             ///< Time the task last ended.
  char* attack_state;         ///< Attack status.
  unsigned int current_port;  ///< Port currently under test.
  unsigned int max_port;      ///< Last port to test.
  GArray *open_ports;         ///< Open ports that the server has found.
  int open_ports_size;        ///< Number of open ports.
} task_t;

/**
 * @brief Possible port types.
 */
typedef enum
{
  PORT_PROTOCOL_TCP,
  PORT_PROTOCOL_UDP,
  PORT_PROTOCOL_OTHER
} port_protocol_t;

/**
 * @brief A port.
 */
typedef struct
{
  int number;                ///< Port number.
  port_protocol_t protocol;  ///< Port protocol (TCP, UDP, ...).
} port_t;

/**
 * @brief Reallocation increment for the tasks array.
 */
#define TASKS_INCREMENT 1024

/**
 * @brief Parameter name during OMP MODIFY_TASK.
 */
char* modify_task_parameter = NULL;

/**
 * @brief Task ID during OMP MODIFY_TASK and START_TASK.
 */
char* current_task_task_id = NULL;

/**
 * @brief Parameter value during OMP MODIFY_TASK.
 */
char* modify_task_value = NULL;

/**
 * @brief Current client task during OMP NEW_TASK or MODIFY_TASK.
 */
task_t* current_client_task = NULL;

/**
 * @brief The task currently running on the server.
 */
task_t* current_server_task = NULL;

/**
 * @brief The array of all defined tasks.
 */
task_t* tasks = NULL;

/**
 * @brief The size of the \ref tasks array.
 */
unsigned int tasks_size = 0;

/**
 * @brief The number of the defined tasks.
 */
unsigned int num_tasks = 0;

#if TRACE
/**
 * @brief Print the server tasks.
 */
void
print_tasks ()
{
  task_t *index = tasks;
  tracef ("   tasks: %p\n", tasks);
  tracef ("   tasks end: %p\n", tasks + tasks_size);
  while (index < tasks + tasks_size)
    {
      //tracef ("   index: %p\n", index);
      if (index->name)
        {
          tracef ("   Task %u: \"%s\" %s\n%s\n\n",
                  index->id,
                  index->name,
                  index->comment ?: "",
                  index->description ?: "");
        }
      index++;
    }
}
#endif

/**
 * @brief Grow the array of tasks.
 */
int
grow_tasks ()
{
  tracef ("   task_t size: %i\n", sizeof (task_t));
  task_t* new = realloc (tasks,
                         (tasks_size + TASKS_INCREMENT) * sizeof (task_t));
  if (new == NULL) return -1;
  tasks = new;

  /* Clear the new part of the memory. */
  new = tasks + tasks_size;
  memset (new, '\0', TASKS_INCREMENT * sizeof (task_t));

  tasks_size += TASKS_INCREMENT;
  tracef ("   tasks grown to %i\n", tasks_size);
#if TRACE
  print_tasks ();
#endif
  return 0;
}

/**
 * @brief Free all tasks and the array of tasks.
 */
void
free_tasks ()
{
  task_t* index = tasks;
  task_t* end = tasks + tasks_size;
  while (index < end)
    {
      if (index->name)
        {
          tracef ("   Freeing task %u: \"%s\" %s (%i)\n%s\n\n",
                  index->id,
                  index->name,
                  index->comment,
                  index->description_length,
                  index->description);
          free (index->name);
          free (index->comment);
          free (index->description);
          if (index->start_time) free (index->start_time);
          if (index->end_time) free (index->end_time);
          if (index->open_ports) g_array_free (index->open_ports, TRUE);
        }
      index++;
    }
  tasks_size = 0;
  free (tasks);
  tasks = NULL;
}

/**
 * @brief Make a task.
 *
 * The char* parameters name and comment are used directly and freed
 * when the task is freed.
 *
 * @param[in]  name     The name of the task.
 * @param[in]  time     The period of the task, in seconds.
 * @param[in]  comment  A comment associated the task.
 *
 * @return A pointer to the new task or NULL when out of memory.
 */
task_t*
make_task (char* name, unsigned int time, char* comment)
{
  tracef ("   make_task %s %u %s\n", name, time, comment);
  if (tasks == NULL && grow_tasks ()) return NULL;
  task_t* index = tasks;
  task_t* end = tasks + tasks_size;
  while (1)
    {
      while (index < end)
        {
          if (index->name == NULL)
            {
              index->id = index - tasks;
              index->name = name;
              index->time = time;
              index->comment = comment;
              index->description = NULL;
              index->description_size = 0;
              index->running = 0;
              index->open_ports = NULL;
              tracef ("   Made task %i at %p\n", index->id, index);
              num_tasks++;
              return index;
            }
          index++;
        }
      index = (task_t*) tasks_size;
      if (grow_tasks ()) return NULL;
      index = index + (int) tasks;
    }
}

/**
 * @brief Find a task.
 *
 * @param[in]  id  A task identifier.
 *
 * @return A pointer to the task with the given ID.
 */
task_t*
find_task (unsigned int id)
{
  task_t* index = tasks;
  task_t* end = tasks + tasks_size;
  while (index < end) {
    if (index->name) tracef ("   %u vs %u\n", index->id, id);
    if (index->name && index->id == id) return index; else index++;
  }
  return NULL;
}

/**
 * @brief Modify a task.
 *
 * The char* parameters are used directly and freed when the task is
 * freed.
 *
 * @param[in]  task     A pointer to a task.
 * @param[in]  name     The new name for the task.
 * @param[in]  time     The new period for the task, in seconds.
 * @param[in]  comment  A new comment associcated with the task.
 */
void
modify_task (task_t* task, char* name, unsigned int time, char* comment)
{
  assert (task->name);
  tracef ("   modify_task %u\n", task->id);
  task->name = name;
  task->time = time;
  task->comment = comment;
  task->description_length = 0;
}

/**
 * @brief Set a task parameter.
 *
 * The value parameter is used directly and freed when the task is
 * freed.
 *
 * @param[in]  task       A pointer to a task.
 * @param[in]  parameter  The name of the parameter.
 * @param[in]  value      The value of the parameter.
 *
 * @return 0 on success, -1 when out of memory, -2 if parameter name error.
 */
int
set_task_parameter (task_t* task, char* parameter, char* value)
{
  tracef ("   set_task_parameter %u %s\n", task->id, parameter);
  if (strncasecmp ("TASK_FILE", parameter, 9) == 0)
    {
      task->description = value;
      task->description_length = strlen (value);;
    }
  else if (strncasecmp ("IDENTIFIER", parameter, 10) == 0)
    {
      unsigned int id;
      if (sscanf (value, "%u", &id) != 1) return -1;
      free (value);
      task->id = id;
    }
  else if (strncasecmp ("COMMENT", parameter, 7) == 0)
    {
      task->comment = value;
    }
  else
    return -2;
  return 0;
}

/**
 * @brief Start a task.
 *
 * @param  task  A pointer to the task.
 *
 * @return 0 on success, -1 if out of space in \ref to_server buffer.
 */
int
start_task (task_t* task)
{
  tracef ("   start task %u\n", task->id);

  if (send_to_server ("CLIENT <|> PREFERENCES <|>\n")) return -1;

  if (send_to_server ("plugin_set <|> ")) return -1;
#if 0
  if (send_to_server (task_plugins (task))) return -1;
#endif
  if (send_to_server ("\n")) return -1;
#if 0
  queue_task_preferences (task);
  queue_task_plugin_preferences (task);
#endif
  if (send_to_server ("<|> CLIENT\n")) return -1;

  if (send_to_server ("CLIENT <|> RULES <|>\n")) return -1;
#if 0
  queue_task_rules (task);
#endif
  if (send_to_server ("<|> CLIENT\n")) return -1;

#if 0
  char* targets = task_preference (task, "targets");
  if (send_to_server ("CLIENT <|> LONG_ATTACK <|>\n%d\n%s\n",
                      strlen (targets),
                      targets))
    return -1;
#else
  if (send_to_server ("CLIENT <|> LONG_ATTACK <|>\n6\nchiles\n"))
    return -1;
#endif

  task->running = 1;
  if (task->open_ports) g_array_free (task->open_ports, TRUE);
  task->open_ports = g_array_new (FALSE, FALSE, sizeof (port_t));
  task->open_ports_size = 0;
  current_server_task = task;

  return 0;
}

/**
 * @brief Append text to the comment associated with a task.
 *
 * @param  task    A pointer to the task.
 * @param  text    The text to append.
 * @param  length  Length of the text.
 *
 * @return 0 on success, -1 if out of memory.
 */
int
append_to_task_comment (task_t* task, const char* text, int length)
{
  if (task->comment)
    {
      // FIX
      char* new = g_strconcat (task->comment, text, NULL);
      task->comment = new;
      return 0;
    }
  task->comment = strdup (text);
  return task->comment == NULL;
}

/**
 * @brief Append text to the identifier associated with a task.
 *
 * @param  task    A pointer to the task.
 * @param  text    The text to append.
 * @param  length  Length of the text.
 *
 * @return 0 on success, 1 if out of memory.
 */
int
append_to_task_identifier (task_t* task, const char* text, int length)
{
  if (task->name)
    {
      // FIX
      char* new = g_strconcat (task->name, text, NULL);
      task->name = new;
      return 0;
    }
  task->name = strdup (text);
  return task->name == NULL;
}

/**
 * @brief Reallocation increment for a task description.
 */
#define DESCRIPTION_INCREMENT 4096

/**
 * @brief Increase the memory allocated for a task description.
 *
 * @param  task       A pointer to the task.
 * @param  increment  Minimum number of bytes to increase memory.
 *
 * @return 0 on success, -1 if out of memory.
 */
int
grow_description (task_t* task, int increment)
{
  int new_size = task->description_size
                 + (increment < DESCRIPTION_INCREMENT
                    ? DESCRIPTION_INCREMENT : increment);
  char* new = realloc (task->description, new_size);
  if (new == NULL) return -1;
  tracef ("  grew description to %i.\n", new_size);
  task->description = new;
  task->description_size = new_size;
  return 0;
}

/**
 * @brief Add a line to a task description.
 *
 * The line memory is used directly, and freed with the task.
 *
 * @param[in]  task         A pointer to the task.
 * @param[in]  line         The line.
 * @param[in]  line_length  The length of the line.
 */
int
add_task_description_line (task_t* task, const char* line, int line_length)
{
  if (task->description_size - task->description_length < line_length
      && grow_description (task, line_length))
    return -1;
  char* description = task->description;
  description += task->description_length;
  strncpy (description, line, line_length);
  task->description_length += line_length;
  return 0;
}

/**
 * @brief Set the ports of a task.
 *
 * @param[in]  task     The task.
 * @param[in]  current  New value for port currently being scanned.
 * @param[in]  max      New value for last port to be scanned.
 */
void
set_task_ports (task_t *task, unsigned int current, unsigned int max)
{
  task->current_port = current;
  task->max_port = max;
}

/**
 * @brief Add an open port to a task.
 *
 * @param[in]  task       The task.
 * @param[in]  number     The port number.
 * @param[in]  protocol   The port protocol.
 */
void
append_task_open_port (task_t *task, unsigned int number, char* protocol)
{
  port_t port;

  port.number = number;
  if (strncasecmp ("udp", protocol, 3) == 0)
    port.protocol = PORT_PROTOCOL_UDP;
  else if (strncasecmp ("tcp", protocol, 3) == 0)
    port.protocol = PORT_PROTOCOL_TCP;
  else
    port.protocol = PORT_PROTOCOL_OTHER;

  g_array_append_val (task->open_ports, port);
  task->open_ports++;
}


/* OpenVAS Transfer Protocol (OTP). */

/**
 * @brief Serve the OpenVAS Transfer Protocol (OTP).
 *
 * @param[in]  client_session  The TLS session with the client.
 * @param[in]  server_session  The TLS session with the server.
 * @param[in]  client_socket   The socket connected to the client.
 * @param[in]  server_socket   The socket connected to the server.
 *
 * @return 0 on success, -1 on error.
 */
int
serve_otp (gnutls_session_t* client_session,
           gnutls_session_t* server_session,
           int client_socket, int server_socket)
{
  /* Handle the first client input, which was read by `read_protocol'. */
#if TRACE || LOG
  logf ("<= %.*s\n", from_client_end, from_client);
#if TRACE_TEXT
  tracef ("<= client  \"%.*s\"\n", from_client_end, from_client);
#else
  tracef ("<= client  %i bytes\n", from_client_end - initial_start);
#endif
#endif /* TRACE || LOG */

  /* Loop handling input from the sockets. */
  int nfds = 1 + (client_socket > server_socket
                  ? client_socket : server_socket);
  fd_set readfds, exceptfds, writefds;
  while (1)
    {
      /* Setup for select. */
      unsigned char fds = 0; /* What `select' is going to watch. */
      FD_ZERO (&exceptfds);
      FD_ZERO (&readfds);
      FD_ZERO (&writefds);
      FD_SET (client_socket, &exceptfds);
      FD_SET (server_socket, &exceptfds);
      if (from_client_end < BUFFER_SIZE)
        {
          FD_SET (client_socket, &readfds);
          fds |= FD_CLIENT_READ;
        }
      if (from_server_end < BUFFER_SIZE)
        {
          FD_SET (server_socket, &readfds);
          fds |= FD_SERVER_READ;
        }
      if (from_server_start < from_server_end)
        {
          FD_SET (client_socket, &writefds);
          fds |= FD_CLIENT_WRITE;
        }
      if (from_client_start < from_client_end)
        {
          FD_SET (server_socket, &writefds);
          fds |= FD_SERVER_WRITE;
        }

      /* Select, then handle result. */
      int ret = select (nfds, &readfds, &writefds, &exceptfds, NULL);
      if (ret < 0)
        {
          if (errno == EINTR) continue;
          perror ("Child select failed");
          return -1;
        }
      if (ret > 0)
        {
          if (FD_ISSET (client_socket, &exceptfds))
            {
              fprintf (stderr, "Exception on client in child select.\n");
              return -1;
            }

          if (FD_ISSET (server_socket, &exceptfds))
            {
              fprintf (stderr, "Exception on server in child select.\n");
              return -1;
            }

          if (fds & FD_CLIENT_READ && FD_ISSET (client_socket, &readfds))
            {
#if TRACE || LOG
              int initial_start = from_client_end;
#endif
              /* Read as much as possible from the client. */
              while (from_client_end < BUFFER_SIZE)
                {
                  ssize_t count;
                  count = gnutls_record_recv (*client_session,
                                              from_client + from_client_end,
                                              BUFFER_SIZE
                                              - from_client_end);
                  if (count < 0)
                    {
                      if (count == GNUTLS_E_AGAIN)
                        /* Got everything available, return to `select'. */
                        break;
                      if (count == GNUTLS_E_INTERRUPTED)
                        /* Interrupted, try read again. */
                        continue;
                      if (count == GNUTLS_E_REHANDSHAKE)
                        /* Return to select. TODO Rehandshake. */
                        break;
                      fprintf (stderr, "Failed to read from client.\n");
                      gnutls_perror (count);
                      return -1;
                    }
                  if (count == 0)
                    /* End of file. */
                    return 0;
                  from_client_end += count;
                }
#if TRACE || LOG
              /* This check prevents output in the "asynchronous network
               * error" case. */
              if (from_client_end > initial_start)
                {
                  logf ("<= %.*s\n",
                        from_client_end - initial_start,
                        from_client + initial_start);
#if TRACE_TEXT
                  tracef ("<= client  \"%.*s\"\n",
                          from_client_end - initial_start,
                          from_client + initial_start);
#else
                  tracef ("<= client  %i bytes\n",
                          from_client_end - initial_start);
#endif
                }
#endif /* TRACE || LOG */
            }

          if (fds & FD_SERVER_WRITE && FD_ISSET (server_socket, &writefds))
            {
              gboolean wrote_all = TRUE;
              /* Write as much as possible to the server. */
              while (from_client_start < from_client_end)
                {
                  ssize_t count;
                  count = gnutls_record_send (*server_session,
                                              from_client + from_client_start,
                                              from_client_end - from_client_start);
                  if (count < 0)
                    {
                      if (count == GNUTLS_E_AGAIN)
                        {
                          /* Wrote as much server would accept, return to
                           * `select'. */
                          wrote_all = FALSE;
                          break;
                        }
                      if (count == GNUTLS_E_INTERRUPTED)
                        /* Interrupted, try write again. */
                        continue;
                      if (count == GNUTLS_E_REHANDSHAKE)
                        /* Return to select. TODO Rehandshake. */
                        break;
                      fprintf (stderr, "Failed to write to server.\n");
                      gnutls_perror (count);
                      return -1;
                    }
                  from_client_start += count;
                  tracef ("=> server  %i bytes\n", count);
                }
              if (wrote_all)
                {
                  tracef ("=> server  done\n");
                  from_client_start = from_client_end = 0;
                }
            }

          if (fds & FD_SERVER_READ && FD_ISSET (server_socket, &readfds))
            {
#if TRACE
              int initial_start = from_server_end;
#endif
              /* Read as much as possible from the server. */
              while (from_server_end < BUFFER_SIZE)
                {
                  ssize_t count;
                  count = gnutls_record_recv (*server_session,
                                              from_server + from_server_end,
                                              BUFFER_SIZE
                                              - from_server_end);
                  if (count < 0)
                    {
                      if (count == GNUTLS_E_AGAIN)
                        /* Got everything available, return to `select'. */
                        break;
                      if (count == GNUTLS_E_INTERRUPTED)
                        /* Interrupted, try read again. */
                        continue;
                      if (count == GNUTLS_E_REHANDSHAKE)
                        /* Return to select. TODO Rehandshake. */
                        break;
                      fprintf (stderr, "Failed to read from server.\n");
                      gnutls_perror (count);
                      return -1;
                    }
                  if (count == 0)
                    /* End of file. */
                    return 0;
                  from_server_end += count;
                }
#if TRACE
              /* This check prevents output in the "asynchronous network
               * error" case. */
              if (from_server_end > initial_start)
                {
#if TRACE_TEXT
                  tracef ("<= server  \"%.*s\"\n",
                          from_server_end - initial_start,
                          from_server + initial_start);
#else
                  tracef ("<= server  %i bytes\n",
                          from_server_end - initial_start);
#endif
                }
#endif /* TRACE */
            }

          if (fds & FD_CLIENT_WRITE && FD_ISSET (client_socket, &writefds))
            {
              gboolean wrote_all = TRUE;

              /* Write as much as possible to the client. */
              while (from_server_start < from_server_end)
                {
                  ssize_t count;
                  count = gnutls_record_send (*client_session,
                                              from_server + from_server_start,
                                              from_server_end - from_server_start);
                  if (count < 0)
                    {
                      if (count == GNUTLS_E_AGAIN)
                        {
                          /* Wrote as much as possible, return to `select'. */
                          wrote_all = FALSE;
                          break;
                        }
                      if (count == GNUTLS_E_INTERRUPTED)
                        /* Interrupted, try write again. */
                        continue;
                      if (count == GNUTLS_E_REHANDSHAKE)
                        /* Return to select. TODO Rehandshake. */
                        break;
                      fprintf (stderr, "Failed to write to client.\n");
                      gnutls_perror (count);
                      return -1;
                    }
                  logf ("=> %.*s\n",
                        from_server_end - from_server_start,
                        from_server + from_server_start);
                  from_server_start += count;
                  tracef ("=> client  %i bytes\n", count);
                }
              if (wrote_all)
                {
                  tracef ("=> client  done\n");
                  from_server_start = from_server_end = 0;
                }
            }
        }
    }
}


/* OpenVAS Management Protocol (OMP). */

/**
 * @brief Send a response message to the client.
 *
 * @param[in]  msg  The message, a string.
 */
#define RESPOND(msg)                                              \
  do                                                              \
    {                                                             \
      if (BUFFER_SIZE - to_client_end < strlen (msg))             \
        {                                                         \
          (messages - 1)[0] = '\n';                               \
          if (command) (message - 1)[0] = ' ';                    \
          goto respond_fail;                                      \
        }                                                         \
      memcpy (to_client + to_client_end, msg, strlen (msg));      \
      tracef ("-> client: %s\n", msg);                            \
      to_client_end += strlen (msg);                              \
    }                                                             \
  while (0)

/**
 * @brief Process any lines available in from_client.
 *
 * Queue any resulting server commands in to_server and any replies for
 * the client in to_client.
 *
 * @return 0 success, -1 error, -2 or -3 too little space in to_client or to_server.
 */
int
process_omp_old_client_input ()
{
  char* messages = from_client + from_client_start;
  int original_from_client_start;
  //tracef ("   consider %.*s\n", from_client_end - from_client_start, messages);
  while (memchr (messages, 10, from_client_end - from_client_start))
    {
      /* Found a full line, process the message. */
      original_from_client_start = from_client_start;
      char* command = NULL;
#if 0
      tracef ("   messages: %.*s...\n",
              from_client_end - from_client_start < 200
              ? from_client_end - from_client_start
              : 200,
              messages);
#endif
      char* message = strsep (&messages, "\n");
      tracef ("   message: %s\n", message);
      from_client_start += strlen(message) + 1;

      if (current_client_task)
        {
          /* A NEW_TASK or MODIFY_TASK description is being read. */

          if (strlen (message) == 1 && message[0] == '.')
            {
              /* End of description marker. */
              char response[16];
              sprintf (response, "201 %i\n", current_client_task->id);
              RESPOND (response);
              current_client_task = NULL;
              continue;
            }
          else if (strlen (message) > 1 && message[0] == '.')
            {
              /* Line of description starting with a '.'.  The client is
               * required to add an extra '.' to the front of the line. */
              message += 1;
            }

          if (add_task_description_line (current_client_task,
                                         message,
                                         messages - message))
            goto out_of_memory;

          continue;
        }

      command = strsep (&message, " ");
      tracef ("   command: %s\n", command);

      if (strncasecmp ("OMP_VERSION", command, 11) == 0)
        RESPOND ("200 1.0\n");
      else if (strncasecmp ("LOGIN", command, 5) == 0)
        {
          char* next = strsep (&message, " ");
          if (next == message || next == NULL || strlen (next) == 0)
            RESPOND ("403 LOGIN requires a username.\n");
          else
            {
              if (login) free (login);
              login = strdup (next);
              if (login == NULL) goto out_of_memory;
              next = strsep (&message, " ");
              if (next && strlen (next) > 0)
                {
                  if (credentials) free (credentials);
                  credentials = strdup (next);
                  if (credentials == NULL) goto out_of_memory;
                }
              RESPOND ("202\n");
            }
        }
      else if (login == NULL)
        RESPOND ("401 LOGIN first.\n");
      else if (strncasecmp ("NEW_TASK", command, 8) == 0)
        {
          /* Scan name. */
          char* next = strsep (&message, " ");
          if (next == message || next == NULL || strlen (next) == 0)
            {
              // FIX flush rest of command
              RESPOND ("404 NEW_TASK requires a name.\n");
              continue;
            }
          tracef ("   next %s\n", next);
          // FIX parse name with spaces
          char* name = strdup (next);
          if (name == NULL) goto out_of_memory;
          next = strsep (&message, " ");
          if (next == message || next == NULL || strlen (next) == 0)
            {
              // FIX flush rest of command
              RESPOND ("405 NEW_TASK requires a time.\n");
              continue;
            }
          tracef ("   next %s\n", next);
          /* Scan time. */
          int time;
          if (sscanf (next, "%u", &time) != 1)
            {
              // FIX flush rest of command
              RESPOND ("406 Failed to parse ID.\n");
              continue;
            }
          /* Scan comment. */
          char* comment = strdup (message);
          if (comment == NULL)
            {
              free (name);
              goto out_of_memory;
            }
          /* Make task. */
          current_client_task = make_task (name, time, comment);
          if (current_client_task == NULL)
            {
              free (name);
              free (comment);
              goto out_of_memory;
            }
        }
      else if (strncasecmp ("MODIFY_TASK", command, 11) == 0)
        {
          char* next = strsep (&message, " ");
          if (next == message || next == NULL || strlen (next) == 0)
            {
              // FIX flush rest of command
              RESPOND ("405 Command requires a task ID.\n");
              continue;
            }
          unsigned int id;
          if (sscanf (next, "%u", &id) != 1)
            {
              RESPOND ("406 Failed to parse ID.\n");
              // FIX flush rest of command
              continue;
            }
          current_client_task = find_task (id);
          if (current_client_task == NULL)
            {
              RESPOND ("407 Failed to find task.\n");
              // FIX flush rest of command
              continue;
            }
          // -- FIX same as above
          /* Scan name. */
          next = strsep (&message, " ");
          if (next == message || next == NULL || strlen (next) == 0)
            {
              // FIX flush rest of command
              RESPOND ("404 NEW_TASK requires a name.\n");
              continue;
            }
          // FIX parse name with spaces
          char* name = strdup (next);
          if (name == NULL) goto out_of_memory;
          next = strsep (&message, " ");
          if (next == message || next == NULL || strlen (next) == 0)
            {
              // FIX flush rest of command
              RESPOND ("405 NEW_TASK requires a time.\n");
              free (name);
              continue;
            }
          /* Scan time. */
          int time;
          if (sscanf (next, "%u", &time) != 1)
            {
              // FIX flush rest of command
              RESPOND ("406 Failed to parse ID.\n");
              free (name);
              continue;
            }
          /* Scan comment. */
          char* comment = strdup (message);
          if (comment == NULL)
            {
              free (name);
              goto out_of_memory;
            }
          // --
          modify_task (current_client_task, name, time, comment);
        }
      else if (strncasecmp ("START_TASK", command, 10) == 0)
        {
          // -- FIX same as above
          char* next = strsep (&message, " ");
          if (next == message || next == NULL || strlen (next) == 0)
            {
              // FIX flush rest of command
              RESPOND ("405 Command requires a task ID.\n");
              continue;
            }
          unsigned int id;
          if (sscanf (next, "%u", &id) != 1)
            {
              RESPOND ("406 Failed to parse ID.\n");
              // FIX flush rest of command
              continue;
            }
          // --
          task_t *task = find_task (id);
          if (task == NULL)
            RESPOND ("407 Failed to find task.\n");
          else if (start_task (task))
            {
              /* to_server is full. */
              from_client_start = original_from_client_start;
              /* Revert parsing. */
              (message - 1)[0] = ' ';
              (messages - 1)[0] = '\n';
              return -2;
            }
          else
            RESPOND ("203\n");
        }
      else if (strncasecmp ("STATUS", command, 6) == 0)
        {
#if 0
          // -- FIX same as above
          char* next = strsep (&message, " ");
          if (next == message || next == NULL || strlen (next) == 0)
            {
              // FIX flush rest of command
              RESPOND ("405 Command requires a task ID.\n");
              continue;
            }
          unsigned int id;
          if (sscanf (next, "%u", &id) != 1)
            {
              RESPOND ("406 Failed to parse ID.\n");
              // FIX flush rest of command
              continue;
            }
          // --
#endif
          char response[16];
          sprintf (response, "210 %u\n", num_tasks);
          RESPOND (response);
          task_t* index = tasks;
          task_t* end = tasks + tasks_size;
          while (index < end)
            {
              if (index->name)
                {
                  gchar* line = g_strdup_printf ("%u %s %c . . . . .\n",
                                                 index->id,
                                                 index->name,
                                                 index->running ? 'R' : 'N');
                  if (line == NULL) goto out_of_memory;
                  // FIX free line if RESPOND fails
                  RESPOND (line);
                  g_free (line);
                }
              index++;
            }
        }
      else
        RESPOND ("402 Command name error.\n");

      continue;
 out_of_memory:
      RESPOND ("501 Manager out of memory.\n");
    } /* while (memchr (... */

  if (from_client_start > 0 && from_client_start == from_client_end)
    {
      from_client_start = from_client_end = 0;
      tracef ("   client start caught end\n");
    }
  else if (from_client_start == 0)
    {
      if (from_client_end == BUFFER_SIZE)
        {
          // FIX if the buffer is entirely full here then respond with err and close connection
          //     (or will hang waiting for buffer to empty)
          //     this could happen if the client sends a field with length >= buffer length
          //         could realloc buffer
          //             which may eventually use all mem and bring down manager
          tracef ("   client buffer full\n");
          return -1;
        }
    }
  else
    {
      /* Move the remaining partial line to the front of the buffer.  This
       * ensures that there is space after the partial line into which
       * serve_omp can read the rest of the line. */
      char* start = from_client + from_client_start;
      from_client_end -= from_client_start;
      memmove (from_client, start, from_client_end);
      from_client_start = 0;
#if TRACE
      from_client[from_client_end] = '\0';
      //tracef ("   new from_client: %s\n", from_client);
      tracef ("   new from_client_start: %i\n", from_client_start);
      tracef ("   new from_client_end: %i\n", from_client_end);
#endif
    }

  return 0;

  /* RESPOND jumps here when there is too little space in to_client for the
   * response.  The result is that the manager closes the connection, so
   * from_client_end and from_client_start can be left as they are. */
 respond_fail:
  tracef ("   RESPOND out of space in to_client\n");
  from_client_start = original_from_client_start;
  return -3;
}

/**
 * @brief Send a response message to the client.
 *
 * @param[in]  msg  The message, a string.
 */
#define XML_RESPOND(msg)                                          \
  do                                                              \
    {                                                             \
      if (BUFFER_SIZE - to_client_end < strlen (msg))             \
        goto respond_fail;                                        \
      memcpy (to_client + to_client_end, msg, strlen (msg));      \
      tracef ("-> client: %s\n", msg);                            \
      to_client_end += strlen (msg);                              \
    }                                                             \
  while (0)

/**
 * @brief Handle the start of an OMP XML element.
 *
 * @param[in]  context           Parser context.
 * @param[in]  element_name      XML element name.
 * @param[in]  attribute_names   XML attribute name.
 * @param[in]  attribute_values  XML attribute values.
 * @param[in]  user_data         Dummy parameter.
 * @param[in]  error             Error parameter.
 */
void
omp_xml_handle_start_element (GMarkupParseContext* context,
                              const gchar *element_name,
                              const gchar **attribute_names,
                              const gchar **attribute_values,
                              gpointer user_data,
                              GError **error)
{
  tracef ("   XML  start: %s\n", element_name);

  switch (client_state)
    {
      case CLIENT_TOP:
        if (strncasecmp ("MODIFY_TASK", element_name, 11) == 0)
          set_client_state (CLIENT_MODIFY_TASK);
        else if (strncasecmp ("NEW_TASK", element_name, 8) == 0)
          {
            assert (current_client_task == NULL);
            current_client_task = make_task (NULL, 0, NULL);
            if (current_client_task == NULL) abort (); // FIX
            set_client_state (CLIENT_NEW_TASK);
          }
        else if (strncasecmp ("OMP_VERSION", element_name, 11) == 0)
          set_client_state (CLIENT_VERSION);
        else if (strncasecmp ("START_TASK", element_name, 10) == 0)
          set_client_state (CLIENT_START_TASK);
        else if (strncasecmp ("STATUS", element_name, 6) == 0)
          {
            current_task_task_id = NULL;
            set_client_state (CLIENT_STATUS);
          }
        else
          XML_RESPOND ("<omp_response><status>402</status></omp_response>");
        break;

      case CLIENT_MODIFY_TASK:
        if (strncasecmp ("TASK_ID", element_name, 7) == 0)
          set_client_state (CLIENT_MODIFY_TASK_TASK_ID);
        else if (strncasecmp ("PARAMETER", element_name, 9) == 0)
          set_client_state (CLIENT_MODIFY_TASK_PARAMETER);
        else if (strncasecmp ("VALUE", element_name, 5) == 0)
          set_client_state (CLIENT_MODIFY_TASK_VALUE);
        else
          {
            XML_RESPOND ("<modify_task_response><status>402</status></modify_task_response>");
            set_client_state (CLIENT_TOP);
            // FIX notify parser of error
          }
        break;

      case CLIENT_NEW_TASK:
        if (strncasecmp ("TASK_FILE", element_name, 9) == 0)
          set_client_state (CLIENT_NEW_TASK_TASK_FILE);
        else if (strncasecmp ("IDENTIFIER", element_name, 10) == 0)
          set_client_state (CLIENT_NEW_TASK_IDENTIFIER);
        else if (strncasecmp ("COMMENT", element_name, 7) == 0)
          set_client_state (CLIENT_NEW_TASK_COMMENT);
        else
          {
            XML_RESPOND ("<new_task_response><status>402</status></new_task_response>");
            set_client_state (CLIENT_TOP);
            // FIX notify parser of error (more above,below)
          }
        break;

      case CLIENT_START_TASK:
        if (strncasecmp ("TASK_ID", element_name, 7) == 0)
          set_client_state (CLIENT_START_TASK_TASK_ID);
        else
          {
            XML_RESPOND ("<start_task_response><status>402</status></start_task_response>");
            set_client_state (CLIENT_TOP);
            // FIX notify parser of error
          }
        break;

      case CLIENT_STATUS:
        if (strncasecmp ("TASK_ID", element_name, 7) == 0)
          set_client_state (CLIENT_STATUS_TASK_ID);
        else
          {
            XML_RESPOND ("<status_response><status>402</status></status_task_response>");
            set_client_state (CLIENT_TOP);
            // FIX notify parser of error
          }
        break;

      default:
        // FIX respond fail to client
        assert (0);
        break;
    }

  return;

 respond_fail:
  tracef ("   XML RESPOND out of space in to_client\n");
  g_set_error (error, G_MARKUP_ERROR, G_MARKUP_ERROR_UNKNOWN_ELEMENT,
               "Out of space for reply to client.\n");
}

/**
 * @brief Handle the end of an OMP XML element.
 *
 * @param[in]  context           Parser context.
 * @param[in]  element_name      XML element name.
 * @param[in]  user_data         Dummy parameter.
 * @param[in]  error             Error parameter.
 */
void
omp_xml_handle_end_element (GMarkupParseContext* context,
                            const gchar *element_name,
                            gpointer user_data,
                            GError **error)
{
  tracef ("   XML    end: %s\n", element_name);
  switch (client_state)
    {
      case CLIENT_TOP:
        assert (0);
        break;

      case CLIENT_VERSION:
        XML_RESPOND ("<omp_version_response><status>200</status><version preferred=\"yes\">1.0</version></omp_version_response>");
        set_client_state (CLIENT_TOP);
        break;

      case CLIENT_MODIFY_TASK:
        {
          assert (current_client_task == NULL);
          unsigned int id;
          if (sscanf (current_task_task_id, "%u", &id) != 1)
            XML_RESPOND ("<modify_task_response><status>40x</status></modify_task_response>");
          else
            {
              current_client_task = find_task (id);
              if (current_client_task == NULL)
                XML_RESPOND ("<modify_task_response><status>407</status></modify_task_response>");
              else
                {
                  // FIX check if param,value else respond fail
                  int fail = set_task_parameter (current_client_task,
                                                 modify_task_parameter,
                                                 modify_task_value);
                  free (modify_task_parameter);
                  modify_task_parameter = NULL;
                  if (fail)
                    {
                      free (modify_task_parameter);
                      modify_task_value = NULL;
                      XML_RESPOND ("<modify_task_response><status>40x</status></modify_task_response>");
                    }
                  else
                    {
                      modify_task_value = NULL;
                      XML_RESPOND ("<modify_task_response><status>201</status></modify_task_response>");
                    }
                }
            }
          set_client_state (CLIENT_TOP);
        }
        break;
      case CLIENT_MODIFY_TASK_PARAMETER:
        assert (strncasecmp ("PARAMETER", element_name, 9) == 0);
        set_client_state (CLIENT_MODIFY_TASK);
        break;
      case CLIENT_MODIFY_TASK_TASK_ID:
        assert (strncasecmp ("TASK_ID", element_name, 7) == 0);
        set_client_state (CLIENT_MODIFY_TASK);
        break;
      case CLIENT_MODIFY_TASK_VALUE:
        assert (strncasecmp ("VALUE", element_name, 5) == 0);
        set_client_state (CLIENT_MODIFY_TASK);
        break;

      case CLIENT_NEW_TASK:
        assert (strncasecmp ("NEW_TASK", element_name, 7) == 0);
        assert (current_client_task);
        // FIX if all rqrd fields given then ok, else respond fail
        gchar* msg;
        msg = g_strdup_printf ("<new_task_response><status>201</status><task_id>%u</task_id></new_task_response>",
                               current_client_task->id);
        // FIX free msg if fail
        XML_RESPOND (msg);
        free (msg);
        current_client_task = NULL;
        set_client_state (CLIENT_TOP);
        break;
      case CLIENT_NEW_TASK_COMMENT:
        assert (strncasecmp ("COMMENT", element_name, 12) == 0);
        set_client_state (CLIENT_NEW_TASK);
        break;
      case CLIENT_NEW_TASK_IDENTIFIER:
        assert (strncasecmp ("IDENTIFIER", element_name, 10) == 0);
        set_client_state (CLIENT_NEW_TASK);
        break;
      case CLIENT_NEW_TASK_TASK_FILE:
        assert (strncasecmp ("TASK_FILE", element_name, 9) == 0);
        set_client_state (CLIENT_NEW_TASK);
        break;

      case CLIENT_START_TASK:
        {
          assert (current_client_task == NULL);
          unsigned int id;
          if (sscanf (current_task_task_id, "%u", &id) != 1)
            XML_RESPOND ("<start_task_response><status>40x</status></start_task_response>");
          else
            {
              task_t* task = find_task (id);
              if (task == NULL)
                XML_RESPOND ("<start_task_response><status>407</status></start_task_response>");
              else if (start_task (task))
                {
                  /* to_server is full. */
                  // FIX revert parsing for retry
                  // process_omp_client_input must return -2
                  abort ();
                }
              else
                XML_RESPOND ("<start_task_response><status>201</status></start_task_response>");
            }
          set_client_state (CLIENT_TOP);
        }
        break;
      case CLIENT_START_TASK_TASK_ID:
        assert (strncasecmp ("TASK_ID", element_name, 7) == 0);
        set_client_state (CLIENT_START_TASK);
        break;

      case CLIENT_STATUS:
        assert (strncasecmp ("STATUS", element_name, 6) == 0);
        XML_RESPOND ("<status_response><status>200</status>");
        if (current_task_task_id)
          {
            unsigned int id;
            if (sscanf (current_task_task_id, "%u", &id) != 1)
              XML_RESPOND ("<status_response><status>40x</status></status_response>");
            else
              {
                task_t* task = find_task (id);
                if (task == NULL)
                  XML_RESPOND ("<status_response><status>407</status></status_response>");
                else
                  {
                    gchar* response;
                    response = g_strdup_printf ("<report_count>%u</report_count>",
                                                0);
                                                //task->report_count);
                    XML_RESPOND (response);
                  }
              }
          }
        else
          {
            gchar* response = g_strdup_printf ("<task_count>%u</task_count>", num_tasks);
            XML_RESPOND (response);
            task_t* index = tasks;
            task_t* end = tasks + tasks_size;
            while (index < end)
              {
                if (index->name)
                  {
                    gchar* line = g_strdup_printf ("<task>\
                                                      <task_id>%u</task_id>\
                                                      <identifier>%s</identifier>\
                                                      <task_status>%s</task_status>\
                                                      <messages>\
                                                        <hole></hole>\
                                                        <warning></warning>\
                                                        <info></info>\
                                                        <log></log>\
                                                        <debug></debug>\
                                                      </messages>\
                                                    </task>",
                                                   index->id,
                                                   index->name,
                                                   index->running ? "Running" : "New");
                    // FIX free line if RESPOND fails
                    XML_RESPOND (line);
                    g_free (line);
                  }
                index++;
              }
          }
        XML_RESPOND ("</status_response>");
        set_client_state (CLIENT_TOP);
        break;
      case CLIENT_STATUS_TASK_ID:
        assert (strncasecmp ("TASK_ID", element_name, 7) == 0);
        set_client_state (CLIENT_STATUS);
        break;

      default:
        assert (0);
        break;
    }

  return;

 respond_fail:
  tracef ("   XML RESPOND out of space in to_client\n");
  g_set_error (error, G_MARKUP_ERROR, G_MARKUP_ERROR_UNKNOWN_ELEMENT,
               "Out of space for reply to client.\n");
}

/**
 * @brief Handle additional text of an OMP XML element.
 *
 * @param[in]  context           Parser context.
 * @param[in]  text              The text.
 * @param[in]  text_len          Length of the text.
 * @param[in]  user_data         Dummy parameter.
 * @param[in]  error             Error parameter.
 */
void
omp_xml_handle_text (GMarkupParseContext* context,
                     const gchar *text,
                     gsize text_len,
                     gpointer user_data,
                     GError **error)
{
  if (text_len == 0) return;
  tracef ("   XML   text: %s\n", text);
  switch (client_state)
    {
      case CLIENT_MODIFY_TASK_PARAMETER:
        if (modify_task_parameter)
          {
            // FIX
            char* new = g_strconcat (modify_task_parameter, text, NULL);
            modify_task_parameter = new;
          }
        else
          {
            modify_task_parameter = strdup (text);
            if (modify_task_parameter == NULL) abort (); // FIX
          }
        break;
      case CLIENT_MODIFY_TASK_TASK_ID:
        if (current_task_task_id)
          {
            // FIX
            char* new = g_strconcat (current_task_task_id, text, NULL);
            current_task_task_id = new;
          }
        else
          {
            current_task_task_id = strdup (text);
            if (current_task_task_id == NULL) abort (); // FIX
          }
        break;
      case CLIENT_MODIFY_TASK_VALUE:
        if (modify_task_value)
          {
            // FIX
            char* new = g_strconcat (modify_task_value, text, NULL);
            modify_task_value = new;
          }
        else
          {
            modify_task_value = strdup (text);
            if (modify_task_value == NULL) abort (); // FIX
          }
        break;

      case CLIENT_NEW_TASK_COMMENT:
        append_to_task_comment (current_client_task, text, text_len);
        break;
      case CLIENT_NEW_TASK_IDENTIFIER:
        append_to_task_identifier (current_client_task, text, text_len);
        break;
      case CLIENT_NEW_TASK_TASK_FILE:
        /* Append the text to the task description. */
        if (add_task_description_line (current_client_task,
                                       text,
                                       text_len))
          abort (); // FIX out of mem
        break;

      case CLIENT_START_TASK_TASK_ID:
      case CLIENT_STATUS_TASK_ID:
        if (current_task_task_id)
          {
            // FIX
            char* new = g_strconcat (current_task_task_id, text, NULL);
            current_task_task_id = new;
          }
        else
          {
            current_task_task_id = strdup (text);
            if (current_task_task_id == NULL) abort (); // FIX
          }
        break;

      default:
        /* Just pass over the text. */
        break;
    }
}

/**
 * @brief Handle an OMP XML parsing error.
 *
 * @param[in]  context           Parser context.
 * @param[in]  error             The error.
 * @param[in]  user_data         Dummy parameter.
 */
void
omp_xml_handle_error (GMarkupParseContext* context,
                      GError *error,
                      gpointer user_data)
{
  tracef ("   XML ERROR %s\n", error->message);
  abort ();
}

/**
 * @brief Process any XML available in from_client.
 *
 * Queue any resulting server commands in to_server and any replies for
 * the client in to_client.
 *
 * @return 0 success, -1 error, -2 or -3 too little space in to_client or to_server.
 */
int
process_omp_client_input ()
{
  GError* error = NULL;
  g_markup_parse_context_parse (xml_context,
                                from_client + from_client_start,
                                from_client_end - from_client_start,
                                &error);
  if (error)
    {
      fprintf (stderr, "Failed to parse client XML: %s\n", error->message);
      g_error_free (error);
      return -1;
    }
  from_client_end = from_client_start = 0;
  return 0;
}

/**
 * @brief Process any lines available in from_server.
 *
 * Only ever update manager server records according to the input from the
 * server.  Output to the server is always done via
 * process_omp_client_input, in reaction to client requests.
 *
 * @return 0 on success, -1 on error.
 */
int
process_omp_server_input ()
{
  char* match;
  char* messages = from_server + from_server_start;
  char* input;
  int from_start, from_end;
  //tracef ("   consider %.*s\n", from_server_end - from_server_start, messages);

  /* First, handle special server states where the input from the server
   * ends in something other than <|> (usually a newline). */

  switch (server_init_state)
    {
      case SERVER_INIT_SENT_VERSION:
        if (from_server_end - from_server_start < 12)
          /* Need more input. */
          goto succeed;
        if (strncasecmp ("< OTP/1.0 >\n", messages, 12))
          {
            tracef ("   server fail: expected \"< OTP/1.0 >, got \"%.12s\"\n\"\n",
                    messages);
            goto fail;
          }
        from_server_start += 12;
        messages += 12;
        set_server_init_state (SERVER_INIT_GOT_VERSION);
        /* Fall through to attempt next step. */
      case SERVER_INIT_GOT_VERSION:
        if (from_server_end - from_server_start < 7)
          /* Need more input. */
          goto succeed;
        if (strncasecmp ("User : ", messages, 7))
          {
            tracef ("   server fail: expected \"User : \", got \"%7s\"\n",
                    messages);
            goto fail;
          }
        from_server_start += 7;
        messages += 7;
        set_server_init_state (SERVER_INIT_GOT_USER);
        goto succeed;
      case SERVER_INIT_GOT_USER:
        /* Input from server after "User : " and before user name sent. */
        goto fail;
      case SERVER_INIT_SENT_USER:
        if (from_server_end - from_server_start < 11)
          /* Need more input. */
          goto succeed;
        if (strncasecmp ("Password : ", messages, 11))
          {
            tracef ("   server fail: expected \"Password : \", got \"%11s\"\n",
                    messages);
            goto fail;
          }
        from_server_start += 11;
        messages += 11;
        set_server_init_state (SERVER_INIT_GOT_PASSWORD);
        goto succeed;
      case SERVER_INIT_GOT_PASSWORD:
        /* Input from server after "Password : " and before password sent. */
        goto fail;
      case SERVER_INIT_CONNECT_INTR:
      case SERVER_INIT_CONNECTED:
        /* Input from server before version string sent. */
        goto fail;
      case SERVER_INIT_DONE:
      case SERVER_INIT_TOP:
        if (server_state == SERVER_DONE)
          {
            char *end;
       server_done:
            end = messages + from_server_end - from_server_start;
            while (messages < end && (messages[0] == ' ' || messages[0] == '\n'))
              { messages++; from_server_start++; }
            if ((int) (end - messages) < 6)
              /* Too few characters to be the end marker, return to select to
               * wait for more input. */
              goto succeed;
            if (strncasecmp ("SERVER", messages, 6))
              {
                tracef ("   server fail: expected final \"SERVER\"\n");
                goto fail;
              }
            set_server_state (SERVER_TOP);
            from_server_start += 6;
            messages += 6;
          }
        else if (server_state == SERVER_PREFERENCE_VALUE)
          {
            char *value, *end;
       server_preference_value:
            assert (current_server_preference);
            end = messages + from_server_end - from_server_start;
            while (messages < end && (messages[0] == ' '))
              { messages++; from_server_start++; }
            if ((match = memchr (messages, '\n', from_server_end - from_server_start)))
              {
                match[0] = '\0';
                value = strdup (messages);
                if (value == NULL) goto out_of_memory;
                add_server_preference (current_server_preference, value);
                set_server_state (SERVER_PREFERENCE_NAME);
                from_server_start += match + 1 - messages;
                messages = match + 1;
              }
            else
              /* Need to wait for a newline to end the value so return to select
               * to wait for more input. */
              goto succeed;
          }
        else if (server_state == SERVER_RULE)
          {
       server_rule:
            while (1)
              {
                char *end;
                end = messages + from_server_end - from_server_start;
                while (messages < end && (messages[0] == ' '))
                  { messages++; from_server_start++; }
                if ((match = memchr (messages, ';', from_server_end - from_server_start)))
                  {
                    char* rule;
                    match[0] = '\0';
                    rule = strdup (messages);
                    if (rule == NULL) goto out_of_memory;
                    add_server_rule (rule);
                    from_server_start += match + 1 - messages;
                    messages = match + 1;
                  }
                else
                  /* Rules are followed by <|> SERVER so carry on, to check for
                   * the <|>. */
                  break;
              }
          }
        else if (server_state == SERVER_SERVER)
          {
            /* Look for any newline delimited server commands. */
            char *end;
       server_server:
            end = messages + from_server_end - from_server_start;
            while (messages < end && (messages[0] == ' '))
              { messages++; from_server_start++; }
            if ((match = memchr (messages, '\n', from_server_end - from_server_start)))
              {
                match[0] = '\0';
                // FIX is there ever whitespace before the newline?
                while (messages < end && (messages[0] == ' '))
                  { messages++; from_server_start++; }
                if (strncasecmp ("PLUGINS_DEPENDENCIES", messages, 20) == 0)
                  {
                    from_server_start += match + 1 - messages;
                    messages = match + 1;
                    maybe_free_server_plugins_dependencies ();
                    make_server_plugins_dependencies ();
                    set_server_state (SERVER_PLUGIN_DEPENDENCY_NAME);
                  }
                else
                  {
                    char* newline = match;
                    newline[0] = '\n';
                    /* Check for a <|>. */
                    input = messages;
                    from_start = from_server_start, from_end = from_server_end;
                    while (from_start < from_end
                           && (match = memchr (input, '<', from_end - from_start)))
                      {
                        if ((((int) (match - input) - from_start + 1) < from_end)
                            && (match[1] == '|')
                            && (match[2] == '>'))
                          {
                            if (match > newline)
                              /* The next <|> is after the newline, which is an error. */
                              goto fail;
                            /* The next <|> is before the newline, which may be correct.  Jump
                             * over the <|> search in the `while' beginning the next section,
                             * to save repeating the search. */
                            goto server_server_command;
                          }
                        from_start += match + 1 - input;
                        input = match + 1;
                      }
                    /* Need more input for a newline or <|>. */
                    goto succeed;
                  }
              }
          }
        else if (server_state == SERVER_PLUGIN_DEPENDENCY_DEPENDENCY)
          {
            /* Look for the end of dependency marker: a newline that comes before
             * the next <|>. */
            char *separator, *end;
       server_plugin_dependency_dependency:
            separator = NULL;
            /* Look for <|>. */
            input = messages;
            from_start = from_server_start;
            from_end = from_server_end;
            while (from_start < from_end
                   && (match = memchr (input, '<', from_end - from_start)))
              {
                if (((int) (match - input) - from_start + 1) < from_end
                    && (match[1] == '|')
                    && (match[2] == '>'))
                  {
                    separator = match;
                    break;
                  }
                from_start += match + 1 - input;
                input = match + 1;
              }
            /* Look for newline. */
            end = messages + from_server_end - from_server_start;
            while (messages < end && (messages[0] == ' '))
              { messages++; from_server_start++; }
            if ((match = memchr (messages, '\n', from_server_end - from_server_start)))
              {
                /* Compare newline position to <|> position. */
                if ((separator == NULL) || (match < separator))
                  {
                    finish_current_server_plugin_dependency ();
                    from_server_start += match + 1 - messages;
                    messages = match + 1;
                    set_server_state (SERVER_PLUGIN_DEPENDENCY_NAME);
                  }
              }
          }
    } /* switch (server_init_state) */

  /* Parse and handle any fields ending in <|>. */

  input = messages;
  from_start = from_server_start;
  from_end = from_server_end;
  while (from_start < from_end
         && (match = memchr (input, '<', from_end - from_start)))
    {
      if (((int) (match - input) - from_start + 1) < from_end
          && (match[1] == '|')
          && (match[2] == '>'))
        {
          char* message;
     server_server_command:
          /* Found a full field, process the field. */
#if 1
          tracef ("   server messages: %.*s...\n",
                  from_server_end - from_server_start < 200
                  ? from_server_end - from_server_start
                  : 200,
                  messages);
#endif
          message = messages;
          *match = '\0';
          from_server_start += match + 3 - messages;
          from_start = from_server_start;
          messages = match + 3;
          input = messages;
          tracef ("   server message: %s\n", message);

          /* Strip leading and trailing whitespace. */
          char* field = strip_space (message, match);

          tracef ("   server old state %i\n", server_state);
          tracef ("   server field: %s\n", field);
          switch (server_state)
            {
              case SERVER_BYE:
                if (strncasecmp ("BYE", field, 3))
                  goto fail;
                set_server_init_state (SERVER_INIT_TOP);
                set_server_state (SERVER_DONE);
// FIX
#if 0
                if (shutdown (server_socket, SHUT_RDWR) == -1)
                  perror ("Failed to shutdown server socket");
#endif
                /* Jump to the done check, as this loop only considers fields
                 * ending in <|>. */
                goto server_done;
              case SERVER_PLUGIN_DEPENDENCY_NAME:
                {
                  if (strlen (field) == 0)
                    {
                      set_server_state (SERVER_DONE);
                      /* Jump to the done check, as this loop only considers fields
                       * ending in <|>. */
                      goto server_done;
                    }
                  char* name = strdup (field);
                  if (name == NULL)
                    goto out_of_memory;
                  make_current_server_plugin_dependency (name);
                  set_server_state (SERVER_PLUGIN_DEPENDENCY_DEPENDENCY);
                  /* Jump to the newline check, as this loop only considers fields
                   * ending in <|> and the list of dependencies can end in a
                   * newline. */
                  goto server_plugin_dependency_dependency;
                }
              case SERVER_PLUGIN_DEPENDENCY_DEPENDENCY:
                {
                  char* dep = strdup (field);
                  if (dep == NULL)
                    goto out_of_memory;
                  append_to_current_server_plugin_dependency (dep);
                  /* Jump to the newline check, as this loop only considers fields
                   * ending in <|> and the list of dependencies can end in a
                   * newline. */
                  goto server_plugin_dependency_dependency;
                }
              case SERVER_PLUGINS_MD5:
                {
                  char* md5 = strdup (field);
                  if (md5 == NULL)
                    goto out_of_memory;
                  tracef ("   server got plugins_md5: %s\n", md5);
                  server.plugins_md5 = md5;
                  set_server_state (SERVER_DONE);
                  /* Jump to the done check, as this loop only considers fields
                   * ending in <|>. */
                  goto server_done;
                }
              case SERVER_PORT_HOST:
                {
                  //if (strncasecmp ("chiles", field, 11) == 0) // FIX
                  set_server_state (SERVER_PORT_NUMBER);
                  break;
                }
              case SERVER_PORT_NUMBER:
                {
                  if (current_server_task)
                    {
                      int number;
                      char *name = g_newa (char, strlen (field));
                      char *protocol = g_newa (char, strlen (field));

                      if (sscanf (field, "%s (%i/%[^)])",
                                  name, &number, protocol)
                          != 3)
                        {
                          number = atoi (field);
                          protocol[0] = '\0';
                        }
                      tracef ("   server got open port, number: %i, protocol: %s\n",
                              number, protocol);
                      append_task_open_port (current_server_task,
                                             number,
                                             protocol);
                    }
                  set_server_state (SERVER_DONE);
                  /* Jump to the done check, as this loop only considers fields
                   * ending in <|>. */
                  goto server_done;
                }
              case SERVER_PREFERENCE_NAME:
                {
                  if (strlen (field) == 0)
                    {
                      set_server_state (SERVER_DONE);
                      /* Jump to the done check, as this loop only considers fields
                       * ending in <|>. */
                      goto server_done;
                    }
                  char* name = strdup (field);
                  if (name == NULL) goto out_of_memory;
                  current_server_preference = name;
                  set_server_state (SERVER_PREFERENCE_VALUE);
                  /* Jump to preference value check, as values end with a
                   * newline and this loop only considers fields ending in <|>. */
                  goto server_preference_value;
                }
              case SERVER_RULE:
                /* A <|> following a rule. */
                set_server_state (SERVER_DONE);
                /* Jump to the done check, as this loop only considers fields
                 * ending in <|>. */
                goto server_done;
              case SERVER_SERVER:
                if (strncasecmp ("BYE", field, 3) == 0)
                  set_server_state (SERVER_BYE);
                else if (strncasecmp ("PLUGINS_MD5", field, 11) == 0)
                  set_server_state (SERVER_PLUGINS_MD5);
                else if (strncasecmp ("PORT", field, 4) == 0)
                  set_server_state (SERVER_PORT_HOST);
                else if (strncasecmp ("PREFERENCES", field, 11) == 0)
                  {
                    maybe_free_server_preferences ();
                    make_server_preferences ();
                    set_server_state (SERVER_PREFERENCE_NAME);
                  }
                else if (strncasecmp ("RULES", field, 5) == 0)
                  {
                    maybe_free_server_rules ();
                    make_server_rules ();
                    set_server_state (SERVER_RULE);
                    /* Jump to rules parsing, as each rule end in a ; and this
                     * loop only considers fields ending in <|>. */
                    goto server_rule;
                  }
                else if (strncasecmp ("TIME", field, 4) == 0)
                  {
                    set_server_state (SERVER_TIME);
                  }
                else if (strncasecmp ("STATUS", field, 6) == 0)
                  {
                    set_server_state (SERVER_STATUS_HOST);
                  }
                else
                  {
                    tracef ("New server command to implement: %s\n",
                            field);
                    goto fail;
                  }
                break;
              case SERVER_STATUS_ATTACK_STATE:
                {
                  if (current_server_task)
                    {
                      char* state = strdup (field);
                      if (state == NULL)
                        goto out_of_memory;
                      tracef ("   server got attack state: %s\n", state);
                      if (current_server_task->attack_state)
                        free (current_server_task->attack_state);
                      current_server_task->attack_state = state;
                    }
                  set_server_state (SERVER_STATUS_PORTS);
                  break;
                }
              case SERVER_STATUS_HOST:
                {
                  //if (strncasecmp ("chiles", field, 11) == 0) // FIX
                  set_server_state (SERVER_STATUS_ATTACK_STATE);
                  break;
                }
              case SERVER_STATUS_PORTS:
                {
                  if (current_server_task)
                    {
                      unsigned int current, max;
                      tracef ("   server got ports: %s\n", field);
                      if (sscanf (field, "%u/%u", &current, &max) == 2)
                        set_task_ports (current_server_task, current, max);
                    }
                  set_server_state (SERVER_DONE);
                  /* Jump to the done check, as this loop only considers fields
                   * ending in <|>. */
                  goto server_done;
                }
              case SERVER_TIME:
                {
                  if (strncasecmp ("HOST_START", field, 10) == 0)
                    set_server_state (SERVER_TIME_HOST_START_HOST);
                  else if (strncasecmp ("HOST_END", field, 8) == 0)
                    set_server_state (SERVER_TIME_HOST_END_HOST);
                  else if (strncasecmp ("SCAN_START", field, 10) == 0)
                    set_server_state (SERVER_TIME_SCAN_START);
                  else if (strncasecmp ("SCAN_END", field, 8) == 0)
                    set_server_state (SERVER_TIME_SCAN_END);
                  else
                    abort (); // FIX read all fields up to <|> SERVER?
                  break;
                }
              case SERVER_TIME_HOST_START_HOST:
                {
                  //if (strncasecmp ("chiles", field, 11) == 0) // FIX
                  set_server_state (SERVER_TIME_HOST_START_TIME);
                  break;
                }
              case SERVER_TIME_HOST_START_TIME:
                {
                  if (current_server_task)
                    {
                      char* time = strdup (field);
                      if (time == NULL)
                        goto out_of_memory;
                      tracef ("   server got start time: %s\n", time);
                      if (current_server_task->start_time)
                        free (current_server_task->start_time);
                      current_server_task->start_time = time;
                    }
                  set_server_state (SERVER_DONE);
                  /* Jump to the done check, as this loop only considers fields
                   * ending in <|>. */
                  goto server_done;
                }
              case SERVER_TIME_HOST_END_HOST:
                {
                  //if (strncasecmp ("chiles", field, 11) == 0) // FIX
                  set_server_state (SERVER_TIME_HOST_END_TIME);
                  break;
                }
              case SERVER_TIME_HOST_END_TIME:
                {
                  if (current_server_task)
                    {
                      char* time = strdup (field);
                      if (time == NULL)
                        goto out_of_memory;
                      tracef ("   server got end time: %s\n", time);
                      if (current_server_task->end_time)
                        free (current_server_task->end_time);
                      current_server_task->end_time = time;
                    }
                  set_server_state (SERVER_DONE);
                  /* Jump to the done check, as this loop only considers fields
                   * ending in <|>. */
                  goto server_done;
                }
              case SERVER_TIME_SCAN_START:
                {
                  /* Read over it. */
                  set_server_state (SERVER_DONE);
                  /* Jump to the done check, as this loop only considers fields
                   * ending in <|>. */
                  goto server_done;
                }
              case SERVER_TIME_SCAN_END:
                {
                  /* Read over it. */
                  set_server_state (SERVER_DONE);
                  /* Jump to the done check, as this loop only considers fields
                   * ending in <|>. */
                  goto server_done;
                }
              case SERVER_TOP:
              default:
                tracef ("   switch t\n");
                tracef ("   cmp %i\n", strncasecmp ("SERVER", field, 6));
                if (strncasecmp ("SERVER", field, 6))
                  goto fail;
                set_server_state (SERVER_SERVER);
                /* Jump to newline check, in case command ends in a newline. */
                goto server_server;
            }

          tracef ("   server new state: %i\n", server_state);
        }
      else
        {
          from_start += match + 1 - input;
          input = match + 1;
        }
    }

 succeed:

  if (from_server_start > 0 && from_server_start == from_server_end)
    {
      from_server_start = from_server_end = 0;
      tracef ("   server start caught end\n");
    }
  else if (from_server_start == 0)
    {
      if (from_server_end == BUFFER_SIZE)
        {
          // FIX if the buffer is entirely full here then exit
          //     (or will hang waiting for buffer to empty)
          //     this could happen if the server sends a field with length >= buffer length
          //         could realloc buffer
          //             which may eventually use all mem and bring down manager
          tracef ("   server buffer full\n");
          return -1;
        }
    }
  else
    {
      /* Move the remaining partial line to the front of the buffer.  This
       * ensures that there is space after the partial line into which
       * serve_omp can read the rest of the line. */
      char* start = from_server + from_server_start;
      from_server_end -= from_server_start;
      memmove (from_server, start, from_server_end);
      from_server_start = 0;
#if TRACE
      from_server[from_server_end] = '\0';
      //tracef ("   new from_server: %s\n", from_server);
      tracef ("   new from_server_start: %i\n", from_server_start);
      tracef ("   new from_server_end: %i\n", from_server_end);
#endif
    }

  return 0;

 out_of_memory:
  tracef ("   out of mem (server)\n");

 fail:
  return -1;
}

/**
 * @brief Read as much from the client as the from_client buffer will hold.
 *
 * @param[in]  client_session  The TLS session with the client.
 * @param[in]  client_socket   The socket connected to the client.
 *
 * @return 0 on reading everything available, -1 on error, -2 if
 * from_client buffer is full or -3 on reaching end of file.
 */
int
read_from_client (gnutls_session_t* client_session, int client_socket)
{
  while (from_client_end < BUFFER_SIZE)
    {
      ssize_t count;
      count = gnutls_record_recv (*client_session,
                                  from_client + from_client_end,
                                  BUFFER_SIZE - from_client_end);
      tracef ("   c count: %i\n", count);
      if (count < 0)
        {
          if (count == GNUTLS_E_AGAIN)
            /* Got everything available, return to `select'. */
            return 0;
          if (count == GNUTLS_E_INTERRUPTED)
            /* Interrupted, try read again. */
            continue;
          if (count == GNUTLS_E_REHANDSHAKE)
            {
              /* \todo Rehandshake. */
              tracef ("   FIX should rehandshake\n");
              continue;
            }
          fprintf (stderr, "Failed to read from client.\n");
          gnutls_perror (count);
          return -1;
        }
      if (count == 0)
        /* End of file. */
        return -3;
      from_client_end += count;
    }

  /* Buffer full. */
  return -2;
}

// FIX combine with read_from_client
/**
 * @brief Read as much from the server as the from_server buffer will hold.
 *
 * @param[in]  server_session  The TLS session with the server.
 * @param[in]  server_socket   The socket connected to the server.
 *
 * @return 0 on reading everything available, -1 on error, -2 if
 * from_server buffer is full or -3 on reaching end of file.
 */
int
read_from_server (gnutls_session_t* server_session, int server_socket)
{
  while (from_server_end < BUFFER_SIZE)
    {
      ssize_t count;
      count = gnutls_record_recv (*server_session,
                                  from_server + from_server_end,
                                  BUFFER_SIZE - from_server_end);
      tracef ("   s count: %i\n", count);
      if (count < 0)
        {
          if (count == GNUTLS_E_AGAIN)
            /* Got everything available, return to `select'. */
            return 0;
          if (count == GNUTLS_E_INTERRUPTED)
            /* Interrupted, try read again. */
            continue;
          if (count == GNUTLS_E_REHANDSHAKE)
            {
              /* \todo Rehandshake. */
              tracef ("   FIX should rehandshake\n");
              continue;
            }
          fprintf (stderr, "Failed to read from server.\n");
          gnutls_perror (count);
          return -1;
        }
      if (count == 0)
        /* End of file. */
        return -3;
      from_server_end += count;
    }

  /* Buffer full. */
  return -2;
}

/**
 * @brief Write as much as possible from to_client to the client.
 *
 * @param[in]  client_session  The client session.
 *
 * @return 0 wrote everything, -1 error, -2 wrote as much as server accepted.
 */
int
write_to_client (gnutls_session_t* client_session)
{
  while (to_client_start < to_client_end)
    {
      ssize_t count;
      count = gnutls_record_send (*client_session,
                                  to_client + to_client_start,
                                  to_client_end - to_client_start);
      if (count < 0)
        {
          if (count == GNUTLS_E_AGAIN)
            /* Wrote as much as server would accept. */
            return -2;
          if (count == GNUTLS_E_INTERRUPTED)
            /* Interrupted, try write again. */
            continue;
          if (count == GNUTLS_E_REHANDSHAKE)
            /* \todo Rehandshake. */
            continue;
          fprintf (stderr, "Failed to write to client.\n");
          gnutls_perror (count);
          return -1;
        }
      logf ("=> %.*s\n",
            to_client_end - to_client_start,
            to_client + to_client_start);
      to_client_start += count;
      tracef ("=> client  %i bytes\n", count);
    }
  tracef ("=> client  done\n");
  to_client_start = to_client_end = 0;

  /* Wrote everything. */
  return 0;
}

/**
 * @brief Write as much as possible from a string to the server.
 *
 * @param[in]  server_session  The server session.
 * @param[in]  string          The string.
 *
 * @return 0 wrote everything, -1 error, or the number of bytes written
 *         when the server accepted fewer bytes than given in string.
 */
int
write_string_to_server (gnutls_session_t* server_session, char* const string)
{
  char* point = string;
  char* end = string + strlen (string);
  while (point < end)
    {
      ssize_t count;
      count = gnutls_record_send (*server_session,
                                  point,
                                  end - point);
      if (count < 0)
        {
          if (count == GNUTLS_E_AGAIN)
            /* Wrote as much as server accepted. */
            return point - string;
          if (count == GNUTLS_E_INTERRUPTED)
            /* Interrupted, try write again. */
            continue;
          if (count == GNUTLS_E_REHANDSHAKE)
            /* \todo Rehandshake. */
            continue;
          fprintf (stderr, "Failed to write to server.\n");
          gnutls_perror (count);
          return -1;
        }
      point += count;
      tracef ("=> server  (string) %i bytes\n", count);
    }
  tracef ("=> server  (string) done\n");
  /* Wrote everything. */
  return 0;
}

/**
 * @brief Write as much as possible from to_server to the server.
 *
 * @param[in]  server_socket   The server socket.
 * @param[in]  server_session  The server session.
 *
 * @return 0 wrote everything, -1 error, -2 wrote as much as server accepted,
 *         -3 did an initialisation step.
 */
int
write_to_server (int server_socket, gnutls_session_t* server_session)
{
  switch (server_init_state)
    {
      case SERVER_INIT_CONNECT_INTR:
      case SERVER_INIT_TOP:
        switch (connect_to_server (server_socket,
                                   &server_address,
                                   server_session,
                                   server_init_state
                                   == SERVER_INIT_CONNECT_INTR))
          {
            case 0:
              set_server_init_state (SERVER_INIT_CONNECTED);
              /* Fall through to SERVER_INIT_CONNECTED case below, to write
               * version string. */
              break;
            case -2:
              set_server_init_state (SERVER_INIT_CONNECT_INTR);
              return -3;
            default:
              return -1;
          }
      case SERVER_INIT_CONNECTED:
        {
          char* string = "< OTP/1.0 >\n";
          server_init_offset = write_string_to_server (server_session,
                                                       string
                                                       + server_init_offset);
          if (server_init_offset == 0)
            set_server_init_state (SERVER_INIT_SENT_VERSION);
          else
            {
              if (server_init_offset == -1)
                {
                  server_init_offset = 0;
                  return -1;
                }
            }
          break;
        }
      case SERVER_INIT_SENT_VERSION:
      case SERVER_INIT_GOT_VERSION:
        assert (0);
        break;
      case SERVER_INIT_GOT_USER:
        {
          char* user = "mattm\n"; // FIX (string must stay same across init)
          server_init_offset = write_string_to_server (server_session,
                                                       user + server_init_offset);
          if (server_init_offset == 0)
            set_server_init_state (SERVER_INIT_SENT_USER);
          else if (server_init_offset == -1)
            {
              server_init_offset = 0;
              return -1;
            }
          break;
        }
      case SERVER_INIT_SENT_USER:
        assert (0);
        break;
      case SERVER_INIT_GOT_PASSWORD:
        {
          char* password = "mattm\n"; // FIX (string must stay same across init)
          server_init_offset = write_string_to_server (server_session,
                                                       password + server_init_offset);
          if (server_init_offset == 0)
            set_server_init_state (SERVER_INIT_DONE);
            /* Fall through to send any available output. */
          else if (server_init_offset == -1)
            {
              server_init_offset = 0;
              return -1;
            }
          else
            break;
        }
      case SERVER_INIT_DONE:
        while (to_server_start < to_server_end)
          {
            ssize_t count;
            count = gnutls_record_send (*server_session,
                                        to_server + to_server_start,
                                        to_server_end - to_server_start);
            if (count < 0)
              {
                if (count == GNUTLS_E_AGAIN)
                  /* Wrote as much as server accepted. */
                  return -2;
                if (count == GNUTLS_E_INTERRUPTED)
                  /* Interrupted, try write again. */
                  continue;
                if (count == GNUTLS_E_REHANDSHAKE)
                  /* \todo Rehandshake. */
                  continue;
                fprintf (stderr, "Failed to write to server.\n");
                gnutls_perror (count);
                return -1;
              }
            to_server_start += count;
            tracef ("=> server  %i bytes\n", count);
          }
        tracef ("=> server  done\n");
        to_server_start = to_server_end = 0;
        /* Wrote everything. */
        return 0;
    }
  return -3;
}

/**
 * @brief Serve the OpenVAS Management Protocol (OMP).
 *
 * @param[in]  client_session  The TLS session with the client.
 * @param[in]  server_session  The TLS session with the server.
 * @param[in]  client_socket   The socket connected to the client.
 * @param[in]  server_socket   The socket connected to the server.
 *
 * @return 0 on success, -1 on error.
 */
int
serve_omp (gnutls_session_t* client_session,
           gnutls_session_t* server_session,
           int client_socket, int server_socket)
{
  /* True if processing of the client input is waiting for space in the
   * to_server buffer. */
  short client_input_stalled = 0;
  /* True if processing of the server input is waiting for space in the
   * to_client buffer. */
  gboolean server_input_stalled = FALSE;
  /* True if there is more to read from the client. */
  gboolean from_client_more = FALSE;
  /* True if there is more to read from the server. */
  gboolean from_server_more = FALSE;

  tracef ("   Serving OMP.\n");

  /* Create the XML parser. */
  GMarkupParser xml_parser;
  xml_parser.start_element = omp_xml_handle_start_element;
  xml_parser.end_element = omp_xml_handle_end_element;
  xml_parser.text = omp_xml_handle_text;
  xml_parser.passthrough = NULL;
  xml_parser.error = omp_xml_handle_error;
  xml_context = g_markup_parse_context_new (&xml_parser,
                                            0,
                                            NULL,
                                            NULL);

  /* Handle the first client input, which was read by `read_protocol'. */
#if TRACE || LOG
  logf ("<= %.*s\n", from_client_end, from_client);
#if TRACE_TEXT
  tracef ("<= client  \"%.*s\"\n", from_client_end, from_client);
#else
  tracef ("<= client  %i bytes\n", from_client_end - initial_start);
#endif
#endif /* TRACE || LOG */
  // FIX handle client_input_stalled
  if (process_omp_client_input ()) return -1;

  /* Loop forever handling input from the sockets.
   *
   * That is, select on all the socket fds and then, as necessary
   *   - read from the client into buffer from_client
   *   - write to the server from buffer to_server
   *   - read from the server into buffer from_server
   *   - write to the client from buffer to_client.
   *
   * On reading from an fd, immediately try react to the input.  On reading
   * from the client call process_omp_client_input, which parses OMP
   * commands and may write to to_server and to_client.  On reading from
   * the server call process_omp_server_input, which mostly just updates
   * information kept about the server.
   *
   * There are a few complications here
   *   - the program must read everything available on an fd before
   *     selecting for read on the fd again,
   *   - the program need only select on the fds for writing if there is
   *     something to write,
   *   - similarly, the program need only select on the fds for reading
   *     if there's buffer space available,
   *   - the buffers from_client and from_server can become full during
   *     reading
   *   - a read from the client can be stalled by the to_server buffer
   *     filling up, or the to_client buffer filling up,
   *   - a read from the server can, theoretically, be stalled by the
   *     to_server buffer filling up (during initialisation).
   */
  int nfds = 1 + (client_socket > server_socket
                  ? client_socket : server_socket);
  fd_set readfds, exceptfds, writefds;
  unsigned char lastfds = 0; // FIX
  while (1)
    {
      /* Setup for select. */
      unsigned char fds = 0; /* What `select' is going to watch. */
      FD_ZERO (&exceptfds);
      FD_ZERO (&readfds);
      FD_ZERO (&writefds);
      FD_SET (client_socket, &exceptfds);
      FD_SET (server_socket, &exceptfds);
      // FIX shutdown if any eg read fails
      if (from_client_more == FALSE
          && from_client_end < BUFFER_SIZE)
        {
          FD_SET (client_socket, &readfds);
          fds |= FD_CLIENT_READ;
          if ((lastfds & FD_CLIENT_READ) == 0) tracef ("   client read on\n");
        }
      else
        {
          if (lastfds & FD_CLIENT_READ) tracef ("   client read off\n");
        }
      if (from_server_more == TRUE) abort ();
      if (from_server_more == FALSE // FIX
          && (server_init_state == SERVER_INIT_DONE
              || server_init_state == SERVER_INIT_GOT_VERSION
              || server_init_state == SERVER_INIT_SENT_USER
              || server_init_state == SERVER_INIT_SENT_VERSION)
          && from_server_end < BUFFER_SIZE)
        {
          FD_SET (server_socket, &readfds);
          fds |= FD_SERVER_READ;
          if ((lastfds & FD_SERVER_READ) == 0) tracef ("   server read on\n");
        }
      else
        {
          if (lastfds & FD_SERVER_READ) tracef ("   server read off\n");
        }
      if (to_client_start < to_client_end)
        {
          FD_SET (client_socket, &writefds);
          fds |= FD_CLIENT_WRITE;
        }
      if (((server_init_state == SERVER_INIT_TOP
            || server_init_state == SERVER_INIT_DONE)
           && to_server_start < to_server_end)
          || server_init_state == SERVER_INIT_CONNECT_INTR
          || server_init_state == SERVER_INIT_CONNECTED
          || server_init_state == SERVER_INIT_GOT_PASSWORD
          || server_init_state == SERVER_INIT_GOT_USER)
        {
          FD_SET (server_socket, &writefds);
          fds |= FD_SERVER_WRITE;
        }
      lastfds = fds;

      /* Select, then handle result. */
      int ret = select (nfds, &readfds, &writefds, &exceptfds, NULL);
      if (ret < 0)
        {
          if (errno == EINTR) continue;
          perror ("Child select failed");
          return -1;
        }
      if (ret == 0) continue;

      if (FD_ISSET (client_socket, &exceptfds))
        {
          fprintf (stderr, "Exception on client in child select.\n");
          return -1;
        }

      if (FD_ISSET (server_socket, &exceptfds))
        {
          fprintf (stderr, "Exception on server in child select.\n");
          return -1;
        }

      if (fds & FD_CLIENT_READ && FD_ISSET (client_socket, &readfds))
        {
          tracef ("   FD_CLIENT_READ\n");
#if TRACE || LOG
          int initial_start = from_client_end;
#endif

          do
            {
              switch (read_from_client (client_session, client_socket))
                {
                  case  0:       /* Read everything. */
                    from_client_more = FALSE;
                    break;
                  case -1:       /* Error. */
                    return -1;
                  case -2:       /* from_client buffer full. */
                    /* There may be more to read. */
                    // FIX if client_input_stalled below, how return to this loop?
                    from_client_more = TRUE;
                    break;
                  case -3:       /* End of file. */
                    return 0;
                  default:       /* Programming error. */
                    assert (0);
                }

#if TRACE || LOG
              /* This check prevents output in the "asynchronous network
               * error" case. */
              if (from_client_end > initial_start)
                {
                  logf ("<= %.*s\n",
                        from_client_end - initial_start,
                        from_client + initial_start);
#if TRACE_TEXT
                  tracef ("<= client  \"%.*s\"\n",
                          from_client_end - initial_start,
                          from_client + initial_start);
#else
                  tracef ("<= client  %i bytes\n",
                          from_client_end - initial_start);
#endif
                }
#endif /* TRACE || LOG */

              int ret = process_omp_client_input ();
              if (ret == 0)
                /* Processed all input. */
                client_input_stalled = 0;
              else if (ret == -1)
                /* Error. */
                return -1;
              else if (ret == -2)
                {
                  /* to_server buffer full. */
                  tracef ("   client input stalled 1\n");
                  client_input_stalled = 1;
                  /* Break to write to_server. */
                  break;
                }
              else if (ret == -3)
                {
                  /* to_client buffer full. */
                  tracef ("   client input stalled 2\n");
                  client_input_stalled = 2;
                  /* Break to write to_client. */
                  break;
                }
              else
                /* Programming error. */
                assert (0);
            }
          while (from_client_more);
        }

      if (fds & FD_SERVER_READ && FD_ISSET (server_socket, &readfds))
        {
          tracef ("   FD_SERVER_READ\n");
#if TRACE || LOG
          int initial_start = from_server_end;
#endif

          do
            {
              switch (read_from_server (server_session, server_socket))
                {
                  case  0:       /* Read everything. */
                    from_server_more = FALSE;
                    break;
                  case -1:       /* Error. */
                    /* This may be because the server closed the connection
                     * at the end of a command. */
                    set_server_init_state (SERVER_INIT_TOP);
                    break;
                  case -2:       /* from_server buffer full. */
                    /* There may be more to read. */
                    // FIX if server_input_stalled below, how return to this loop?
                    from_server_more = TRUE;
                    break;
                  case -3:       /* End of file. */
                    set_server_init_state (SERVER_INIT_TOP);
                    break;
                  default:       /* Programming error. */
                    assert (0);
                }

#if TRACE || LOG
              /* This check prevents output in the "asynchronous network
               * error" case. */
              if (from_server_end > initial_start)
                {
                  logf ("<= %.*s\n",
                        from_server_end - initial_start,
                        from_server + initial_start);
#if TRACE_TEXT
                  tracef ("<= server  \"%.*s\"\n",
                          from_server_end - initial_start,
                          from_server + initial_start);
#else
                  tracef ("<= server  %i bytes\n",
                          from_server_end - initial_start);
#endif
                }
#endif /* TRACE || LOG */

              int ret = process_omp_server_input ();
              if (ret == 0)
                /* Processed all input. */
                server_input_stalled = FALSE;
              else if (ret == -1)
                /* Error. */
                return -1;
              else if (ret == -3)
                {
                  /* to_server buffer full. */
                  tracef ("   server input stalled\n");
                  server_input_stalled = TRUE;
                  /* Break to write to server. */
                  break;
                }
              else
                /* Programming error. */
                assert (0);
            }
          while (from_server_more);
        }

      if (fds & FD_SERVER_WRITE
          && FD_ISSET (server_socket, &writefds))
        {
          /* Write as much as possible to the server. */

          switch (write_to_server (server_socket, server_session))
            {
              case  0:      /* Wrote everything in to_server. */
                break;
              case -1:      /* Error. */
                /* FIX This may be because the server closed the connection
                 * at the end of a command? */
                return -1;
              case -2:      /* Wrote as much as server was willing to accept. */
                break;
              case -3:      /* Did an initialisation step. */
                break;
              default:      /* Programming error. */
                assert (0);
            }
        }

      if (fds & FD_CLIENT_WRITE
          && FD_ISSET (client_socket, &writefds))
        {
          /* Write as much as possible to the client. */

          switch (write_to_client (client_session))
            {
              case  0:      /* Wrote everything in to_client. */
                break;
              case -1:      /* Error. */
                return -1;
              case -2:      /* Wrote as much as client was willing to accept. */
                break;
              default:      /* Programming error. */
                assert (0);
            }
        }

      if (client_input_stalled)
        {
          /* Try process the client input, in case writing to the server
           * or client has freed some space in to_server or to_client. */

          int ret = process_omp_client_input ();
          if (ret == 0)
            /* Processed all input. */
            client_input_stalled = 0;
          else if (ret == -1)
            /* Error. */
            return -1;
          else if (ret == -2)
            {
              /* to_server buffer full. */
              tracef ("   client input still stalled (1)\n");
              client_input_stalled = 1;
            }
          else if (ret == -3)
            {
              /* to_client buffer full. */
              tracef ("   client input still stalled (2)\n");
              client_input_stalled = 2;
            }
          else
            /* Programming error. */
            assert (0);
        }

      if (server_input_stalled)
        {
          /* Try process the server input, in case writing to the server
           * has freed some space in to_server. */

          int ret = process_omp_server_input ();
          if (ret == 0)
            /* Processed all input. */
            server_input_stalled = FALSE;
          else if (ret == -1)
            /* Error. */
            return -1;
          else if (ret == -3)
            /* to_server buffer still full. */
            tracef ("   server input stalled\n");
          else
            /* Programming error. */
            assert (0);
        }

    } /* while (1) */

  return 0;
}


/* Other functions. */

/**
 * @brief Read the type of protocol from the client.
 *
 * @param[in]  client_session  The TLS session with the client.
 * @param[in]  client_socket   The socket connected to the client.
 *
 * @return PROTOCOL_FAIL, PROTOCOL_CLOSE, PROTOCOL_OTP or PROTOCOL_OMP.
 */
protocol_read_t
read_protocol (gnutls_session_t* client_session, int client_socket)
{
  /* Turn on blocking. */
  // FIX get flags first
  if (fcntl (client_socket, F_SETFL, 0) == -1)
    {
      perror ("Failed to set client socket flag (read_protocol)");
      return PROTOCOL_FAIL;
    }

  /* Read from the client, checking the protocol when a newline or return
   * is read. */
  protocol_read_t ret = PROTOCOL_FAIL;
  char* from_client_current = from_client + from_client_end;
  while (from_client_end < BUFFER_SIZE)
    {
      ssize_t count;
 retry:
      count = gnutls_record_recv (*client_session,
                                  from_client + from_client_end,
                                  BUFFER_SIZE
                                  - from_client_end);
      if (count < 0)
        {
          if (count == GNUTLS_E_INTERRUPTED)
            /* Interrupted, try read again. */
            goto retry;
          if (count == GNUTLS_E_REHANDSHAKE)
            /* Try again. TODO Rehandshake. */
            goto retry;
          fprintf (stderr, "Failed to read from client (read_protocol).\n");
          gnutls_perror (count);
          break;
        }
      if (count == 0)
        {
          /* End of file. */
          ret = PROTOCOL_CLOSE;
          break;
        }
      from_client_end += count;

#if 0
      /* Check for newline or return. */
      from_client[from_client_end] = '\0';
      if (strchr (from_client_current, 10) || strchr (from_client_current, 13))
        {
          if (strstr (from_client, "< OTP/1.0 >"))
            ret = PROTOCOL_OTP;
          else
            ret = PROTOCOL_OMP;
          break;
        }
#else
      /* Check for ">".  FIX need a better check */
      from_client[from_client_end] = '\0';
      if (strchr (from_client_current, '>'))
        {
          if (strstr (from_client, "< OTP/1.0 >"))
            ret = PROTOCOL_OTP;
          else
            ret = PROTOCOL_OMP;
          break;
        }
#endif

      from_client_current += count;
    }

  // FIX use orig value
  /* Turn blocking back off. */
  if (fcntl (client_socket, F_SETFL, O_NONBLOCK) == -1)
    {
      perror ("Failed to reset client socket flag (read_protocol)");
      return PROTOCOL_FAIL;
    }

  return ret;
}

/**
 * @brief Serve the client.
 *
 * Connect to the openvasd server, then call either \ref serve_otp or \ref
 * serve_omp to serve the protocol, depending on the first message that
 * the client sends.
 *
 * @param[in]  client_socket  The socket connected to the client.
 *
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 */
int
serve_client (int client_socket)
{
  int server_socket;

  /* Make the server socket. */
  server_socket = socket (PF_INET, SOCK_STREAM, 0);
  if (server_socket == -1)
    {
      perror ("Failed to create server socket");
      return EXIT_FAILURE;
    }

  /* Setup server session. */

  gnutls_certificate_credentials_t server_credentials;
  if (gnutls_certificate_allocate_credentials (&server_credentials))
    {
      fprintf (stderr, "Failed to allocate server credentials.\n");
      goto close_fail;
    }

  gnutls_session_t server_session;
  if (gnutls_init (&server_session, GNUTLS_CLIENT))
    {
      fprintf (stderr, "Failed to initialise server session.\n");
      goto server_free_fail;
    }

  if (gnutls_set_default_priority (server_session))
    {
      fprintf (stderr, "Failed to set server session priority.\n");
      goto server_fail;
    }

  const int kx_priority[] = { GNUTLS_KX_DHE_RSA,
                              GNUTLS_KX_RSA,
                              GNUTLS_KX_DHE_DSS,
                              0 };
  if (gnutls_kx_set_priority (server_session, kx_priority))
    {
      fprintf (stderr, "Failed to set server key exchange priority.\n");
      goto server_fail;
    }

  if (gnutls_credentials_set (server_session,
                              GNUTLS_CRD_CERTIFICATE,
                              server_credentials))
    {
      fprintf (stderr, "Failed to set server credentials.\n");
      goto server_fail;
    }

  // FIX get flags first
  // FIX after read_protocol
  /* The socket must have O_NONBLOCK set, in case an "asynchronous network
   * error" removes the data between `select' and `read'. */
  if (fcntl (server_socket, F_SETFL, O_NONBLOCK) == -1)
    {
      perror ("Failed to set server socket flag");
      goto fail;
    }

  /* Get client socket and session from libopenvas. */

  int real_socket = nessus_get_socket_from_connection (client_socket);
  if (real_socket == -1 || real_socket == client_socket)
    {
      perror ("Failed to get client socket from libopenvas");
      goto fail;
    }

  gnutls_session_t* client_session = ovas_get_tlssession_from_connection(client_socket);
  if (client_session == NULL)
    {
      perror ("Failed to get connection from client socket");
      goto fail;
    }
  client_socket = real_socket;

  // FIX get flags first
  /* The socket must have O_NONBLOCK set, in case an "asynchronous network
   * error" removes the data between `select' and `read'. */
  if (fcntl (client_socket, F_SETFL, O_NONBLOCK) == -1)
    {
      perror ("Failed to set real client socket flag");
      goto fail;
    }
  gnutls_transport_set_lowat (*client_session, 0);

  /* Read a message from the client, and call the appropriate protocol
   * handler. */

  switch (read_protocol (client_session, client_socket))
    {
      case PROTOCOL_OTP:
        if (serve_otp (client_session, &server_session, client_socket, server_socket))
          goto fail;
        break;
      case PROTOCOL_OMP:
        if (serve_omp (client_session, &server_session, client_socket, server_socket))
          goto fail;
        break;
      case PROTOCOL_CLOSE:
        goto fail;
      default:
        fprintf (stderr, "Failed to determine protocol.\n");
    }

  gnutls_bye (server_session, GNUTLS_SHUT_RDWR);
  gnutls_deinit (server_session);
  gnutls_certificate_free_credentials (server_credentials);
  close (server_socket);
  return EXIT_SUCCESS;

 fail:
  gnutls_bye (server_session, GNUTLS_SHUT_RDWR);
 server_fail:
  gnutls_deinit (server_session);

 server_free_fail:
  gnutls_certificate_free_credentials (server_credentials);

 close_fail:

  close (server_socket);
  return EXIT_FAILURE;
}

#undef FD_CLIENT_READ
#undef FD_CLIENT_WRITE
#undef FD_SERVER_READ
#undef FD_SERVER_WRITE

/**
 * @brief Accept and fork.
 *
 * Accept the client connection and fork a child process.  The child calls
 * \ref serve_client to do the rest of the work.
 */
void
accept_and_maybe_fork () {
  /* Accept the client connection. */
  struct sockaddr_in client_address;
  client_address.sin_family = AF_INET;
  socklen_t size = sizeof (client_address);
  int client_socket;
  while ((client_socket = accept (manager_socket,
                                  (struct sockaddr *) &client_address,
                                  &size))
         == -1)
    {
      if (errno == EINTR)
        continue;
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        /* The connection is gone, return to select. */
        return;
      perror ("Failed to accept client connection");
      exit (EXIT_FAILURE);
    }

  /* Fork a child to serve the client. */
  pid_t pid = fork ();
  switch (pid)
    {
      case 0:
        /* Child. */
        {
          // FIX get flags first
          /* The socket must have O_NONBLOCK set, in case an "asynchronous
           * network error" removes the data between `select' and `read'.
           */
          if (fcntl (client_socket, F_SETFL, O_NONBLOCK) == -1)
            {
              perror ("Failed to set client socket flag");
              shutdown (client_socket, SHUT_RDWR);
              close (client_socket);
              exit (EXIT_FAILURE);
            }
          int secure_client_socket
            = ovas_server_context_attach (server_context, client_socket);
          if (secure_client_socket == -1)
            {
              fprintf (stderr,
                       "Failed to attach server context to socket %i.\n",
                       client_socket);
              shutdown (client_socket, SHUT_RDWR);
              close (client_socket);
              exit (EXIT_FAILURE);
            }
          tracef ("   Server context attached.\n");
          int ret = serve_client (secure_client_socket);
          close_stream_connection (secure_client_socket);
          exit (ret);
        }
      case -1:
        /* Parent when error, return to select. */
        perror ("Failed to fork child");
        break;
      default:
        /* Parent.  Return to select. */
        break;
    }
}

/**
 * @brief Clean up for exit.
 *
 * Close sockets and streams, free the ovas context.
 */
void
cleanup ()
{
  tracef ("   Cleaning up.\n");
  if (manager_socket > -1) close (manager_socket);
#if LOG
  if (fclose (log_stream)) perror ("Failed to close log stream");
#endif
  ovas_server_context_free (server_context);
  /** \todo Are these really necessary? */
  if (login) free (login);
  if (credentials) free (credentials);
  if (tasks) free_tasks ();
  if (current_server_preference) free (current_server_preference);
  maybe_free_current_server_plugin_dependency ();
  maybe_free_server_preferences ();
  maybe_free_server_rules ();
  maybe_free_server_plugins_dependencies ();
}

/**
 * @brief Handler for all signals.
 *
 * @param[in]  signal  The signal that caused this function to run.
 */
void
handle_signal (int signal)
{
  switch (signal)
    {
      case SIGTERM:
      case SIGHUP:
      case SIGINT:
        exit (EXIT_SUCCESS);
    }
}


/**
 * @brief Entry point to the manager.
 *
 * Setup the manager and then loop forever passing connections to
 * \ref accept_and_maybe_fork.
 *
 * @param[in]  argc  The number of arguments in argv.
 * @param[in]  argv  The list of arguments to the program.
 *
 * @return EXIT_SUCCESS on success, EXIT_FAILURE on failure.
 */
int
main (int argc, char** argv)
{
  int server_port, manager_port;
  tracef ("   OpenVAS Manager\n");

  /* Process options. */

  static gboolean print_version = FALSE;
  static gchar *manager_address_string = NULL;
  static gchar *manager_port_string = NULL;
  static gchar *server_address_string = NULL;
  static gchar *server_port_string = NULL;
  GError *error = NULL;
  GOptionContext *option_context;
  static GOptionEntry option_entries[]
    = {
        { "listen", 'a', 0, G_OPTION_ARG_STRING, &manager_address_string, "Listen on <address>.", "<address>" },
        { "port", 'p', 0, G_OPTION_ARG_STRING, &manager_port_string, "Use port number <number>.", "<number>" },
        { "slisten", 'l', 0, G_OPTION_ARG_STRING, &server_address_string, "Server (openvasd) address.", "<address>" },
        { "sport", 's', 0, G_OPTION_ARG_STRING, &server_port_string, "Server (openvasd) port number.", "<number>" },
        { "version", 'v', 0, G_OPTION_ARG_NONE, &print_version, "Print version.", NULL },
        { NULL }
      };

  option_context = g_option_context_new ("- OpenVAS security scanner manager");
  g_option_context_add_main_entries (option_context, option_entries, NULL);
  if (!g_option_context_parse (option_context, &argc, &argv, &error))
    {
      printf ("%s\n\n", error->message);
      exit (EXIT_FAILURE);
    }

  if (print_version)
    {
      printf ("openvasmd (%s) %s for %s\n",
              PROGNAME, OPENVASMD_VERSION, OPENVAS_OS_NAME);
      printf ("Copyright (C) 2008 Intevation GmbH\n\n");
      exit (EXIT_SUCCESS);
    }

  if (server_address_string == NULL)
    server_address_string = OPENVASD_ADDRESS;

  if (manager_port_string)
    {
      manager_port = atoi (manager_port_string);
      if (manager_port <= 0 || manager_port >= 65536)
        {
          fprintf (stderr, "Manager port must be a number between 0 and 65536.\n");
          exit (EXIT_FAILURE);
        }
      manager_port = htons (manager_port);
    }
  else
    {
      struct servent *servent = getservbyname ("openvas", "tcp");
      if (servent)
        // FIX free servent?
        manager_address.sin_port = servent->s_port;
      else
        manager_address.sin_port = htons (OPENVASMD_PORT);
    }

  if (server_port_string)
    {
      server_port = atoi (server_port_string);
      if (server_port <= 0 || server_port >= 65536)
        {
          fprintf (stderr, "Server port must be a number between 0 and 65536.\n");
          exit (EXIT_FAILURE);
        }
      server_port = htons (server_port);
    }
  else
    {
      struct servent *servent = getservbyname ("omp", "tcp");
      if (servent)
        // FIX free servent?
        server_port = servent->s_port;
      else
        server_port = htons (OPENVASD_PORT);
    }

  /* Initialise server information needed by `cleanup'. */

  server.preferences = NULL;
  server.rules = NULL;

  /* Register the `cleanup' function. */

  if (atexit (&cleanup))
    {
      fprintf (stderr, "Failed to register `atexit' cleanup function.\n");
      exit (EXIT_FAILURE);
    }

  /* Create the manager socket. */

  manager_socket = socket (PF_INET, SOCK_STREAM, 0);
  if (manager_socket == -1)
    {
      perror ("Failed to create manager socket");
      exit (EXIT_FAILURE);
    }

#if LOG
  /* Open the log file. */

  log_stream = fopen (LOG_FILE, "w");
  if (log_stream == NULL)
    {
      perror ("Failed to open log file");
      exit (EXIT_FAILURE);
    }
#endif

  /* Register the signal handler. */

  if (signal (SIGTERM, handle_signal) == SIG_ERR
      || signal (SIGINT, handle_signal) == SIG_ERR
      || signal (SIGHUP, handle_signal) == SIG_ERR
      || signal (SIGCHLD, SIG_IGN) == SIG_ERR)
    {
      fprintf (stderr, "Failed to register signal handler.\n");
      exit (EXIT_FAILURE);
    }

  /* Setup the server address. */

  server_address.sin_family = AF_INET;
  server_address.sin_port = server_port;
  if (!inet_aton(server_address_string, &server_address.sin_addr))
    {
      fprintf (stderr, "Failed to create server address %s.\n",
               server_address_string);
      exit (EXIT_FAILURE);
    }

  /* Setup security. */

  if (nessus_SSL_init (NULL) < 0)
    {
      fprintf (stderr, "Failed to initialise security.\n");
      exit (EXIT_FAILURE);
    }
  server_context
    = ovas_server_context_new (NESSUS_ENCAPS_TLSv1,
                               SERVERCERT,
                               SERVERKEY,
                               NULL,
                               CACERT,
                               0);
  if (server_context == NULL)
    {
      fprintf (stderr, "Failed to create server context.\n");
      exit (EXIT_FAILURE);
    }

  // FIX get flags first
  /* The socket must have O_NONBLOCK set, in case an "asynchronous network
   * error" removes the connection between `select' and `accept'. */
  if (fcntl (manager_socket, F_SETFL, O_NONBLOCK) == -1)
    {
      perror ("Failed to set manager socket flag");
      exit (EXIT_FAILURE);
    }

  /* Bind the manager socket to a port. */

  manager_address.sin_family = AF_INET;
  manager_address.sin_port = manager_port;
  if (manager_address_string)
    {
      if (!inet_aton (manager_address_string, &manager_address.sin_addr))
        {
          fprintf (stderr, "Failed to create manager address %s.\n",
                   manager_address_string);
          exit (EXIT_FAILURE);
        }
    }
  else
    manager_address.sin_addr.s_addr = INADDR_ANY;

  if (bind (manager_socket,
            (struct sockaddr *) &manager_address,
            sizeof (manager_address))
      == -1)
    {
      perror ("Failed to bind manager socket");
      close (manager_socket);
      exit (EXIT_FAILURE);
    }

  tracef ("   Manager bound to address %s port %i\n",
          manager_address_string ? manager_address_string : "*",
          ntohs (manager_address.sin_port));
  tracef ("   Set to connect to address %s port %i\n",
          server_address_string,
          ntohs (server_address.sin_port));

  /* Enable connections to the socket. */

  if (listen (manager_socket, MAX_CONNECTIONS) == -1)
    {
      perror ("Failed to listen on manager socket");
      close (manager_socket);
      exit (EXIT_FAILURE);
    }

  /* Loop waiting for connections and passing the work to
   * `accept_and_maybe_fork'.
   *
   * FIX This could just loop accept_and_maybe_fork.  Might the manager
   *     want to communicate with anything else here, like the server?
   */

  int ret, nfds;
  fd_set readfds, exceptfds;
  while (1)
    {
      FD_ZERO (&readfds);
      FD_SET (manager_socket, &readfds);
      FD_ZERO (&exceptfds);
      FD_SET (manager_socket, &exceptfds);
      nfds = manager_socket + 1;

      ret = select (nfds, &readfds, NULL, &exceptfds, NULL);

      if (ret == -1)
        {
          perror ("Select failed");
          exit (EXIT_FAILURE);
        }
      if (ret > 0)
        {
          if (FD_ISSET (manager_socket, &exceptfds))
            {
              fprintf (stderr, "Exception in select.\n");
              exit (EXIT_FAILURE);
            }
          if (FD_ISSET (manager_socket, &readfds))
            accept_and_maybe_fork();
        }
    }

  return EXIT_SUCCESS;
}
