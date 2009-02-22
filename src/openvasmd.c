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
 *
 * The entry point to the manager is the \ref main function.  From there
 * the references in the function documentation describe the flow of
 * control in the program.
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
 * src/\ref openvasmd.c
 *
 * src/\ref ovas-mngr-comm.c
 *
 * src/tests/\ref common.c
 */

/**
 * \page manpage openvasmd
 * \htmlinclude openvasmd.html
 */

#include <arpa/inet.h>
#include <assert.h>
#include <dirent.h>
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

#include "file.h"
#include "ovas-mngr-comm.h"
#include "string.h"

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
 * @brief The size of the data buffers, in bytes.
 *
 * When the client/server buffer is full `select' stops watching for input
 * from the client/server.
 */
#define BUFFER_SIZE 1048576

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


/* Helper functions. */

/**
 * @brief Free a GSList.
 *
 * Wrapper for GHashTable.
 *
 * @param[in]  list  A pointer to a GSList.
 */
void
free_g_slist (gpointer list)
{
  g_slist_free ((GSList*) list);
}

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
  // FIX does this free the elements (data slot)?
  g_ptr_array_free (array, TRUE);
}


/* Client state. */

/**
 * @brief Possible states of the client.
 */
typedef enum
{
  CLIENT_TOP,
  CLIENT_AUTHENTIC,

  CLIENT_ABORT_TASK,
  CLIENT_ABORT_TASK_TASK_ID,
#if 0
  CLIENT_ABORT_TASK_CRITERION,
#endif
  CLIENT_AUTHENTICATE,
  CLIENT_CREDENTIALS,
  CLIENT_CREDENTIALS_USERNAME,
  CLIENT_CREDENTIALS_PASSWORD,
  CLIENT_DELETE_TASK,
  CLIENT_DELETE_TASK_TASK_ID,
  CLIENT_GET_DEPENDENCIES,
  CLIENT_GET_NVT_FEED_ALL,
  CLIENT_GET_NVT_FEED_CHECKSUM,
  CLIENT_GET_NVT_FEED_DETAILS,
  CLIENT_GET_PREFERENCES,
  CLIENT_GET_RULES,
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
  int rules_size;                    ///< Number of rules.
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
  SERVER_DEBUG_DESCRIPTION,
  SERVER_DEBUG_HOST,
  SERVER_DEBUG_NUMBER,
  SERVER_DEBUG_OID,
  SERVER_HOLE_DESCRIPTION,
  SERVER_HOLE_HOST,
  SERVER_HOLE_NUMBER,
  SERVER_HOLE_OID,
  SERVER_INFO_DESCRIPTION,
  SERVER_INFO_HOST,
  SERVER_INFO_NUMBER,
  SERVER_INFO_OID,
  SERVER_LOG_DESCRIPTION,
  SERVER_LOG_HOST,
  SERVER_LOG_NUMBER,
  SERVER_LOG_OID,
  SERVER_NOTE_DESCRIPTION,
  SERVER_NOTE_HOST,
  SERVER_NOTE_NUMBER,
  SERVER_NOTE_OID,
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
 * @brief Set the server state, \ref server_state.
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
 * @brief Set the server initialisation state, \ref server_init_state.
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
 * Both parameters are used directly, and are freed when the
 * preferences are freed.
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
GSList* current_server_plugin_dependency_dependencies = NULL;

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
                                                       free_g_slist);
}

/**
 * @brief Add a plugin to the server dependencies.
 *
 * @param[in]  name          The name of the plugin.
 * @param[in]  requirements  The plugins required by the plugin.
 */
void
add_server_plugins_dependency (char* name, GSList* requirements)
{
  assert (server.plugins_dependencies);
  tracef ("   server new dependency name: %s\n", name);
  g_hash_table_insert (server.plugins_dependencies, name, requirements);
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
  current_server_plugin_dependency_dependencies = NULL; /* Empty list. */
}

/**
 * @brief Append a requirement to the current plugin.
 *
 * @param[in]  requirement  The name of the required plugin.
 */
void
append_to_current_server_plugin_dependency (char* requirement)
{
  tracef ("   server appending plugin requirement: %s\n", requirement);
  current_server_plugin_dependency_dependencies
    = g_slist_append (current_server_plugin_dependency_dependencies,
                      requirement);
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
    g_slist_free (current_server_plugin_dependency_dependencies);
}

/**
 * @brief Add the current plugin to the server dependencies.
 */
void
finish_current_server_plugin_dependency ()
{
  assert (current_server_plugin_dependency_name);
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
      server.rules_size = 0;
    }
}

/**
 * @brief Create the server rules.
 */
void
make_server_rules ()
{
  server.rules = g_ptr_array_new ();
  server.rules_size = 0;
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
  server.rules_size++;
}


/* Credentials. */

/**
 * @brief A username password pair.
 */
typedef struct
{
  gchar* username;  ///< Login name of user.
  gchar* password;  ///< Password of user.
} credentials_t;

/**
 * @brief Current credentials during any OMP command.
 */
credentials_t current_credentials;

/**
 * @brief Free credentials.
 *
 * Free the members of a credentials pair.
 *
 * @param[in]  credentials  Pointer to the credentials.
 */
void
free_credentials (credentials_t* credentials)
{
  if (credentials->username)
    {
      g_free (credentials->username);
      credentials->username = NULL;
    }
  if (credentials->password)
    {
      g_free (credentials->password);
      credentials->password = NULL;
    }
}

/**
 * @brief Append text to the username of a credential pair.
 *
 * @param[in]  credentials  Credentials.
 * @param[in]  text         The text to append.
 * @param[in]  length       Length of the text.
 */
void
append_to_credentials_username (credentials_t* credentials,
                                const char* text,
                                int length)
{
  credentials->username = credentials->username
                          ? g_strconcat (credentials->username, text, NULL)
                          : g_strndup (text, length);
}

/**
 * @brief Append text to the password of a credential pair.
 *
 * @param[in]  credentials  Credentials.
 * @param[in]  text         The text to append.
 * @param[in]  length       Length of the text.
 */
void
append_to_credentials_password (credentials_t* credentials,
                                const char* text,
                                int length)
{
  credentials->password = credentials->password
                          ? g_strconcat (credentials->password, text, NULL)
                          : g_strndup (text, length);
}

/**
 * @brief Authenticate credentials.
 *
 * @param[in]  credentials  Credentials.
 *
 * @return 1 if credentials are authentic, else 0.
 */
int
authenticate (credentials_t credentials)
{
  if (credentials.username) return 1;
  return 0;
}


/* Ports. */

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
 * @brief Get the name of the protocol of a port.
 *
 * @param[in]  port  The port.
 *
 * @return The name.
 */
char*
port_protocol_name (port_t* port)
{
  switch (port->protocol)
    {
      case PORT_PROTOCOL_TCP: return "tcp";
      case PORT_PROTOCOL_UDP: return "udp";
      case PORT_PROTOCOL_OTHER: return "???";
      default: assert (0); return "";
    }
}

/**
 * @brief Print a string representation of a port to a stream.
 *
 * @param[in]  stream  Destination stream.
 * @param[in]  port    Port to print.
 */
void
print_port (FILE* stream, port_t* port)
{
  fprintf (stream, "FIX (%d/%s)", port->number, port_protocol_name (port));
}


/* Messages. */

/**
 * @brief The record of a message.
 */
typedef struct
{
  port_t port;          ///< The port.
  char* description;    ///< Description of the message.
  char* oid;            ///< NVT identifier.
} message_t;

/**
 * @brief Current message during OTP SERVER message commands.
 */
message_t* current_message = NULL;

/**
 * @brief Make a message.
 *
 * @param[in]  number    Port number.
 * @param[in]  protocol  Port protocol.
 *
 * @return A pointer to the new message.
 */
message_t*
make_message (unsigned int number, const char* protocol)
{
  tracef ("   make_message %u %s\n", number, protocol);

  message_t* message = g_malloc (sizeof (message_t));

  message->description = NULL;
  message->oid = NULL;
  message->port.number = number;
  if (strncasecmp ("udp", protocol, 3) == 0)
    message->port.protocol = PORT_PROTOCOL_UDP;
  else if (strncasecmp ("tcp", protocol, 3) == 0)
    message->port.protocol = PORT_PROTOCOL_TCP;
  else
    message->port.protocol = PORT_PROTOCOL_OTHER;

  return message;
}

/**
 * @brief Free a message for g_ptr_array_foreach.
 *
 * @param[in]  message       Pointer to the message.
 * @param[in]  dummy         Dummy parameter.
 */
void
free_message (gpointer message, gpointer dummy)
{
  message_t* msg = (message_t*) message;
  if (msg->description) free (msg->description);
  if (msg->oid) free (msg->oid);
  free (msg);
}

/**
 * @brief Set the description of a message.
 *
 * @param[in]  message       Pointer to the message.
 * @param[in]  description  Description.
 */
void
set_message_description (message_t* message, char* description)
{
  if (message->description) free (message->description);
  message->description = description;
}

/**
 * @brief Set the OID of a message.
 *
 * @param[in]  message       Pointer to the message.
 * @param[in]  oid          OID.
 */
void
set_message_oid (message_t* message, char* oid)
{
  if (message->oid) free (message->oid);
  message->oid = oid;
}

/**
 * @brief Pair of stream and type for write_messages.
 */
typedef struct
{
  FILE* stream;  ///< Destination stream.
  char* type;    ///< Type of message.
} message_data_t;

/**
 * @brief Write a message for g_ptr_array_foreach.
 *
 * @param[in]  message       The message.
 * @param[in]  message_data  The stream and message type.
 */
void
write_message (gpointer message, gpointer message_data)
{
  message_t* msg = (message_t*) message;
  message_data_t* data = (message_data_t*) message_data;
  fprintf (data->stream, "results|%s|%s|", "dik", "dik"); // FIX
  print_port (data->stream, &msg->port);
  fprintf (data->stream, "|%s|%s|%s|\n",
           msg->oid, data->type, msg->description);
}

/**
 * @brief Write an array of messages to a stream.
 *
 * @param[in]  file       The stream.
 * @param[in]  messages   Array of messages.
 * @param[in]  type       Type of message.
 */
void
write_messages (FILE* file, GPtrArray* messages, char* type)
{
  message_data_t data = { file, type};
  g_ptr_array_foreach (messages, write_message, &data);
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
 * @brief Current client task during OMP commands like NEW_TASK and MODIFY_TASK.
 */
task_t* current_client_task = NULL;

/**
 * @brief The task currently running on the server.
 */
task_t* current_server_task = NULL;

/**
 * @brief The array of all the tasks of the current user.
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

/**
 * @brief Return a string version of the ID of a task.
 *
 * @param[in]   task  Task.
 * @param[out]  id    Pointer to a string.  On successful return contains a
 *                    pointer to a static buffer with the task ID as a string.
 *                    The static buffer is overwritten across successive calls.
 *
 * @return 0 success, -1 error.
 */
int
task_id_string (task_t* task, const char ** id)
{
  static char buffer[11]; /* (expt 2 32) => 4294967296 */
  int length = sprintf (buffer, "%010u", task->id);
  assert (length < 11);
  if (length < 1) return -1;
  *id = buffer;
  return 0;
}

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
 *
 * @return 0 on success, -1 on error (out of memory).
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
 * @brief Free a task.
 *
 * Free all the members of a task.
 *
 * @param[in]  task  The task to free.
 */
void
free_task (task_t* task)
{
  tracef ("   Freeing task %u: \"%s\" %s (%i) %.*s[...]\n\n",
          task->id,
          task->name,
          task->comment,
          task->description_length,
          (task->description_length > 20) ? 20 : task->description_length,
          task->description);
  free (task->name);
  task->name = NULL;
  free (task->comment);
  free (task->description);
  if (task->start_time) free (task->start_time);
  if (task->end_time) free (task->end_time);
  if (task->open_ports) g_array_free (task->open_ports, TRUE);
  if (task->debugs)
    {
      g_ptr_array_foreach (task->debugs, free_message, NULL);
      g_ptr_array_free (task->debugs, TRUE);
    }
  if (task->holes)
    {
      g_ptr_array_foreach (task->holes, free_message, NULL);
      g_ptr_array_free (task->holes, TRUE);
    }
  if (task->infos)
    {
      g_ptr_array_foreach (task->infos, free_message, NULL);
      g_ptr_array_free (task->infos, TRUE);
    }
  if (task->logs)
    {
      g_ptr_array_foreach (task->logs, free_message, NULL);
      g_ptr_array_free (task->logs, TRUE);
    }
  if (task->notes)
    {
      g_ptr_array_foreach (task->notes, free_message, NULL);
      g_ptr_array_free (task->notes, TRUE);
    }
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
      if (index->name) free_task (index);
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
 * @return A pointer to the new task or NULL when out of memory (in which
 *         case caller must free name and comment).
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
              index->report_count = 0;
              index->open_ports = NULL;
              index->debugs = g_ptr_array_new ();
              index->debugs_size = 0;
              index->holes = g_ptr_array_new ();
              index->holes_size = 0;
              index->infos = g_ptr_array_new ();
              index->infos_size = 0;
              index->logs = g_ptr_array_new ();
              index->logs_size = 0;
              index->notes = g_ptr_array_new ();
              index->notes_size = 0;
              tracef ("   Made task %i at %p\n", index->id, index);
              num_tasks++;
              return index;
            }
          index++;
        }
      index = (task_t*) tasks_size;
      /* grow_tasks updates tasks_size. */
      if (grow_tasks ()) return NULL;
      index = index + (int) tasks;
    }
}

/**
 * @brief Load the tasks from disk.
 *
 * @return 0 success, -1 error.
 */
int
load_tasks ()
{
  if (tasks) return -1;

  if (current_credentials.username == NULL) return -1;

  tracef ("   Loading tasks...\n");

  GError* error = NULL;
  gchar* dir_name = g_build_filename (PREFIX
                                      "/var/lib/openvas/mgr/users/",
                                      current_credentials.username,
                                      "tasks",
                                      NULL);

  struct dirent ** names;
  int count;

  count = scandir (dir_name, &names, NULL, alphasort);
  if (count < 0)
    {
      if (errno == ENOENT)
        {
          free (dir_name);
          tracef ("   Loading tasks... done\n");
          return 0;
        }
      fprintf (stderr, "Failed to open dir %s: %s\n",
               dir_name,
               strerror (errno));
      g_free (dir_name);
      return -1;
    }

  int index;
  for (index = 0; index < count; index++)
    {
      const char* task_name = names[index]->d_name;

      if (task_name[0] == '.') continue;

      gchar *name, *comment, *description;
      unsigned int time;

      tracef ("     %s\n", task_name);

      gchar* file_name = g_build_filename (dir_name, task_name, "name", NULL);
      g_file_get_contents (file_name, &name, NULL, &error);
      if (error)
        {
         contents_fail:
          fprintf (stderr, "Failed to get contents of %s: %s\n",
                   file_name,
                   error->message);
         fail:
          g_error_free (error);
          g_free (dir_name);
          g_free (file_name);
          for (; index < count; index++) free (names[index]);
          free (names);
          free_tasks ();
          return -1;
        }

      g_free (file_name);
      file_name = g_build_filename (dir_name, task_name, "time", NULL);
      g_file_get_contents (file_name, &comment, NULL, &error);
      if (error)
        {
          g_free (name);
          goto contents_fail;
        }
      if (sscanf (comment, "%u", &time) != 1)
        {
          fprintf (stderr, "Failed to scan time: %s\n", comment);
          g_free (comment);
          g_free (name);
          goto fail;
        }
      g_free (comment);

      g_free (file_name);
      file_name = g_build_filename (dir_name, task_name, "comment", NULL);
      g_file_get_contents (file_name, &comment, NULL, &error);
      if (error)
        {
          g_free (name);
          goto contents_fail;
        }
      g_free (file_name);

      task_t* task = make_task (name, time, comment);
      if (task == NULL)
        {
          g_free (name);
          g_free (comment);
          g_free (dir_name);
          for (; index < count; index++) free (names[index]);
          free (names);
          free_tasks ();
          return -1;
        }
      /* name and comment are freed with the new task. */

      gsize description_length;
      file_name = g_build_filename (dir_name, task_name, "description", NULL);
      g_file_get_contents (file_name,
                           &description,
                           &description_length,
                           &error);
      if (error) goto contents_fail;

      task->description = description;
      task->description_size = task->description_length = description_length;

      g_free (file_name);
      file_name = g_build_filename (dir_name, task_name, "report_count", NULL);
      g_file_get_contents (file_name, &comment, NULL, &error);
      if (error) goto contents_fail;
      if (sscanf (comment, "%u", &task->report_count) != 1)
        {
          fprintf (stderr, "Failed to scan report count: %s\n", comment);
          goto fail;
        }

      free (names[index]);
    }

  g_free (dir_name);
  free (names);

  tracef ("   Loading tasks... done\n");
  return 0;
}

/**
 * @brief Save a task to a directory.
 *
 * Save a task to a given directory, ensuring that the directory exists
 * before saving the task.
 *
 * @param[in]  task      The task.
 * @param[in]  dir_name  The directory.
 *
 * @return 0 success, -1 error.
 */
int
save_task (task_t* task, gchar* dir_name)
{
  GError* error = NULL;

  /* Ensure directory exists. */

  if (g_mkdir_with_parents (dir_name, 33216 /* -rwx------ */) == -1)
    {
      fprintf (stderr, "Failed to create task dir %s: %s\n",
               dir_name,
               strerror (errno));
      return -1;
    }

  /* Save each component of the task. */

  gchar* file_name = g_build_filename (dir_name, "name", NULL);

  g_file_set_contents (file_name, task->name, -1, &error);
  if (error)
    {
     contents_fail:
      fprintf (stderr, "Failed to set contents of %s: %s\n",
               file_name,
               error->message);
      g_error_free (error);
      g_free (file_name);
      return -1;
    }
  g_free (file_name);

  file_name = g_build_filename (dir_name, "comment", NULL);
  g_file_set_contents (file_name, task->comment, -1, &error);
  if (error) goto contents_fail;
  g_free (file_name);

  file_name = g_build_filename (dir_name, "description", NULL);
  g_file_set_contents (file_name,
                       task->description,
                       task->description_length,
                       &error);
  if (error) goto contents_fail;
  g_free (file_name);

  file_name = g_build_filename (dir_name, "time", NULL);
  static char buffer[11]; /* (expt 2 32) => 4294967296 */
  int length = sprintf (buffer, "%u", task->time);
  assert (length < 11);
  if (length < 1) goto contents_fail;
  g_file_set_contents (file_name, buffer, -1, &error);
  if (error) goto contents_fail;
  g_free (file_name);

  file_name = g_build_filename (dir_name, "report_count", NULL);
  length = sprintf (buffer, "%u", task->report_count);
  assert (length < 11);
  if (length < 1) goto contents_fail;
  g_file_set_contents (file_name, buffer, -1, &error);
  if (error) goto contents_fail;
  g_free (file_name);

  return 0;
}

/**
 * @brief Save all tasks to disk.
 *
 * @return 0 success, -1 error.
 */
int
save_tasks ()
{
  if (tasks == NULL) return 0;
  if (current_credentials.username == NULL) return -1;

  tracef ("   Saving tasks...\n");

  // FIX Could check if up to date already.

  gchar* dir_name = g_build_filename (PREFIX
                                      "/var/lib/openvas/mgr/users/",
                                      current_credentials.username,
                                      "tasks",
                                      NULL);

  /* Write each task in the tasks array to disk. */

  task_t* index = tasks;
  task_t* end = tasks + tasks_size;
  while (index < end)
    {
      if (index->name)
        {
          const char* id;
          tracef ("     %u\n", index->id);

          if (task_id_string (index, &id)) return -1;

          gchar* file_name = g_build_filename (dir_name,
                                               id,
                                               NULL);
          if (save_task (index, file_name))
            {
              g_free (file_name);
              return -1;
            }
          g_free (file_name);
        }
      index++;
    }

  tracef ("   Saving tasks... done.\n");
  return 0;
}

/**
 * @brief Find a task given an identifier.
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
  while (index < end)
    {
      if (index->name) tracef ("   %u vs %u\n", index->id, id);
      if (index->name && index->id == id) return index; else index++;
    }
  return NULL;
}

/**
 * @brief Set a task parameter.
 *
 * The "value" parameter is used directly and freed either immediately or
 * when the task is freed.
 *
 * @param[in]  task       A pointer to a task.
 * @param[in]  parameter  The name of the parameter (in any case): TASK_FILE,
 *                        IDENTIFIER or COMMENT.
 * @param[in]  value      The value of the parameter, in base64 if parameter
 *                        is "TASK_FILE".
 *
 * @return 0 on success, -1 when out of memory, -2 if parameter name error.
 */
int
set_task_parameter (task_t* task, const char* parameter, char* value)
{
  tracef ("   set_task_parameter %u %s\n", task->id, parameter);
  if (strncasecmp ("TASK_FILE", parameter, 9) == 0)
    {
      gsize out_len;
      guchar* out;
      out = g_base64_decode (value, &out_len);
      free (value);
      free (current_client_task->description);
      task->description = (char*) out;
      task->description_length = task->description_size = out_len;
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
 * Use \ref send_to_server to queue the task start sequence in \ref to_server.
 *
 * @param[in]  task  A pointer to the task.
 *
 * @return 0 on success, -1 if out of space in \ref to_server buffer.
 */
int
start_task (task_t* task)
{
  tracef ("   start task %u\n", task->id);

  if (task->running) return 0;

  if (send_to_server ("CLIENT <|> PREFERENCES <|>\n")) return -1;

  if (send_to_server ("ntp_keep_communication_alive <|> yes\n")) return -1;
  if (send_to_server ("ntp_client_accepts_notes <|> yes\n")) return -1;
  //if (send_to_server ("ntp_short_status <|> yes\n")) return -1;
  if (send_to_server ("plugin_set <|> \n")) return -1;
  // FIX
  if (send_to_server ("port_range <|> 21\n")) return -1;
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
  if (send_to_server ("CLIENT <|> LONG_ATTACK <|>\n3\ndik\n"))
    return -1;
#endif

  task->running = 1;

  if (task->open_ports) g_array_free (task->open_ports, TRUE);
  task->open_ports = g_array_new (FALSE, FALSE, sizeof (port_t));
  task->open_ports_size = 0;
  // FIX holes,...  reset_task_data (task);

  current_server_task = task;

  return 0;
}

/**
 * @brief Stop a task.
 *
 * Use \ref send_to_server to queue the task stop sequence in
 * \ref to_server.
 *
 * @param[in]  task  A pointer to the task.
 *
 * @return 0 on success, -1 if out of space in \ref to_server buffer.
 */
int
stop_task (task_t* task)
{
  tracef ("   stop task %u\n", task->id);
  if (task->running)
    {
      // FIX dik
      if (send_to_server ("CLIENT <|> STOP_ATTACK <|> dik <|> CLIENT\n"))
        return -1;
      task->running = 0;
    }
  return 0;
}

/**
 * @brief Delete a task.
 *
 * Stop the task beforehand with \ref stop_task, if it is running.
 *
 * @param[in]  task  A pointer to the task.
 *
 * @return 0 on success, -1 if out of space in \ref to_server buffer.
 */
int
delete_task (task_t* task)
{
  const char* id;
  tracef ("   delete task %u\n", task->id);

  if (task_id_string (task, &id)) return -1;

  if (current_credentials.username == NULL) return -1;

  if (stop_task (task) == -1) return -1;

  // FIX may be atomic problems here

  gchar* name = g_build_filename (PREFIX
                                  "/var/lib/openvas/mgr/users/",
                                  current_credentials.username,
                                  "tasks",
                                  id,
                                  NULL);
  GError* error = NULL;
  if (rmdir_recursively (name, &error))
    {
      fprintf (stderr, "Failed to remove task dir %s: %s\n",
               name,
               error->message);
      g_error_free (error);
      g_free (name);
      return -1;
    }
  g_free (name);

  free_task (task);

  return 0;
}

/**
 * @brief Append text to the comment associated with a task.
 *
 * @param[in]  task    A pointer to the task.
 * @param[in]  text    The text to append.
 * @param[in]  length  Length of the text.
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
 * @param[in]  task    A pointer to the task.
 * @param[in]  text    The text to append.
 * @param[in]  length  Length of the text.
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
 * @param[in]  task       A pointer to the task.
 * @param[in]  increment  Minimum number of bytes to increase memory.
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
  tracef ("   grew description to %i (at %p).\n", new_size, new);
  task->description = new;
  task->description_size = new_size;
  return 0;
}

/**
 * @brief Add a line to a task description.
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
  task->open_ports_size++;
}


/* Appending messages to tasks. */

/**
 * @brief Append a debug message to a task.
 *
 * @param[in]  task         Task.
 * @param[in]  message      Message.
 */
void
append_debug_message (task_t* task, message_t* message)
{
  g_ptr_array_add (task->debugs, (gpointer) message);
  task->debugs_size++;
}

/**
 * @brief Append a hole message to a task.
 *
 * @param[in]  task         Task.
 * @param[in]  message      Message.
 */
void
append_hole_message (task_t* task, message_t* message)
{
  g_ptr_array_add (task->holes, (gpointer) message);
  task->holes_size++;
}

/**
 * @brief Append an info message to a task.
 *
 * @param[in]  task         Task.
 * @param[in]  message      Message.
 */
void
append_info_message (task_t* task, message_t* message)
{
  g_ptr_array_add (task->infos, (gpointer) message);
  task->infos_size++;
}

/**
 * @brief Append a log message to a task.
 *
 * @param[in]  task         Task.
 * @param[in]  message      Message.
 */
void
append_log_message (task_t* task, message_t* message)
{
  g_ptr_array_add (task->logs, (gpointer) message);
  task->logs_size++;
}

/**
 * @brief Append a note message to a task.
 *
 * @param[in]  task         Task.
 * @param[in]  message      Message.
 */
void
append_note_message (task_t* task, message_t* message)
{
  g_ptr_array_add (task->notes, (gpointer) message);
  task->notes_size++;
}


/* Reports. */

/**
 * @brief Write a timestamp to a stream.
 *
 * @param[in]  file       The stream.
 * @param[in]  type       Type of timestamp.
 * @param[in]  time       The time.
 */
void
write_timestamp (FILE* file, char* type, char* time)
{
  fprintf (file, "timestamps|%s|%s|%s|%s|\n", "dik", "dik", type, time); // FIX
}

/**
 * @brief Save a report to a file.
 *
 * @param[in]  task       The task.
 *
 * @return 0 success, -1 failed to open file, -2 failed to close file.
 */
int
save_report (task_t* task)
{
  const char* id;

  if (current_credentials.username == NULL) return -1;

  tracef ("   Saving report %s on task %u\n", task->start_time, task->id);

  if (task_id_string (task, &id)) return -1;

  gchar* dir_name = g_build_filename (PREFIX
                                      "/var/lib/openvas/mgr/users/",
                                      current_credentials.username,
                                      "tasks",
                                      id,
                                      "reports",
                                      NULL);

  /* Ensure reports directory exists. */

  if (g_mkdir_with_parents (dir_name, 33216 /* -rwx------ */) == -1)
    {
      fprintf (stderr, "Failed to create report dir %s: %s\n",
               dir_name,
               strerror (errno));
      g_free (dir_name);
      return -1;
    }

  /* Generate report name. */

  // FIX OID
  static char buffer[15]; /* (expt 2 32) => 4294967296 + .nbe */
  int length = sprintf (buffer, "%010u.nbe", task->report_count);
  assert (length < 15);
  if (length < 4)
    {
      fprintf (stderr, "Failed to generate report id.\n");
      g_free (dir_name);
      return -1;
    }

  gchar* name = g_build_filename (dir_name, buffer, NULL);
  g_free (dir_name);

  /* Write report. */

  FILE* file = fopen (name, "w");
  if (file == NULL)
    {
      fprintf (stderr, "Failed to open report file %s: %s\n",
               name,
               strerror (errno));
      g_free (name);
      return -1;
    }

  write_timestamp (file, "scan_start", task->start_time); // FIX
  write_timestamp (file, "host_start", task->start_time);

  //write_messages (file, task->open_ports, task->open_ports_size); FIX
  write_messages (file, task->debugs, "Debug Message");
  write_messages (file, task->holes, "Security Hole");
  write_messages (file, task->infos, "Security Warning");
  write_messages (file, task->logs, "Log Message");
  write_messages (file, task->notes, "Security Note");

  write_timestamp (file, "host_end", task->end_time);
  write_timestamp (file, "scan_end", task->end_time); // FIX

  task->report_count++;

  if (fclose (file))
    {
      fprintf (stderr, "Failed to close report file %s: %s\n",
               name,
               strerror (errno));
      g_free (name);
      return -2;
    }

  g_free (name);
  return 0;
}


/* OpenVAS Transfer Protocol (OTP). */

/**
 * @brief Serve the OpenVAS Transfer Protocol (OTP).
 *
 * Loop reading input from the sockets, and writing client input to the
 * server socket and server input to the client socket.  Exit the loop
 * on reaching end of file on either of the sockets.
 *
 * If compiled with logging (\ref LOG) then log all output with \ref logf.
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
                      if (gnutls_error_is_fatal (count) == 0
                          && (count == GNUTLS_E_WARNING_ALERT_RECEIVED
                              || count == GNUTLS_E_FATAL_ALERT_RECEIVED))
                        {
                          int alert = gnutls_alert_get (*server_session);
                          fprintf (stderr, "TLS Alert %d: %s.\n",
                                   alert,
                                   gnutls_alert_get_name (alert));
                        }
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
 * Queue a message in \ref to_client.
 *
 * @param[in]  msg  The message, a string.
 */
#define SEND_TO_CLIENT(msg)                                       \
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
 * React to the start of an XML element according to the current value
 * of \ref client_state, usually adjusting \ref client_state to indicate
 * the change (with \ref set_client_state).  Call \ref SEND_TO_CLIENT to
 * queue any responses for the client.
 *
 * Set error parameter on encountering an error.
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
        if (strncasecmp ("AUTHENTICATE", element_name, 10) == 0)
          {
            assert (tasks == NULL);
            assert (current_credentials.username == NULL);
            assert (current_credentials.password == NULL);
            set_client_state (CLIENT_AUTHENTICATE);
          }
        else
          {
            SEND_TO_CLIENT ("<omp_response>"
                            "<status>401</status>"
                            "</omp_response>");
            g_set_error (error, G_MARKUP_ERROR, G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Must authenticate first.");
          }
        break;

      case CLIENT_AUTHENTIC:
        if (strncasecmp ("AUTHENTICATE", element_name, 10) == 0)
          {
            // FIX Could check if reauthenticating current credentials, to
            // save the loading of the tasks.
            save_tasks ();
            free_tasks ();
            free_credentials (&current_credentials);
            set_client_state (CLIENT_AUTHENTICATE);
          }
        else if (strncasecmp ("ABORT_TASK", element_name, 10) == 0)
          set_client_state (CLIENT_ABORT_TASK);
        else if (strncasecmp ("DELETE_TASK", element_name, 11) == 0)
          set_client_state (CLIENT_DELETE_TASK);
        else if (strncasecmp ("GET_DEPENDENCIES", element_name, 16) == 0)
          set_client_state (CLIENT_GET_DEPENDENCIES);
        else if (strncasecmp ("GET_NVT_FEED_ALL", element_name, 16) == 0)
          set_client_state (CLIENT_GET_NVT_FEED_ALL);
        else if (strncasecmp ("GET_NVT_FEED_CHECKSUM", element_name, 21) == 0)
          set_client_state (CLIENT_GET_NVT_FEED_CHECKSUM);
        else if (strncasecmp ("GET_NVT_FEED_DETAILS", element_name, 20) == 0)
          set_client_state (CLIENT_GET_NVT_FEED_DETAILS);
        else if (strncasecmp ("GET_PREFERENCES", element_name, 15) == 0)
          set_client_state (CLIENT_GET_PREFERENCES);
        else if (strncasecmp ("GET_RULES", element_name, 9) == 0)
          set_client_state (CLIENT_GET_RULES);
        else if (strncasecmp ("MODIFY_TASK", element_name, 11) == 0)
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
          {
            SEND_TO_CLIENT ("<omp_response>"
                            "<status>402</status>"
                            "</omp_response>");
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_AUTHENTICATE:
        if (strncasecmp ("CREDENTIALS", element_name, 11) == 0)
          set_client_state (CLIENT_CREDENTIALS);
        else
          {
            SEND_TO_CLIENT ("<authenticate_response>"
                            "<status>402</status>"
                            "</authenticate_response>");
            free_credentials (&current_credentials);
            set_client_state (CLIENT_TOP);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_CREDENTIALS:
        if (strncasecmp ("USERNAME", element_name, 8) == 0)
          set_client_state (CLIENT_CREDENTIALS_USERNAME);
        else if (strncasecmp ("PASSWORD", element_name, 8) == 0)
          set_client_state (CLIENT_CREDENTIALS_PASSWORD);
        else
          {
            SEND_TO_CLIENT ("<authenticate_response>"
                            "<status>402</status>"
                            "</authenticate_response>");
            free_credentials (&current_credentials);
            set_client_state (CLIENT_TOP);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_DELETE_TASK:
        if (strncasecmp ("TASK_ID", element_name, 7) == 0)
          set_client_state (CLIENT_DELETE_TASK_TASK_ID);
        else
          {
            SEND_TO_CLIENT ("<delete_task_response>"
                            "<status>402</status>"
                            "</delete_task_response>");
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_GET_DEPENDENCIES:
          {
            SEND_TO_CLIENT ("<get_dependencies_response>"
                            "<status>402</status>"
                            "</get_dependencies_response>");
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_GET_NVT_FEED_ALL:
          {
            SEND_TO_CLIENT ("<get_nvt_feed_all>"
                            "<status>402</status>"
                            "</get_nvt_feed_all>");
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_GET_NVT_FEED_CHECKSUM:
          {
            SEND_TO_CLIENT ("<get_nvt_feed_checksum>"
                            "<status>402</status>"
                            "</get_nvt_feed_checksum>");
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_GET_NVT_FEED_DETAILS:
          {
            SEND_TO_CLIENT ("<get_nvt_feed_details>"
                            "<status>402</status>"
                            "</get_nvt_feed_details>");
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_GET_PREFERENCES:
          {
            SEND_TO_CLIENT ("<get_preferences_response>"
                            "<status>402</status>"
                            "</get_preferences_response>");
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_GET_RULES:
          {
            SEND_TO_CLIENT ("<get_rules_response>"
                            "<status>402</status>"
                            "</get_rules_response>");
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
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
            SEND_TO_CLIENT ("<modify_task_response>"
                            "<status>402</status>"
                            "</modify_task_response>");
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_ABORT_TASK:
        if (strncasecmp ("TASK_ID", element_name, 7) == 0)
          set_client_state (CLIENT_ABORT_TASK_TASK_ID);
#if 0
        else if (strncasecmp ("CRITERION", element_name, 9) == 0)
          set_client_state (CLIENT_ABORT_TASK_CRITERION);
#endif
        else
          {
            SEND_TO_CLIENT ("<abort_task_response>"
                            "<status>402</status>"
                            "</abort_task_response>");
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
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
            SEND_TO_CLIENT ("<new_task_response>"
                            "<status>402</status>"
                            "</new_task_response>");
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_START_TASK:
        if (strncasecmp ("TASK_ID", element_name, 7) == 0)
          set_client_state (CLIENT_START_TASK_TASK_ID);
        else
          {
            SEND_TO_CLIENT ("<start_task_response>"
                            "<status>402</status>"
                            "</start_task_response>");
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_STATUS:
        if (strncasecmp ("TASK_ID", element_name, 7) == 0)
          set_client_state (CLIENT_STATUS_TASK_ID);
        else
          {
            SEND_TO_CLIENT ("<status_response>"
                            "<status>402</status>"
                            "</status_task_response>");
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      default:
        assert (0);
        // FIX respond fail to client
        g_set_error (error,
                     G_MARKUP_ERROR,
                     G_MARKUP_ERROR_PARSE,
                     "Manager programming error.");
        break;
    }

  return;

 respond_fail:
  tracef ("   XML RESPOND out of space in to_client\n");
  g_set_error (error, G_MARKUP_ERROR, G_MARKUP_ERROR_PARSE,
               "Manager out of space for reply to client.");
}

/**
 * @brief Send XML for a requirement of a plugin.
 *
 * @param[in]  element  The required plugin.
 * @param[in]  dummy    Dummy variable for g_hash_table_find.
 *
 * @return 0 if out of space in to_client buffer, else 1.
 */
gint
send_requirement (gconstpointer element, gconstpointer dummy)
{
  gchar* text = g_markup_escape_text ((char*) element,
                                      strlen ((char*) element));
  gchar* msg = g_strdup_printf ("<need>%s</need>", text);
  g_free (text);

  SEND_TO_CLIENT (msg);

  g_free (msg);
  return 1;
 respond_fail:
  g_free (msg);
  return 0;
}

/**
 * @brief Send XML for a plugin dependency.
 *
 * @param[in]  key    The dependency hashtable key.
 * @param[in]  value  The dependency hashtable value.
 * @param[in]  dummy  Dummy variable for g_hash_table_find.
 *
 * @return TRUE if out of space in to_client buffer, else FALSE.
 */
gboolean
send_dependency (gpointer key, gpointer value, gpointer dummy)
{
  /* \todo Do these reallocations affect performance? */
  gchar* key_text = g_markup_escape_text ((char*) key, strlen ((char*) key));
  gchar* msg = g_strdup_printf ("<dependency><needer>%s</needer>",
                                key_text);
  g_free (key_text);
  SEND_TO_CLIENT (msg);

  if (g_slist_find_custom ((GSList*) value, NULL, send_requirement))
    {
 respond_fail:
      g_free (msg);
      return TRUE;
    }

  SEND_TO_CLIENT ("</dependency>");
  return FALSE;
}

/**
 * @brief Send XML for a preference.
 *
 * @param[in]  key    The preferences hashtable key.
 * @param[in]  value  The preferences hashtable value.
 * @param[in]  dummy  Dummy variable for g_hash_table_find.
 *
 * @return TRUE if out of space in to_client buffer, else FALSE.
 */
gboolean
send_preference (gpointer key, gpointer value, gpointer dummy)
{
  /* \todo Do these reallocations affect performance? */
  gchar* key_text = g_markup_escape_text ((char*) key,
                                          strlen ((char*) key));
  gchar* value_text = g_markup_escape_text ((char*) value,
                                            strlen ((char*) value));
  gchar* msg = g_strdup_printf ("<preference>"
                                "<name>%s</name><value>%s</value>"
                                "</preference>",
                                key_text, value_text);
  g_free (key_text);
  g_free (value_text);
  SEND_TO_CLIENT (msg);
  g_free (msg);
  return FALSE;
 respond_fail:
  g_free (msg);
  return TRUE;
}

/**
 * @brief Send XML for a rule.
 *
 * @param[in]  rule  The rule.
 *
 * @return TRUE if out of space in to_client buffer, else FALSE.
 */
gboolean
send_rule (gpointer rule)
{
  /* \todo Do these reallocations affect performance? */
  gchar* rule_text = g_markup_escape_text ((char*) rule,
                                           strlen ((char*) rule));
  gchar* msg = g_strdup_printf ("<rule>%s</rule>", rule_text);
  g_free (rule_text);
  SEND_TO_CLIENT (msg);
  g_free (msg);
  return FALSE;
 respond_fail:
  g_free (msg);
  return TRUE;
}

/**
 * @brief Handle the end of an OMP XML element.
 *
 * React to the end of an XML element according to the current value
 * of \ref client_state, usually adjusting \ref client_state to indicate
 * the change (with \ref set_client_state).  Call \ref SEND_TO_CLIENT to queue
 * any responses for the client.  Call the task utilities to adjust the
 * tasks (for example \ref start_task, \ref stop_task, \ref set_task_parameter,
 * \ref delete_task and \ref find_task).
 *
 * Set error parameter on encountering an error.
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

      case CLIENT_ABORT_TASK:
        {
          assert (current_client_task == NULL);
          unsigned int id;
          if (sscanf (current_task_task_id, "%u", &id) != 1)
            SEND_TO_CLIENT ("<abort_task_response>"
                            "<status>40x</status>"
                            "</abort_task_response>");
          else
            {
              task_t* task = find_task (id);
              if (task == NULL)
                SEND_TO_CLIENT ("<abort_task_response>"
                                "<status>407</status>"
                                "</abort_task_response>");
              else if (stop_task (task))
                {
                  /* to_server is full. */
                  // FIX revert parsing for retry
                  // process_omp_client_input must return -2
                  abort ();
                }
              else
                SEND_TO_CLIENT ("<abort_task_response>"
                                "<status>201</status>"
                                "</abort_task_response>");
            }
          set_client_state (CLIENT_AUTHENTIC);
        }
        break;
      case CLIENT_ABORT_TASK_TASK_ID:
        assert (strncasecmp ("TASK_ID", element_name, 7) == 0);
        set_client_state (CLIENT_ABORT_TASK);
        break;

#if 0
      case CLIENT_ABORT_TASK_CRITERION:
        assert (strncasecmp ("CRITERION", element_name, 9) == 0);
        set_client_state (CLIENT_ABORT_TASK);
        break;
      case CLIENT_ABORT_TASK_CRITERION_VALUE:
        assert (strncasecmp ("TASK_ID", element_name, 7) == 0);
        set_client_state (CLIENT_ABORT_TASK);
        break;
#endif

      case CLIENT_AUTHENTICATE:
        if (authenticate (current_credentials))
          {
            if (load_tasks ())
              {
                fprintf (stderr, "Failed to load tasks.\n");
                g_set_error (error, G_MARKUP_ERROR, G_MARKUP_ERROR_PARSE,
                             "Manager failed to load tasks.");
                free_credentials (&current_credentials);
                set_client_state (CLIENT_TOP);
              }
            else
              set_client_state (CLIENT_AUTHENTIC);
          }
        else
          {
            SEND_TO_CLIENT ("<authenticate_response>"
                            "<status>403</status>"
                            "</authenticate_response>");
            free_credentials (&current_credentials);
            set_client_state (CLIENT_TOP);
          }
        break;

      case CLIENT_CREDENTIALS:
        assert (strncasecmp ("CREDENTIALS", element_name, 11) == 0);
        set_client_state (CLIENT_AUTHENTICATE);
        break;

      case CLIENT_CREDENTIALS_USERNAME:
        assert (strncasecmp ("USERNAME", element_name, 8) == 0);
        set_client_state (CLIENT_CREDENTIALS);
        break;

      case CLIENT_CREDENTIALS_PASSWORD:
        assert (strncasecmp ("PASSWORD", element_name, 8) == 0);
        set_client_state (CLIENT_CREDENTIALS);
        break;

      case CLIENT_GET_PREFERENCES:
        if (server.preferences)
          {
            SEND_TO_CLIENT ("<get_preferences_response><status>200</status>");
            if (g_hash_table_find (server.preferences, send_preference, NULL))
              goto respond_fail;
            SEND_TO_CLIENT ("</get_preferences_response>");
          }
        else
          SEND_TO_CLIENT ("<get_preferences_response>"
                          "<status>500</status>"
                          "</get_preferences_response>");
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_GET_DEPENDENCIES:
        if (server.plugins_dependencies)
          {
            SEND_TO_CLIENT ("<get_dependencies_response><status>200</status>");
            if (g_hash_table_find (server.plugins_dependencies,
                                   send_dependency,
                                   NULL))
              goto respond_fail;
            SEND_TO_CLIENT ("</get_dependencies_response>");
          }
        else
          SEND_TO_CLIENT ("<get_dependencies_response>"
                          "<status>500</status>"
                          "</get_dependencies_response>");
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_GET_NVT_FEED_ALL:
        SEND_TO_CLIENT ("<get_nvt_feed_all_response><status>200</status>");
        SEND_TO_CLIENT ("<nvt_count>2</nvt_count>");
        SEND_TO_CLIENT ("<feed_checksum>"
                        "<algorithm>md5</algorithm>"
                        "333"
                        "</feed_checksum>");
        SEND_TO_CLIENT ("<nvt>"
                     "<oid>1.3.6.1.4.1.25623.1.7.13005</oid>"
                     "<name>FooBar 1.5 installed</name>"
                     "<checksum><algorithm>md5</algorithm>222</checksum>"
                     "</nvt>");
        SEND_TO_CLIENT ("<nvt>"
                     "<oid>1.3.6.1.4.1.25623.1.7.13006</oid>"
                     "<name>FooBar 2.1 XSS vulnerability</name>"
                     "<checksum><algorithm>md5</algorithm>223</checksum>"
                     "</nvt>");
        SEND_TO_CLIENT ("</get_nvt_feed_all_response>");
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_GET_NVT_FEED_CHECKSUM:
// FIX
#if 0
        if (server.plugins_md5)
          {
            SEND_TO_CLIENT ("<get_nvt_feed_checksum_response>"
                            "<status>200</status>"
                            "<algorithm>md5</algorithm>");
            SEND_TO_CLIENT (server.plugins_md5);
            SEND_TO_CLIENT ("</get_nvt_feed_checksum_response>");
          }
        else
          SEND_TO_CLIENT ("<get_nvt_feed_checksum_response>"
                          "<status>500</status>"
                          "</get_nvt_feed_checksum_response>");
#else
        SEND_TO_CLIENT ("<get_nvt_feed_checksum_response>"
                        "<status>200</status>"
                        "<algorithm>md5</algorithm>");
        SEND_TO_CLIENT ("111");
        SEND_TO_CLIENT ("</get_nvt_feed_checksum_response>");
#endif
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_GET_NVT_FEED_DETAILS:
        SEND_TO_CLIENT ("<get_nvt_feed_details_response><status>200</status>");
        SEND_TO_CLIENT ("<nvt>"
                        "<oid>1.3.6.1.4.1.25623.1.7.13005</oid>"
                        "<cve>CVE-2008-4877</cve>"
                        "<cve>CVE-2008-4881</cve>"
                        "<bugtraq_id>12345</bugtraq_id>"
                        "<filename>foobar_15_detect.nasl</filename>"
                        "<description>This script detects whether FooBar 1.5 is installed.</description>"
                        "</nvt>");
        SEND_TO_CLIENT ("<nvt>"
                        "<oid>1.3.6.1.4.1.25623.1.7.13006</oid>"
                        "<cve>CVE-2008-5142</cve>"
                        "<bugtraq_id>12478</bugtraq_id>"
                        "<filename>foobar_21_xss.nasl</filename>"
                        "<description>This script detects whether the FooBar 2.1 XSS vulnerability is present.</description>"
                        "</nvt>");
        SEND_TO_CLIENT ("</get_nvt_feed_details_response>");
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_GET_RULES:
        if (server.rules)
          {
            int index;
            SEND_TO_CLIENT ("<get_rules_response><status>200</status>");
            for (index = 0; index < server.rules_size; index++)
              if (send_rule (g_ptr_array_index (server.rules, index)))
                goto respond_fail;
            SEND_TO_CLIENT ("</get_rules_response>");
          }
        else
          SEND_TO_CLIENT ("<get_rules_response>"
                          "<status>500</status>"
                          "</get_rules_response>");
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_VERSION:
        SEND_TO_CLIENT ("<omp_version_response>"
                        "<status>200</status>"
                        "<version><preferred/>1.0</version>"
                        "</omp_version_response>");
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_DELETE_TASK:
        {
          assert (current_client_task == NULL);
          unsigned int id;
          if (sscanf (current_task_task_id, "%u", &id) != 1)
            SEND_TO_CLIENT ("<delete_task_response>"
                            "<status>40x</status>"
                            "</delete_task_response>");
          else
            {
              task_t* task = find_task (id);
              if (task == NULL)
                SEND_TO_CLIENT ("<delete_task_response>"
                                "<status>407</status>"
                                "</delete_task_response>");
              else if (delete_task (task))
                {
                  /* to_server is full. */
                  // FIX revert parsing for retry
                  // process_omp_client_input must return -2
                  abort ();
                }
              else
                SEND_TO_CLIENT ("<delete_task_response>"
                                "<status>201</status>"
                                "</delete_task_response>");
            }
          set_client_state (CLIENT_AUTHENTIC);
        }
        break;
      case CLIENT_DELETE_TASK_TASK_ID:
        assert (strncasecmp ("TASK_ID", element_name, 7) == 0);
        set_client_state (CLIENT_DELETE_TASK);
        break;

      case CLIENT_MODIFY_TASK:
        {
          assert (current_client_task == NULL);
          unsigned int id;
          if (sscanf (current_task_task_id, "%u", &id) != 1)
            SEND_TO_CLIENT ("<modify_task_response>"
                            "<status>40x</status>"
                            "</modify_task_response>");
          else
            {
              current_client_task = find_task (id);
              if (current_client_task == NULL)
                SEND_TO_CLIENT ("<modify_task_response>"
                                "<status>407</status>"
                                "</modify_task_response>");
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
                      free (modify_task_value);
                      modify_task_value = NULL;
                      SEND_TO_CLIENT ("<modify_task_response>"
                                      "<status>40x</status>"
                                      "</modify_task_response>");
                    }
                  else
                    {
                      modify_task_value = NULL;
                      SEND_TO_CLIENT ("<modify_task_response>"
                                      "<status>201</status>"
                                      "</modify_task_response>");
                    }
                }
            }
          set_client_state (CLIENT_AUTHENTIC);
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
        // FIX only here should the task be added to tasks
        //       eg on err half task could be saved (or saved with base64 file)
        gchar* msg;
        msg = g_strdup_printf ("<new_task_response>"
                               "<status>201</status>"
                               "<task_id>%u</task_id>"
                               "</new_task_response>",
                               current_client_task->id);
        // FIX free msg if fail
        SEND_TO_CLIENT (msg);
        free (msg);
        current_client_task = NULL;
        set_client_state (CLIENT_AUTHENTIC);
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
        if (current_client_task)
          {
            gsize out_len;
            guchar* out;
            out = g_base64_decode (current_client_task->description, &out_len);
            free (current_client_task->description);
            current_client_task->description = (char*) out;
            current_client_task->description_length = out_len;
            current_client_task->description_size = out_len;
            set_client_state (CLIENT_NEW_TASK);
          }
        break;

      case CLIENT_START_TASK:
        {
          assert (current_client_task == NULL);
          unsigned int id;
          if (sscanf (current_task_task_id, "%u", &id) != 1)
            SEND_TO_CLIENT ("<start_task_response>"
                            "<status>40x</status>"
                            "</start_task_response>");
          else
            {
              task_t* task = find_task (id);
              if (task == NULL)
                SEND_TO_CLIENT ("<start_task_response>"
                                "<status>407</status>"
                                "</start_task_response>");
              else if (start_task (task))
                {
                  /* to_server is full. */
                  // FIX revert parsing for retry
                  // process_omp_client_input must return -2
                  abort ();
                }
              else
                SEND_TO_CLIENT ("<start_task_response>"
                                "<status>201</status>"
                                "</start_task_response>");
            }
          set_client_state (CLIENT_AUTHENTIC);
        }
        break;
      case CLIENT_START_TASK_TASK_ID:
        assert (strncasecmp ("TASK_ID", element_name, 7) == 0);
        set_client_state (CLIENT_START_TASK);
        break;

      case CLIENT_STATUS:
        assert (strncasecmp ("STATUS", element_name, 6) == 0);
        if (current_task_task_id)
          {
            unsigned int id;
            if (sscanf (current_task_task_id, "%u", &id) != 1)
              SEND_TO_CLIENT ("<status_response>"
                              "<status>40x</status>"
                              "</status_response>");
            else
              {
                task_t* task = find_task (id);
                if (task == NULL)
                  SEND_TO_CLIENT ("<status_response>"
                                  "<status>407</status>"
                                  "</status_response>");
                else
                  {
                    SEND_TO_CLIENT ("<status_response><status>200</status>");
                    gchar* response;
                    response = g_strdup_printf ("<report_count>%u</report_count>",
                                                task->report_count);
                    SEND_TO_CLIENT (response);
                    // FIX output reports
                  }
              }
          }
        else
          {
            SEND_TO_CLIENT ("<status_response><status>200</status>");
            gchar* response = g_strdup_printf ("<task_count>%u</task_count>", num_tasks);
            SEND_TO_CLIENT (response);
            task_t* index = tasks;
            task_t* end = tasks + tasks_size;
            while (index < end)
              {
                if (index->name)
                  {
                    gchar* line;
                    line = g_strdup_printf ("<task>"
                                            "<task_id>%u</task_id>"
                                            "<identifier>%s</identifier>"
                                            "<task_status>%s</task_status>"
                                            "<messages>"
                                            "<debug>%i</debug>"
                                            "<hole>%i</hole>"
                                            "<info>%i</info>"
                                            "<log>%i</log>"
                                            "<warning>%i</warning>"
                                            "</messages>"
                                            "</task>",
                                            index->id,
                                            index->name,
                                            index->running ? "Running" : "New",
                                            index->debugs_size,
                                            index->holes_size,
                                            index->infos_size,
                                            index->logs_size,
                                            index->notes_size);
                    // FIX free line if RESPOND fails
                    SEND_TO_CLIENT (line);
                    g_free (line);
                  }
                index++;
              }
          }
        SEND_TO_CLIENT ("</status_response>");
        set_client_state (CLIENT_AUTHENTIC);
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
  g_set_error (error, G_MARKUP_ERROR, G_MARKUP_ERROR_PARSE,
               "Manager out of space for reply to client.\n");
}

/**
 * @brief Handle the addition of text to an OMP XML element.
 *
 * React to the addition of text to the value of an XML element.
 * React according to the current value of \ref client_state,
 * usually appending the text to some part of the current task
 * (\ref current_client_task) with functions like
 * \ref add_task_description_line and \ref append_to_task_comment.
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

      case CLIENT_CREDENTIALS_USERNAME:
        append_to_credentials_username (&current_credentials, text, text_len);
        break;
      case CLIENT_CREDENTIALS_PASSWORD:
        append_to_credentials_password (&current_credentials, text, text_len);
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

      case CLIENT_ABORT_TASK_TASK_ID:
      case CLIENT_DELETE_TASK_TASK_ID:
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
 * Simply leave the error for the caller of the parser to handle.
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
}

/**
 * @brief Process any XML available in \ref from_client.
 *
 * Call the XML parser and let the callback functions do the work
 * (\ref omp_xml_handle_start_element, \ref omp_xml_handle_end_element,
 * \ref omp_xml_handle_text and \ref omp_xml_handle_error).
 *
 * The callback functions will queue any resulting server commands in
 * \ref to_server (using \ref send_to_server) and any replies for
 * the client in \ref to_client (using \ref SEND_TO_CLIENT).
 *
 * @return 0 success, -1 error, -2 or -3 too little space in \ref to_client
 *         or \ref to_server.
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
      if (g_error_matches (error,
                           G_MARKUP_ERROR,
                           G_MARKUP_ERROR_UNKNOWN_ELEMENT))
        tracef ("   client error: G_MARKUP_ERROR_UNKNOWN_ELEMENT\n");
      else if (g_error_matches (error,
                                G_MARKUP_ERROR,
                                G_MARKUP_ERROR_INVALID_CONTENT))
        tracef ("   client error: G_MARKUP_ERROR_INVALID_CONTENT\n");
      else if (g_error_matches (error,
                                G_MARKUP_ERROR,
                                G_MARKUP_ERROR_UNKNOWN_ATTRIBUTE))
        tracef ("   client error: G_MARKUP_ERROR_UNKNOWN_ATTRIBUTE\n");
      fprintf (stderr, "Failed to parse client XML: %s\n", error->message);
      g_error_free (error);
      /* In all error cases return -1 to close the connection, because it
         would be too hard, if possible at all, to figure out where the
         next command starts. */
      return -1;
    }
  from_client_end = from_client_start = 0;
  return 0;
}

/**
 * @brief Process any lines available in \ref from_server.
 *
 * Update server information according to the input from the server.
 * This includes updating the server state with \ref set_server_state
 * and \ref set_server_init_state, and updating server records with functions
 * like \ref add_server_preference and \ref append_task_open_port.
 *
 * This function simply records input from the server.  Output to the server
 * or client is always done via \ref process_omp_client_input in reaction to
 * client requests.
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
                while (messages < end && (messages[0] == '\n'))
                  { messages++; from_server_start++; }
                while (messages < end && (messages[0] == ' '))
                  { messages++; from_server_start++; }
                /* Check for the end marker. */
                if (end - messages > 2
                    && messages[0] == '<'
                    && messages[1] == '|'
                    && messages[2] == '>')
                  /* The rules list ends with "<|> SERVER" so carry on, to
                   * process the ending. */
                  break;
                /* There may be a rule ending in a semicolon. */
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
                  /* Need more input for a ; or <|>. */
                  goto succeed;
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
              case SERVER_DEBUG_DESCRIPTION:
                {
                  if (current_message)
                    {
                      // FIX \n for newline in description
                      char* description = strdup (field);
                      if (description == NULL) goto out_of_memory;
                      set_message_description (current_message, description);
                    }
                  set_server_state (SERVER_DEBUG_OID);
                  break;
                }
              case SERVER_DEBUG_HOST:
                {
                  //if (strncasecmp ("chiles", field, 11) == 0) // FIX
                  //if (current_server_task)  HOST_START
                  set_server_state (SERVER_DEBUG_NUMBER);
                  break;
                }
              case SERVER_DEBUG_NUMBER:
                {
                  assert (current_message == NULL);

                  // FIX field could be "general"
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
                  tracef ("   server got debug port, number: %i, protocol: %s\n",
                          number, protocol);

                  current_message = make_message (number, protocol);
                  if (current_message == NULL) goto out_of_memory;

                  set_server_state (SERVER_DEBUG_DESCRIPTION);
                  break;
                }
              case SERVER_DEBUG_OID:
                {
                  if (current_message)
                    {
                      char* oid = strdup (field);
                      if (oid == NULL) goto out_of_memory;
                      set_message_oid (current_message, oid);

                      append_debug_message (current_server_task, current_message);
                      current_message = NULL;
                    }
                  set_server_state (SERVER_DONE);
                  /* Jump to the done check, as this loop only considers fields
                   * ending in <|>. */
                  goto server_done;
                }
              case SERVER_HOLE_DESCRIPTION:
                {
                  if (current_message)
                    {
                      // FIX \n for newline in description
                      char* description = strdup (field);
                      if (description == NULL) goto out_of_memory;
                      set_message_description (current_message, description);
                    }
                  set_server_state (SERVER_HOLE_OID);
                  break;
                }
              case SERVER_HOLE_HOST:
                {
                  //if (strncasecmp ("chiles", field, 11) == 0) // FIX
                  //if (current_server_task)  HOST_START
                  set_server_state (SERVER_HOLE_NUMBER);
                  break;
                }
              case SERVER_HOLE_NUMBER:
                {
                  assert (current_message == NULL);

                  // FIX field could be "general"
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
                  tracef ("   server got hole port, number: %i, protocol: %s\n",
                          number, protocol);

                  current_message = make_message (number, protocol);
                  if (current_message == NULL) goto out_of_memory;

                  set_server_state (SERVER_HOLE_DESCRIPTION);
                  break;
                }
              case SERVER_HOLE_OID:
                {
                  if (current_message)
                    {
                      char* oid = strdup (field);
                      if (oid == NULL) goto out_of_memory;
                      set_message_oid (current_message, oid);

                      append_hole_message (current_server_task, current_message);
                      current_message = NULL;
                    }
                  set_server_state (SERVER_DONE);
                  /* Jump to the done check, as this loop only considers fields
                   * ending in <|>. */
                  goto server_done;
                }
              case SERVER_INFO_DESCRIPTION:
                {
                  if (current_message)
                    {
                      // FIX \n for newline in description
                      char* description = strdup (field);
                      if (description == NULL) goto out_of_memory;
                      set_message_description (current_message, description);
                    }
                  set_server_state (SERVER_INFO_OID);
                  break;
                }
              case SERVER_INFO_HOST:
                {
                  //if (strncasecmp ("chiles", field, 11) == 0) // FIX
                  //if (current_server_task)  HOST_START
                  set_server_state (SERVER_INFO_NUMBER);
                  break;
                }
              case SERVER_INFO_NUMBER:
                {
                  assert (current_message == NULL);

                  // FIX field could be "general"
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
                  tracef ("   server got info port, number: %i, protocol: %s\n",
                          number, protocol);

                  current_message = make_message (number, protocol);
                  if (current_message == NULL) goto out_of_memory;

                  set_server_state (SERVER_INFO_DESCRIPTION);
                  break;
                }
              case SERVER_INFO_OID:
                {
                  if (current_message && current_server_task)
                    {
                      char* oid = strdup (field);
                      if (oid == NULL) goto out_of_memory;
                      set_message_oid (current_message, oid);

                      append_info_message (current_server_task, current_message);
                      current_message = NULL;
                    }
                  set_server_state (SERVER_DONE);
                  /* Jump to the done check, as this loop only considers fields
                   * ending in <|>. */
                  goto server_done;
                }
              case SERVER_LOG_DESCRIPTION:
                {
                  if (current_message)
                    {
                      // FIX \n for newline in description
                      char* description = strdup (field);
                      if (description == NULL) goto out_of_memory;
                      set_message_description (current_message, description);
                    }
                  set_server_state (SERVER_LOG_OID);
                  break;
                }
              case SERVER_LOG_HOST:
                {
                  //if (strncasecmp ("chiles", field, 11) == 0) // FIX
                  //if (current_server_task)  HOST_START
                  set_server_state (SERVER_LOG_NUMBER);
                  break;
                }
              case SERVER_LOG_NUMBER:
                {
                  assert (current_message == NULL);

                  // FIX field could be "general"
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
                  tracef ("   server got log port, number: %i, protocol: %s\n",
                          number, protocol);

                  current_message = make_message (number, protocol);
                  if (current_message == NULL) goto out_of_memory;

                  set_server_state (SERVER_LOG_DESCRIPTION);
                  break;
                }
              case SERVER_LOG_OID:
                {
                  if (current_message && current_server_task)
                    {
                      char* oid = strdup (field);
                      if (oid == NULL) goto out_of_memory;
                      set_message_oid (current_message, oid);

                      append_log_message (current_server_task, current_message);
                      current_message = NULL;
                    }
                  set_server_state (SERVER_DONE);
                  /* Jump to the done check, as this loop only considers fields
                   * ending in <|>. */
                  goto server_done;
                }
              case SERVER_NOTE_DESCRIPTION:
                {
                  if (current_message)
                    {
                      // FIX \n for newline in description
                      char* description = strdup (field);
                      if (description == NULL) goto out_of_memory;
                      set_message_description (current_message, description);
                    }
                  set_server_state (SERVER_NOTE_OID);
                  break;
                }
              case SERVER_NOTE_HOST:
                {
                  //if (strncasecmp ("chiles", field, 11) == 0) // FIX
                  //if (current_server_task)  HOST_START
                  set_server_state (SERVER_NOTE_NUMBER);
                  break;
                }
              case SERVER_NOTE_NUMBER:
                {
                  assert (current_message == NULL);

                  // FIX field could be "general"
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
                  tracef ("   server got note port, number: %i, protocol: %s\n",
                          number, protocol);

                  current_message = make_message (number, protocol);
                  if (current_message == NULL) goto out_of_memory;

                  set_server_state (SERVER_NOTE_DESCRIPTION);
                  break;
                }
              case SERVER_NOTE_OID:
                {
                  if (current_message && current_server_task)
                    {
                      char* oid = strdup (field);
                      if (oid == NULL) goto out_of_memory;
                      set_message_oid (current_message, oid);

                      append_note_message (current_server_task, current_message);
                      current_message = NULL;
                    }
                  set_server_state (SERVER_DONE);
                  /* Jump to the done check, as this loop only considers fields
                   * ending in <|>. */
                  goto server_done;
                }
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
                else if (strncasecmp ("DEBUG", field, 5) == 0)
                  set_server_state (SERVER_HOLE_HOST);
                else if (strncasecmp ("HOLE", field, 4) == 0)
                  set_server_state (SERVER_HOLE_HOST);
                else if (strncasecmp ("INFO", field, 4) == 0)
                  set_server_state (SERVER_INFO_HOST);
                else if (strncasecmp ("LOG", field, 3) == 0)
                  set_server_state (SERVER_LOG_HOST);
                else if (strncasecmp ("NOTE", field, 4) == 0)
                  set_server_state (SERVER_NOTE_HOST);
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

                      if (save_report (current_server_task)) goto fail;

                      current_server_task = NULL;
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
 * @brief Read as much from the client as the \ref from_client buffer will hold.
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
          if (gnutls_error_is_fatal (count) == 0
              && (count == GNUTLS_E_WARNING_ALERT_RECEIVED
                  || count == GNUTLS_E_FATAL_ALERT_RECEIVED))
            {
              int alert = gnutls_alert_get (*client_session);
              fprintf (stderr, "TLS Alert %d: %s.\n",
                       alert,
                       gnutls_alert_get_name (alert));
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
 * @brief Read as much from the server as the \ref from_server buffer will hold.
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
      int retries = 5;
 retry:
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
          fprintf (stderr, "is_fatal: %i\n", gnutls_error_is_fatal (count));
          if (gnutls_error_is_fatal (count) == 0
              && (count == GNUTLS_E_WARNING_ALERT_RECEIVED
                  || count == GNUTLS_E_FATAL_ALERT_RECEIVED))
            {
              int alert = gnutls_alert_get (*server_session);
              fprintf (stderr, "TLS Alert %d: %s.\n",
                       alert,
                       gnutls_alert_get_name (alert));
            }
          fprintf (stderr, "Failed to read from server.\n");
          gnutls_perror (count);
          /* FIX Retry a few times even though there has been an error.
             This is because the recv sometimes fails with a "decryption
             failed" error. */
          while (retries--) goto retry;
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
 * @brief Write as much as possible from \ref to_client to the client.
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
 * @brief Write as much as possible from \ref to_server to the server.
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
 * Loop reading input from the sockets, processing
 * the input, and writing any results to the appropriate socket.
 * Exit the loop on reaching end of file on the client socket.
 *
 * Read input with \ref read_from_client and \ref read_from_server.
 * Process the input with \ref process_omp_client_input and
 * \ref process_omp_server_input.  Write the results with
 * \ref write_to_client and \ref write_to_server.
 *
 * If compiled with logging (\ref LOG) then log all input and output
 * with \ref logf.
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

  /* Loop handling input from the sockets.
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
   * the server call process_omp_server_input, which updates information
   * kept about the server.
   *
   * There are a few complications here
   *   - the program must read from or write to an fd returned by select
   *     before selecting for read on the fd again,
   *   - the program need only select on the fds for writing if there is
   *     something to write,
   *   - similarly, the program need only select on the fds for reading
   *     if there is buffer space available,
   *   - the buffers from_client and from_server can become full during
   *     reading
   *   - a read from the client can be stalled by the to_server buffer
   *     filling up, or the to_client buffer filling up,
   *   - FIX a read from the server can, theoretically, be stalled by the
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
      if (from_client_end < BUFFER_SIZE)
        {
          FD_SET (client_socket, &readfds);
          fds |= FD_CLIENT_READ;
          if ((lastfds & FD_CLIENT_READ) == 0) tracef ("   client read on\n");
        }
      else
        {
          if (lastfds & FD_CLIENT_READ) tracef ("   client read off\n");
        }
      if ((server_init_state == SERVER_INIT_DONE
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

          switch (read_from_client (client_session, client_socket))
            {
              case  0:       /* Read everything. */
                break;
              case -1:       /* Error. */
                return -1;
              case -2:       /* from_client buffer full. */
                /* There may be more to read. */
                break;
              case -3:       /* End of file. */
                tracef ("   EOF reading from client.\n");
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
            // FIX might be nice to write rest of to_client to client, so
            // that the client gets any buffered output and the response to
            // the error
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

      if (fds & FD_SERVER_READ && FD_ISSET (server_socket, &readfds))
        {
          tracef ("   FD_SERVER_READ\n");
#if TRACE || LOG
          int initial_start = from_server_end;
#endif

          switch (read_from_server (server_session, server_socket))
            {
              case  0:       /* Read everything. */
                break;
              case -1:       /* Error. */
                /* This may be because the server closed the connection
                 * at the end of a command. */
                set_server_init_state (SERVER_INIT_TOP);
                break;
              case -2:       /* from_server buffer full. */
                /* There may be more to read. */
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
 * @brief Read and return the type of protocol from the client.
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
          if (gnutls_error_is_fatal (count) == 0
              && (count == GNUTLS_E_WARNING_ALERT_RECEIVED
                  || count == GNUTLS_E_FATAL_ALERT_RECEIVED))
            {
              int alert = gnutls_alert_get (*client_session);
              fprintf (stderr, "TLS Alert %d: %s.\n",
                       alert,
                       gnutls_alert_get_name (alert));
            }
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
 * the client sends.  Read the first message with \ref read_protocol.
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

  const int protocol_priority[] = { GNUTLS_TLS1,
                                    0 };
  if (gnutls_protocol_set_priority (server_session, protocol_priority))
    {
      fprintf (stderr, "Failed to set protocol priority.\n");
      goto server_fail;
    }

  const int cipher_priority[] = { GNUTLS_CIPHER_AES_128_CBC,
                                  GNUTLS_CIPHER_3DES_CBC,
                                  GNUTLS_CIPHER_AES_256_CBC,
                                  GNUTLS_CIPHER_ARCFOUR_128,
                                  0 };
  if (gnutls_cipher_set_priority (server_session, cipher_priority))
    {
      fprintf (stderr, "Failed to set cipher priority.\n");
      goto server_fail;
    }

  const int comp_priority[] = { GNUTLS_COMP_ZLIB,
                                GNUTLS_COMP_NULL,
                                0 };
  if (gnutls_compression_set_priority (server_session, comp_priority))
    {
      fprintf (stderr, "Failed to set compression priority.\n");
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

  const int mac_priority[] = { GNUTLS_MAC_SHA1,
                               GNUTLS_MAC_MD5,
                               0 };
  if (gnutls_mac_set_priority (server_session, mac_priority))
    {
      fprintf (stderr, "Failed to set mac priority.\n");
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
        if (serve_otp (client_session, &server_session,
                       client_socket, server_socket))
          goto fail;
        break;
      case PROTOCOL_OMP:
        if (serve_omp (client_session, &server_session,
                       client_socket, server_socket))
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
 * Accept the client connection and fork a child process to serve the client.
 * The child calls \ref serve_client to do the rest of the work.
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
          save_tasks ();
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
  if (tasks) free_tasks ();
  if (current_server_preference) free (current_server_preference);
  free_credentials (&current_credentials);
  maybe_free_current_server_plugin_dependency ();
  maybe_free_server_preferences ();
  maybe_free_server_rules ();
  maybe_free_server_plugins_dependencies ();
}

/**
 * @brief Handle a signal.
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
