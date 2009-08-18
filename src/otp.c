/* OpenVAS Manager
 * $Id$
 * Description: Module for OpenVAS Manager: the OTP library.
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

/**
 * @file  otp.c
 * @brief The OpenVAS Manager OTP library.
 *
 * This file defines an OpenVAS Transfer Protocol (OTP) library, for
 * implementing OpenVAS managers such as the OpenVAS Manager daemon.
 *
 * The library provides a single function, \ref process_otp_server_input.
 * This function parses a given string of OTP text and adjusts local
 * task records according to the OTP messages in the string.
 */

#include "otp.h"
#include "manage.h"
#include "string.h"
#include "tracef.h"
#include "types.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef S_SPLINT_S
#include "splint.h"
#endif

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md    otp"

// FIX Should probably be passed into process_otp_server_input.
extern buffer_size_t from_buffer_size;


/* Helper functions. */

/**
 * @brief Free a GSList.
 *
 * Wrapper for GHashTable.
 *
 * @param[in]  list  A pointer to a GSList.
 */
static void
free_g_slist (gpointer list)
{
  g_slist_free ((GSList*) list);
}


/* Ports. */

// FIX currently in manage.h
#if 0
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
  char* string;              ///< Original string describing port.
} port_t;
#endif

//#define PARSE_PORTS
#ifdef PARSE_PORTS
/**
 * @brief String for TCP ports.
 */
/*@shared@*/
static char*
tcp_string = "tcp";

/**
 * @brief String for UDP ports.
 */
/*@shared@*/
static char*
udp_string = "udp";

/**
 * @brief String for other ports.
 */
/*@shared@*/
static char*
other_string = "???";

/**
 * @brief Empty string for ports.
 */
/*@shared@*/
static char*
empty_string = "";

/**
 * @brief Get the name of the protocol of a port.
 *
 * @param[in]  port  The port.
 *
 * @return The name.
 */
/*@shared@*/
static const char*
port_protocol_name (port_t* port)
{
  switch (port->protocol)
    {
      case PORT_PROTOCOL_TCP: return tcp_string;
      case PORT_PROTOCOL_UDP: return udp_string;
      case PORT_PROTOCOL_OTHER: return other_string;
      default: assert (0); return empty_string;
    }
}

/**
 * @brief Print a string representation of a port to a stream.
 *
 * @param[in]  stream  Destination stream.
 * @param[in]  port    Port to print.
 */
static void
print_port (FILE* stream, port_t* port)
{
  fprintf (stream, "FIX (%u/%s)", port->number, port_protocol_name (port));
}
#endif


/* Messages. */

// FIX should be in manage.c
#if 0
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
#endif

/**
 * @brief Current message during OTP SERVER message commands.
 */
/*@null@*/ /*@only@*/
static message_t* current_message = NULL;

/**
 * @brief Current host during OTP SERVER message commands.
 */
static gchar* current_host = NULL;

/**
 * @brief Make a message.
 *
 * @param[in]  host    Host name.
 *
 * @return A pointer to the new message.
 */
/*@only@*/
static message_t*
make_message (const char* host)
  /*@ensures isnull result->description, result->oid@*/
{
  message_t* message;

  message = (message_t*) g_malloc (sizeof (message_t));

  message->host = g_strdup (host);
  /* TODO: Calc subnet (__host2subnet in openvas-client/nessus/parser.c). */
  message->subnet = g_strdup (host);
  message->description = NULL;
  message->oid = NULL;
  message->port.number = 0;
  message->port.protocol = PORT_PROTOCOL_OTHER;
  message->port.string = NULL;

  return message;
}

/**
 * @brief Free a message for g_ptr_array_foreach.
 *
 * @param[in]  message       Pointer to the message.
 */
static void
free_message (/*@out@*/ /*@only@*/ message_t* message)
{
  if (message->host) free (message->host);
  if (message->subnet) free (message->subnet);
  if (message->description) free (message->description);
  if (message->oid) free (message->oid);
  if (message->port.string) free (message->port.string);
  free (message);
}

/**
 * @brief Set the port number of a message.
 *
 * @param[in]  message      Pointer to the message.  Used directly, freed by
 *                          free_message.
 * @param[in]  number       Port number.
 */
static void
set_message_port_number (message_t* message, int number)
{
  message->port.number = number;
}

/**
 * @brief Set the port protocol of a message.
 *
 * @param[in]  message      Pointer to the message.  Used directly, freed by
 *                          free_message.
 * @param[in]  protocol     Name of protocol on port.
 */
static void
set_message_port_protocol (message_t* message, const char* protocol)
{
  if (strcasecmp ("udp", protocol) == 0)
    message->port.protocol = PORT_PROTOCOL_UDP;
  else if (strcasecmp ("tcp", protocol) == 0)
    message->port.protocol = PORT_PROTOCOL_TCP;
  else
    message->port.protocol = PORT_PROTOCOL_OTHER;
}

/**
 * @brief Set the original string of a port of a message.
 *
 * @param[in]  message      Pointer to the message.
 * @param[in]  string       Port string.
 */
static void
set_message_port_string (message_t* message, char* string)
{
  if (message->port.string) free (message->port.string);
  message->port.string = string;
}

/**
 * @brief Set the description of a message.
 *
 * @param[in]  message      Pointer to the message.  Used directly, freed by
 *                          free_message.
 * @param[in]  description  Description.
 */
static void
set_message_description (message_t* message, /*@only@*/ char* description)
{
  if (message->description) free (message->description);
  message->description = description;
}

/**
 * @brief Set the OID of a message.
 *
 * @param[in]  message      Pointer to the message.  Used directly, freed by
 *                          free_message.
 * @param[in]  oid          OID.
 */
static void
set_message_oid (message_t* message, /*@only@*/ char* oid)
{
  if (message->oid) free (message->oid);
  message->oid = oid;
}

/**
 * @brief Pair of stream and type for write_messages.
 */
typedef struct
{
  /*@temp@*/ FILE* stream;  ///< Destination stream.
  /*@temp@*/ char* type;    ///< Type of message.
} message_data_t;

/**
 * @brief Write a message for g_ptr_array_foreach.
 *
 * @param[in]  message  The message.
 * @param[in]  stream   The stream to write the message to.
 * @param[in]  type     The message type (for example "Security Warning").
 */
static void
write_message (task_t task, message_t* message, char* type)
{
  result_t result;

  assert (current_report);

  result = make_result (task, message->subnet, message->host,
                        message->port.string, message->oid, type,
                        message->description);
  if (current_report) report_add_result (current_report, result);
}

/**
 * @brief Append a debug message to a report.
 *
 * @param[in]  task         Task.
 * @param[in]  message      Message.
 */
static void
append_debug_message (task_t task, message_t* message)
{
  write_message (task, message, "Debug Message");
}

/**
 * @brief Append a hole message to a report.
 *
 * @param[in]  task         Task.
 * @param[in]  message      Message.
 */
static void
append_hole_message (task_t task, message_t* message)
{
  write_message (task, message, "Security Hole");
}

/**
 * @brief Append an info message to a report.
 *
 * @param[in]  task         Task.
 * @param[in]  message      Message.
 */
static void
append_info_message (task_t task, message_t* message)
{
  write_message (task, message, "Security Warning");
}

/**
 * @brief Append a log message to a report.
 *
 * @param[in]  task         Task.
 * @param[in]  message      Message.
 */
static void
append_log_message (task_t task, message_t* message)
{
  write_message (task, message, "Log Message");
}

/**
 * @brief Append a note message to a report.
 *
 * @param[in]  task         Task.
 * @param[in]  message      Message.
 */
static void
append_note_message (task_t task, message_t* message)
{
  write_message (task, message, "Security Note");
}


/* Server preferences. */

/**
 * @brief The current server preference, during reading of server preferences.
 */
/*@null@*/ /*@only@*/
static char* current_server_preference = NULL;

/**
 * @brief Create the server preferences.
 */
static void
make_server_preferences ()
{
  if (server.preferences) g_hash_table_destroy (server.preferences);
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
static void
add_server_preference (/*@keep@*/ char* preference, /*@keep@*/ char* value)
{
  g_hash_table_insert (server.preferences, preference, value);
}


/* Server plugins. */

/**
 * @brief The current plugins, during reading of server plugin list.
 */
/*@only@*/
static nvtis_t* current_plugins = NULL;

/**
 * @brief The current plugin, during reading of server plugin list.
 */
/*@only@*/
static nvti_t* current_plugin = NULL;


/* Server plugin dependencies. */

/**
 * @brief The current server plugin, during reading of server plugin dependencies.
 */
/*@only@*/
static char* current_server_plugin_dependency_name = NULL;

/**
 * @brief The plugins required by the current server plugin.
 */
/*@only@*/
static GSList* current_server_plugin_dependency_dependencies = NULL;

/**
 * @brief Make the server plugins dependencies.
 */
static void
make_server_plugins_dependencies ()
{
  if (server.plugins_dependencies)
    {
      g_hash_table_destroy (server.plugins_dependencies);
      server.plugins_dependencies = NULL;
    }
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
static void
add_server_plugins_dependency (/*@keep@*/ char* name,
                               /*@keep@*/ GSList* requirements)
{
  assert (server.plugins_dependencies != NULL);
  tracef ("   server new dependency name: %s\n", name);
  g_hash_table_insert (server.plugins_dependencies, name, requirements);
}

/**
 * @brief Set the current plugin.
 *
 * @param[in]  name  The name of the plugin.  Used directly, freed by
 *                   maybe_free_current_server_plugin_dependency.
 */
static void
make_current_server_plugin_dependency (/*@only@*/ char* name)
{
  assert (current_server_plugin_dependency_name == NULL);
  assert (current_server_plugin_dependency_dependencies == NULL);
  current_server_plugin_dependency_name = name;
  current_server_plugin_dependency_dependencies = NULL; /* Empty list. */
}

/**
 * @brief Append a requirement to the current plugin.
 *
 * @param[in]  requirement  The name of the required plugin.  Used directly,
 *                          freed when the dependencies are freed in
 *                          make_server_plugins_dependencies.
 */
static void
append_to_current_server_plugin_dependency (/*@keep@*/ char* requirement)
{
  tracef ("   server appending plugin requirement: %s\n", requirement);
  current_server_plugin_dependency_dependencies
    = g_slist_append (current_server_plugin_dependency_dependencies,
                      requirement);
}

/**
 * @brief Add the current plugin to the server dependencies.
 */
static void
finish_current_server_plugin_dependency ()
{
  assert (current_server_plugin_dependency_name != NULL);
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
static void
free_rule (/*@only@*/ /*@out@*/ void* rule, /*@unused@*/ void* dummy)
{
  if (rule) free (rule);
}

/**
 * @brief Free any server rules.
 */
static void
maybe_free_server_rules ()
{
  if (server.rules)
    {
      g_ptr_array_foreach (server.rules, free_rule, NULL);
      (void) g_ptr_array_free (server.rules, TRUE);
      server.rules_size = 0;
    }
}

/**
 * @brief Create the server rules.
 */
static void
make_server_rules ()
{
  server.rules = g_ptr_array_new ();
  server.rules_size = 0;
}

/**
 * @brief Add a rule to the server rules.
 *
 * The rule is used directly and is freed with the other server rules.
 *
 * @param[in]  rule  The rule.
 */
static void
add_server_rule (/*@keep@*/ char* rule)
{
  g_ptr_array_add (server.rules, rule);
  server.rules_size++;
}


/* Server state. */

/**
 * @brief Initialise OTP library data.
 *
 * This must run once, before the first call to \ref process_otp_server_input.
 */
void
init_otp_data ()
{
  server.certificates = NULL;
  server.preferences = NULL;
  server.rules = NULL;
  server.plugins = NULL;
  server.plugins_md5 = NULL;
}

/**
 * @brief Possible states of the server.
 */
typedef enum
{
  SERVER_BYE,
  SERVER_CERTIFICATE_FINGERPRINT,
  SERVER_CERTIFICATE_LENGTH,
  SERVER_CERTIFICATE_OWNER,
  SERVER_CERTIFICATE_PUBLIC_KEY,
  SERVER_CERTIFICATE_TRUST_LEVEL,
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
  SERVER_PLUGIN_LIST_BUGTRAQ_ID,
  SERVER_PLUGIN_LIST_CATEGORY,
  SERVER_PLUGIN_LIST_COPYRIGHT,
  SERVER_PLUGIN_LIST_CVE_ID,
  SERVER_PLUGIN_LIST_DESCRIPTION,
  SERVER_PLUGIN_LIST_FAMILY,
  SERVER_PLUGIN_LIST_FPRS,
  SERVER_PLUGIN_LIST_NAME,
  SERVER_PLUGIN_LIST_OID,
  SERVER_PLUGIN_LIST_PLUGIN_VERSION,
  SERVER_PLUGIN_LIST_SUMMARY,
  SERVER_PLUGIN_LIST_TAGS,
  SERVER_PLUGIN_LIST_XREFS,
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
static server_state_t server_state = SERVER_TOP;

/**
 * @brief Set the server state, \ref server_state.
 */
static void
set_server_state (server_state_t state)
{
  server_state = state;
  tracef ("   server state set: %i\n", server_state);
}

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


/* Server certificates. */

/**
 * @brief The current certificates, during reading of server certificates.
 */
/*@only@*/
static certificates_t* current_certificates = NULL;

/**
 * @brief The current certificate, during reading of server certificates.
 */
/*@only@*/
static certificate_t* current_certificate = NULL;


/* OTP input processor. */

// FIX probably should pass to process_omp_client_input
extern char from_server[];
extern buffer_size_t from_server_start;
extern buffer_size_t from_server_end;

/**
 * @brief Parse the final field of a certificate in a certificate list.
 *
 * @param  messages  A pointer into the OTP input buffer.
 *
 * @return 0 success, -2 too few characters (need more input).
 */
static int
parse_server_certificate_public_key (char** messages)
{
  gchar *value;
  char *end, *match;
  assert (current_certificate != NULL);
  end = *messages + from_server_end - from_server_start;
  while (*messages < end && ((*messages)[0] == ' '))
    { (*messages)++; from_server_start++; }
  if ((match = memchr (*messages,
                       (int) '\n',
                       from_server_end - from_server_start)))
    {
      match[0] = '\0';
      if (current_certificates && current_certificate)
        {
          value = g_strdup (*messages);
          certificate_set_public_key (current_certificate, value);
          certificates_add (current_certificates, current_certificate);
          current_certificate = NULL;
          g_free (value);
        }
      set_server_state (SERVER_CERTIFICATE_FINGERPRINT);
      from_server_start += match + 1 - *messages;
      *messages = match + 1;
      return 0;
    }
  return -2;
}

/**
 * @brief Parse the final SERVER field of an OTP message.
 *
 * @param  messages  A pointer into the OTP input buffer.
 *
 * @return 0 success, -1 fail, -2 too few characters (need more input).
 */
static int
parse_server_done (char** messages)
{
  char *end = *messages + from_server_end - from_server_start;
  while (*messages < end && ((*messages)[0] == ' ' || (*messages)[0] == '\n'))
    { (*messages)++; from_server_start++; }
  if ((int) (end - *messages) < 6)
    /* Too few characters to be the end marker, return to select to
     * wait for more input. */
    return -2;
  if (strncasecmp ("SERVER", *messages, 6))
    {
      tracef ("   server fail: expected final \"SERVER\"\n");
      return -1;
    }
  set_server_state (SERVER_TOP);
  from_server_start += 6;
  (*messages) += 6;
  return 0;
}

/**
 * @brief Check for a bad login response from the server.
 *
 * @param  messages  A pointer into the OTP input buffer.
 *
 * @return 0 if there is a bad login response, else 1.
 */
static int
parse_server_bad_login (char** messages)
{
  /*@dependent@*/ char *end, *match;
  end = *messages + from_server_end - from_server_start;
  while (*messages < end && ((*messages)[0] == ' '))
    { (*messages)++; from_server_start++; }
  if ((match = memchr (*messages,
                       (int) '\n',
                       from_server_end - from_server_start)))
    {
      // FIX 19 available?
      if (strncasecmp ("Bad login attempt !", *messages, 19) == 0)
        {
          tracef ("match bad login\n");
          from_server_start += match + 1 - *messages;
          *messages = match + 1;
          set_server_init_state (SERVER_INIT_TOP);
          return 0;
        }
    }
  return 1;
}

/**
 * @brief FIX Parse the final SERVER field of an OTP message.
 *
 * @param  messages  A pointer into the OTP input buffer.
 *
 * @return 0 success, -2 too few characters (need more input).
 */
static int
parse_server_preference_value (char** messages)
{
  char *value, *end, *match;
  assert (current_server_preference != NULL);
  end = *messages + from_server_end - from_server_start;
  while (*messages < end && ((*messages)[0] == ' '))
    { (*messages)++; from_server_start++; }
  if ((match = memchr (*messages,
                       (int) '\n',
                       from_server_end - from_server_start)))
    {
      match[0] = '\0';
      value = g_strdup (*messages);
      add_server_preference (current_server_preference, value);
      set_server_state (SERVER_PREFERENCE_NAME);
      from_server_start += match + 1 - *messages;
      *messages = match + 1;
      return 0;
    }
  return -2;
}

/**
 * @brief Parse the final field of a plugin in a plugin list.
 *
 * @param  messages  A pointer into the OTP input buffer.
 *
 * @return 0 success, -2 too few characters (need more input).
 */
static int
parse_server_plugin_list_tags (char** messages)
{
  char *value, *end, *match;
  assert (current_plugin != NULL);
  end = *messages + from_server_end - from_server_start;
  while (*messages < end && ((*messages)[0] == ' '))
    { (*messages)++; from_server_start++; }
  if ((match = memchr (*messages,
                       (int) '\n',
                       from_server_end - from_server_start)))
    {
      match[0] = '\0';
      value = g_strdup (*messages);
      if (current_plugins && current_plugin)
        {
          nvti_set_tag (current_plugin, value);
          nvtis_add (current_plugins, current_plugin);
          current_plugin = NULL;
        }
      set_server_state (SERVER_PLUGIN_LIST_OID);
      from_server_start += match + 1 - *messages;
      *messages = match + 1;
      return 0;
    }
  return -2;
}

/**
 * @brief Parse an OTP rule.
 *
 * @param  messages  A pointer into the OTP input buffer.
 *
 * @return 0 read a rule, -1 read a <|>, -2 too few characters (need
 *         more input).
 */
static int
parse_server_rule (char** messages)
{
  char *end, *match;
  end = *messages + from_server_end - from_server_start;
  while (*messages < end && ((*messages)[0] == '\n'))
    { (*messages)++; from_server_start++; }
  while (*messages < end && ((*messages)[0] == ' '))
    { (*messages)++; from_server_start++; }
  /* Check for the end marker. */
  if (end - *messages > 2
      && (*messages)[0] == '<'
      && (*messages)[1] == '|'
      && (*messages)[2] == '>')
    /* The rules list ends with "<|> SERVER". */
    return -1;
  /* There may be a rule ending in a semicolon. */
  if ((match = memchr (*messages,
                       (int) ';',
                       from_server_end - from_server_start)))
    {
      char* rule;
      match[0] = '\0';
      rule = g_strdup (*messages);
      add_server_rule (rule);
      from_server_start += match + 1 - *messages;
      *messages = match + 1;
      return 0;
    }
  return -2;
}

/**
 * @brief Parse the dependency of a server plugin.
 *
 * @param  messages  A pointer into the OTP input buffer.
 *
 * @return TRUE if a <|> follows in the buffer, otherwise FALSE.
 */
static gboolean
parse_server_plugin_dependency_dependency (/*@dependent@*/ char** messages)
{
  /* Look for the end of dependency marker: a newline that comes before
   * the next <|>. */
  char *separator, *end, *match, *input;
  buffer_size_t from_start, from_end;
  separator = NULL;
  /* Look for <|>. */
  input = *messages;
  from_start = from_server_start;
  from_end = from_server_end;
  while (from_start < from_end
         && (match = memchr (input, (int) '<', from_end - from_start))
            != NULL)
    {
      assert (match >= input);
      if ((((match - input) + from_start + 1) < from_end)
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
  end = *messages + from_server_end - from_server_start;
  while (*messages < end && ((*messages)[0] == ' '))
    { (*messages)++; from_server_start++; }
  if ((match = memchr (*messages,
                       (int) '\n',
                       from_server_end - from_server_start)))
    {
      /* Compare newline position to <|> position. */
      if ((separator == NULL) || (match < separator))
        {
          finish_current_server_plugin_dependency ();
          from_server_start += match + 1 - *messages;
          *messages = match + 1;
          set_server_state (SERVER_PLUGIN_DEPENDENCY_NAME);
        }
    }
  return separator == NULL;
}

/**
 * @brief Parse the field following "SERVER <|>".
 *
 * @param  messages  A pointer into the OTP input buffer.
 *
 * @return 0 found a newline delimited field, -1 error, -2 need more input,
 *         -3 found a <|> before next newline (that is, a <|> delimited
 *         field follows), -4 failed to find a newline (may be a <|>)
 */
static int
parse_server_server (/*@dependent@*/ char** messages)
{
  /*@dependent@*/ char *end, *match;
  end = *messages + from_server_end - from_server_start;
  while (*messages < end && ((*messages)[0] == ' '))
    { (*messages)++; from_server_start++; }
  if ((match = memchr (*messages,
                       (int) '\n',
                       from_server_end - from_server_start)))
    {
      /*@dependent@*/ char* newline;
      /*@dependent@*/ char* input;
      buffer_size_t from_start, from_end;
      match[0] = '\0';
      // FIX is there ever whitespace before the newline?
      while (*messages < end && ((*messages)[0] == ' '))
        { (*messages)++; from_server_start++; }
      // FIX 20 available?
      if (strncasecmp ("PLUGINS_DEPENDENCIES", *messages, 20) == 0)
        {
          from_server_start += match + 1 - *messages;
          *messages = match + 1;
          make_server_plugins_dependencies ();
          set_server_state (SERVER_PLUGIN_DEPENDENCY_NAME);
          return 0;
        }
      // FIX 12 available?
      if (strncasecmp ("CERTIFICATES", *messages, 12) == 0)
        {
          from_server_start += match + 1 - *messages;
          *messages = match + 1;
          /* current_certificates may be allocated already due to a
           * request for the list before the end of the previous
           * request.  In this case just let the responses mix.
           * FIX depends what server does on multiple requests
           */
          if (current_certificates == NULL)
            {
              current_certificates = certificates_create ();
              if (current_certificates == NULL) abort (); // FIX
            }
          set_server_state (SERVER_CERTIFICATE_FINGERPRINT);
          return 0;
        }
      newline = match;
      newline[0] = '\n';
      /* Check for a <|>. */
      input = *messages;
      from_start = from_server_start;
      from_end = from_server_end;
      while (from_start < from_end
             && ((match = memchr (input,
                                  (int) '<',
                                  from_end - from_start))
                 != NULL))
        {
          assert (match >= input);
          if ((((match - input) + from_start + 1) < from_end)
              && (match[1] == '|')
              && (match[2] == '>'))
            {
              if (match > newline)
                /* The next <|> is after the newline, which is an error. */
                return -1;
              /* The next <|> is before the newline, which may be correct. */
              return -3;
            }
          from_start += match + 1 - input;
          input = match + 1;
        }
      /* Need more input for a newline or <|>. */
      return -2;
    }
  return -4;
}

/**
 * @brief "Synchronise" the \ref from_server buffer.
 *
 * Move any OTP in the \ref from_server buffer to the front of the buffer.
 *
 * @return 0 success, -1 \ref from_server is full.
 */
static int
sync_buffer ()
{
  if (from_server_start > 0 && from_server_start == from_server_end)
    {
      from_server_start = from_server_end = 0;
      tracef ("   server start caught end\n");
    }
  else if (from_server_start == 0)
    {
      if (from_server_end == from_buffer_size)
        {
          // FIX if the buffer is entirely full here then exit
          //     (or will hang waiting for buffer to empty)
          //     this could happen if the server sends a field with length >= buffer length
          //         could realloc buffer
          //             which may eventually use all mem and bring down manager
          //                 would only bring down the process serving the client
          //                 may lead to out of mem in other processes?
          //                 could realloc to an upper limit within avail mem
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
      tracef ("   new from_server_start: %" BUFFER_SIZE_T_FORMAT "\n",
              from_server_start);
      tracef ("   new from_server_end: %" BUFFER_SIZE_T_FORMAT "\n",
              from_server_end);
#endif
    }
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
 * @return 0 success, 1 received server BYE, 2 bad login, -1 error.
 */
int
process_otp_server_input ()
{
  /*@dependent@*/ char* match = NULL;
  /*@dependent@*/ char* messages = from_server + from_server_start;
  /*@dependent@*/ char* input;
  buffer_size_t from_start, from_end;
  //tracef ("   consider %.*s\n", from_server_end - from_server_start, messages);

  /* First, handle special server states where the input from the server
   * ends in something other than <|> (usually a newline). */

  switch (server_init_state)
    {
      case SERVER_INIT_SENT_VERSION:
        /* Read over any whitespace left by the previous session. */
        while (from_server_start < from_server_end
               && (messages[0] == ' ' || messages[0] == '\n'))
          from_server_start++, messages++;
        if (from_server_end - from_server_start < 12)
          {
            /* Need more input. */
            if (sync_buffer ()) return -1;
            return 0;
          }
        if (strncasecmp ("< OTP/1.0 >\n", messages, 12))
          {
            tracef ("   server fail: expected \"< OTP/1.0 >, got \"%.12s\"\n\"\n",
                    messages);
            return -1;
          }
        from_server_start += 12;
        messages += 12;
        set_server_init_state (SERVER_INIT_GOT_VERSION);
        /* Fall through to attempt next step. */
        /*@fallthrough@*/
      case SERVER_INIT_GOT_VERSION:
        if (from_server_end - from_server_start < 7)
          {
            /* Need more input. */
            if (sync_buffer ()) return -1;
            return 0;
          }
        if (strncasecmp ("User : ", messages, 7))
          {
            tracef ("   server fail: expected \"User : \", got \"%7s\"\n",
                    messages);
            return -1;
          }
        from_server_start += 7;
        messages += 7;
        set_server_init_state (SERVER_INIT_GOT_USER);
        if (sync_buffer ()) return -1;
        return 0;
      case SERVER_INIT_GOT_USER:
        /* Input from server after "User : " and before user name sent. */
        return -1;
      case SERVER_INIT_SENT_USER:
        if (from_server_end - from_server_start < 11)
          {
            /* Need more input. */
            if (sync_buffer ()) return -1;
            return 0;
          }
        if (strncasecmp ("Password : ", messages, 11))
          {
            tracef ("   server fail: expected \"Password : \", got \"%11s\"\n",
                    messages);
            return -1;
          }
        from_server_start += 11;
        messages += 11;
        set_server_init_state (SERVER_INIT_GOT_PASSWORD);
        if (sync_buffer ()) return -1;
        return 0;
      case SERVER_INIT_GOT_PASSWORD:
        /* Input from server after "Password : " and before password sent. */
        return -1;
      case SERVER_INIT_GOT_MD5SUM:
        /* Somehow called to process the input from the server that followed
         * the initial md5sum, before the initial response to the md5sum has
         * been sent.  A programming error, most likely in setting up for
         * select in serve_omp. */
        assert (0);
        return -1;
      case SERVER_INIT_GOT_PLUGINS:
        /* Somehow called to process the input from the server that followed
         * the initial plugin list, before the initial response to the list has
         * been sent.  A programming error, most likely in setting up for
         * select in serve_omp. */
        assert (0);
        return -1;
      case SERVER_INIT_CONNECT_INTR:
      case SERVER_INIT_CONNECTED:
        /* Input from server before version string sent. */
        return -1;
      case SERVER_INIT_SENT_COMPLETE_LIST:
      case SERVER_INIT_SENT_PASSWORD:
      case SERVER_INIT_DONE:
      case SERVER_INIT_TOP:
        if (server_state == SERVER_TOP)
          switch (parse_server_bad_login (&messages))
            {
              case 0: return 2;    /* Found bad login response. */
              case 1: break;
            }
        else if (server_state == SERVER_CERTIFICATE_PUBLIC_KEY)
          switch (parse_server_certificate_public_key (&messages))
            {
              case -2:
                /* Need more input. */
                if (sync_buffer ()) return -1;
                return 0;
            }
        else if (server_state == SERVER_DONE)
          switch (parse_server_done (&messages))
            {
              case -1: return -1;
              case -2:
                /* Need more input. */
                if (sync_buffer ()) return -1;
                return 0;
            }
        else if (server_state == SERVER_PLUGIN_LIST_TAGS)
          switch (parse_server_plugin_list_tags (&messages))
            {
              case -2:
                /* Need more input. */
                if (sync_buffer ()) return -1;
                return 0;
            }
        else if (server_state == SERVER_PREFERENCE_VALUE)
          switch (parse_server_preference_value (&messages))
            {
              case -2:
                /* Need more input. */
                if (sync_buffer ()) return -1;
                return 0;
            }
        else if (server_state == SERVER_RULE)
          while (1)
            {
              switch (parse_server_rule (&messages))
                {
                  case  0: continue;     /* Read a rule. */
                  case -1: break;        /* At final <|>. */
                  case -2:
                    /* Need more input. */
                    if (sync_buffer ()) return -1;
                    return 0;
                }
              break;
            }
        else if (server_state == SERVER_SERVER)
          /* Look for any newline delimited server commands. */
          switch (parse_server_server (&messages))
            {
              case  0: break;        /* Found newline delimited command. */
              case -1: return -1;    /* Error. */
              case -2:
                /* Need more input. */
                if (sync_buffer ()) return -1;
                return 0;
              case -3: break;        /* Next <|> is before next \n. */
              case -4: break;        /* Failed to find \n, try for <|>. */
            }
        else if (server_state == SERVER_PLUGIN_DEPENDENCY_DEPENDENCY
                 && parse_server_plugin_dependency_dependency (&messages))
          {
            /* Need more input for a <|>. */
            if (sync_buffer ()) return -1;
            return 0;
          }
        break;
    } /* switch (server_init_state) */

  /* Parse and handle any fields ending in <|>. */

  input = messages;
  from_start = from_server_start;
  from_end = from_server_end;
  while (from_start < from_end
         && ((match = memchr (input,
                              (int) '<',
                              from_end - from_start))
             != NULL))
    {
      assert (match >= input);
      if ((((match - input) + from_start + 1) < from_end)
          && (match[1] == '|')
          && (match[2] == '>'))
        {
          char* message;
          char* field;
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
          field = strip_space (message, match);

          tracef ("   server old state %i\n", server_state);
          tracef ("   server field: %s\n", field);
          switch (server_state)
            {
              case SERVER_BYE:
                if (strcasecmp ("BYE", field))
                  return -1;
                /* It's up to the caller to set the init state, as the
                 * caller must flush the ACK. */
                set_server_state (SERVER_DONE);
                switch (parse_server_done (&messages))
                  {
                    case  0:
                      if (sync_buffer ()) return -1;
                      server_active = 0;
                      if (acknowledge_bye ()) return -1;
                      return 1;
                    case -1: return -1;
                    case -2:
                      /* Need more input. */
                      if (sync_buffer ()) return -1;
                      return 0;
                  }
                break;
              case SERVER_CERTIFICATE_FINGERPRINT:
                {
                  if (strlen (field) == 0 && field[1] == '|')
                    {
                      certificates_free (server.certificates);
                      server.certificates = current_certificates;
                      current_certificates = NULL;
                      set_server_state (SERVER_DONE);
                      switch (parse_server_done (&messages))
                        {
                          case -1: return -1;
                          case -2:
                            /* Need more input. */
                            if (sync_buffer ()) return -1;
                            return 0;
                        }
                      break;
                    }
                  current_certificate = certificate_create ();
                  if (current_certificate == NULL) abort (); // FIX
                  if (certificate_set_fingerprint (current_certificate, field))
                    abort (); // FIX
                  set_server_state (SERVER_CERTIFICATE_OWNER);
                  break;
                }
              case SERVER_CERTIFICATE_LENGTH:
                {
                  /* Read over the length. */
                  // \todo TODO consider using this to read next field
                  set_server_state (SERVER_CERTIFICATE_PUBLIC_KEY);
                  switch (parse_server_certificate_public_key (&messages))
                    {
                      case -2:
                        /* Need more input. */
                        if (sync_buffer ()) return -1;
                        return 0;
                    }
                  break;
                }
              case SERVER_CERTIFICATE_OWNER:
                {
                  if (certificate_set_owner (current_certificate, field))
                    abort ();
                  set_server_state (SERVER_CERTIFICATE_TRUST_LEVEL);
                  break;
                }
              case SERVER_CERTIFICATE_TRUST_LEVEL:
                {
                  certificate_set_trusted (current_certificate,
                                           strcasecmp (field, "trusted") == 0);
                  set_server_state (SERVER_CERTIFICATE_LENGTH);
                  break;
                }
              case SERVER_DEBUG_DESCRIPTION:
                {
                  if (current_message)
                    {
                      // FIX \n for newline in description
                      char* description = g_strdup (field);
                      set_message_description (current_message, description);
                    }
                  set_server_state (SERVER_DEBUG_OID);
                  break;
                }
              case SERVER_DEBUG_HOST:
                {
                  assert (current_message == NULL);
                  current_message = make_message (field);
                  set_server_state (SERVER_DEBUG_NUMBER);
                  break;
                }
              case SERVER_DEBUG_NUMBER:
                {
                  // FIX field could be "general"
                  int number;
                  char *name;
                  char *protocol;

                  assert (current_message);

                  name = g_newa (char, strlen (field));
                  protocol = g_newa (char, strlen (field));

                  if (sscanf (field, "%s (%i/%[^)])",
                              name, &number, protocol)
                      != 3)
                    {
                      number = atoi (field);
                      protocol[0] = '\0';
                    }
                  tracef ("   server got debug port, number: %i, protocol: %s\n",
                          number, protocol);

                  set_message_port_number (current_message, number);
                  set_message_port_protocol (current_message, protocol);
                  set_message_port_string (current_message, g_strdup (field));

                  set_server_state (SERVER_DEBUG_DESCRIPTION);
                  break;
                }
              case SERVER_DEBUG_OID:
                {
                  if (current_message != NULL
                      && current_server_task != (task_t) NULL)
                    {
                      char* oid = g_strdup (field);
                      set_message_oid (current_message, oid);

                      append_debug_message (current_server_task, current_message);
                      free_message (current_message);
                      current_message = NULL;
                    }
                  set_server_state (SERVER_DONE);
                  switch (parse_server_done (&messages))
                    {
                      case -1: return -1;
                      case -2:
                        /* Need more input. */
                        if (sync_buffer ()) return -1;
                        return 0;
                    }
                  break;
                }
              case SERVER_HOLE_DESCRIPTION:
                {
                  if (current_message)
                    {
                      // FIX \n for newline in description
                      char* description = g_strdup (field);
                      set_message_description (current_message, description);
                    }
                  set_server_state (SERVER_HOLE_OID);
                  break;
                }
              case SERVER_HOLE_HOST:
                {
                  assert (current_message == NULL);
                  current_message = make_message (field);
                  set_server_state (SERVER_HOLE_NUMBER);
                  break;
                }
              case SERVER_HOLE_NUMBER:
                {
                  // FIX field could be "general"
                  int number;
                  char *name;
                  char *protocol;

                  assert (current_message);

                  name = g_newa (char, strlen (field));
                  protocol = g_newa (char, strlen (field));

                  if (sscanf (field, "%s (%i/%[^)])",
                              name, &number, protocol)
                      != 3)
                    {
                      number = atoi (field);
                      protocol[0] = '\0';
                    }
                  tracef ("   server got hole port, number: %i, protocol: %s\n",
                          number, protocol);

                  set_message_port_number (current_message, number);
                  set_message_port_protocol (current_message, protocol);
                  set_message_port_string (current_message, g_strdup (field));

                  set_server_state (SERVER_HOLE_DESCRIPTION);
                  break;
                }
              case SERVER_HOLE_OID:
                {
                  if (current_message != NULL
                      && current_server_task != (task_t) NULL)
                    {
                      char* oid = g_strdup (field);
                      set_message_oid (current_message, oid);

                      append_hole_message (current_server_task, current_message);
                      free_message (current_message);
                      current_message = NULL;
                    }
                  set_server_state (SERVER_DONE);
                  switch (parse_server_done (&messages))
                    {
                      case -1: return -1;
                      case -2:
                        /* Need more input. */
                        if (sync_buffer ()) return -1;
                        return 0;
                    }
                  break;
                }
              case SERVER_INFO_DESCRIPTION:
                {
                  if (current_message)
                    {
                      // FIX \n for newline in description
                      char* description = g_strdup (field);
                      set_message_description (current_message, description);
                    }
                  set_server_state (SERVER_INFO_OID);
                  break;
                }
              case SERVER_INFO_HOST:
                {
                  assert (current_message == NULL);
                  current_message = make_message (field);
                  set_server_state (SERVER_INFO_NUMBER);
                  break;
                }
              case SERVER_INFO_NUMBER:
                {
                  // FIX field could be "general"
                  int number;
                  char *name;
                  char *protocol;

                  assert (current_message);

                  name = g_newa (char, strlen (field));
                  protocol = g_newa (char, strlen (field));

                  if (sscanf (field, "%s (%i/%[^)])",
                              name, &number, protocol)
                      != 3)
                    {
                      number = atoi (field);
                      protocol[0] = '\0';
                    }
                  tracef ("   server got info port, number: %i, protocol: %s\n",
                          number, protocol);

                  set_message_port_number (current_message, number);
                  set_message_port_protocol (current_message, protocol);
                  set_message_port_string (current_message, g_strdup (field));

                  set_server_state (SERVER_INFO_DESCRIPTION);
                  break;
                }
              case SERVER_INFO_OID:
                {
                  if (current_message != NULL
                      && current_server_task != (task_t) NULL)
                    {
                      char* oid = g_strdup (field);
                      set_message_oid (current_message, oid);

                      append_info_message (current_server_task, current_message);
                      free_message (current_message);
                      current_message = NULL;
                    }
                  set_server_state (SERVER_DONE);
                  switch (parse_server_done (&messages))
                    {
                      case -1: return -1;
                      case -2:
                        /* Need more input. */
                        if (sync_buffer ()) return -1;
                        return 0;
                    }
                  break;
                }
              case SERVER_LOG_DESCRIPTION:
                {
                  if (current_message)
                    {
                      // FIX \n for newline in description
                      char* description = g_strdup (field);
                      set_message_description (current_message, description);
                    }
                  set_server_state (SERVER_LOG_OID);
                  break;
                }
              case SERVER_LOG_HOST:
                {
                  assert (current_message == NULL);
                  current_message = make_message (field);
                  set_server_state (SERVER_LOG_NUMBER);
                  break;
                }
              case SERVER_LOG_NUMBER:
                {
                  // FIX field could be "general"
                  int number;
                  char *name;
                  char *protocol;

                  assert (current_message);

                  name = g_newa (char, strlen (field));
                  protocol = g_newa (char, strlen (field));

                  if (sscanf (field, "%s (%i/%[^)])",
                              name, &number, protocol)
                      != 3)
                    {
                      number = atoi (field);
                      protocol[0] = '\0';
                    }
                  tracef ("   server got log port, number: %i, protocol: %s\n",
                          number, protocol);

                  set_message_port_number (current_message, number);
                  set_message_port_protocol (current_message, protocol);
                  set_message_port_string (current_message, g_strdup (field));

                  set_server_state (SERVER_LOG_DESCRIPTION);
                  break;
                }
              case SERVER_LOG_OID:
                {
                  if (current_message != NULL
                      && current_server_task != (task_t) NULL)
                    {
                      char* oid = g_strdup (field);
                      set_message_oid (current_message, oid);

                      append_log_message (current_server_task, current_message);
                      free_message (current_message);
                      current_message = NULL;
                    }
                  set_server_state (SERVER_DONE);
                  switch (parse_server_done (&messages))
                    {
                      case -1: return -1;
                      case -2:
                        /* Need more input. */
                        if (sync_buffer ()) return -1;
                        return 0;
                    }
                  break;
                }
              case SERVER_NOTE_DESCRIPTION:
                {
                  if (current_message)
                    {
                      // FIX \n for newline in description
                      char* description = g_strdup (field);
                      set_message_description (current_message, description);
                    }
                  set_server_state (SERVER_NOTE_OID);
                  break;
                }
              case SERVER_NOTE_HOST:
                {
                  assert (current_message == NULL);
                  current_message = make_message (field);
                  set_server_state (SERVER_NOTE_NUMBER);
                  break;
                }
              case SERVER_NOTE_NUMBER:
                {
                  // FIX field could be "general"
                  int number;
                  char *name;
                  char *protocol;

                  assert (current_message);

                  name = g_newa (char, strlen (field));
                  protocol = g_newa (char, strlen (field));

                  if (sscanf (field, "%s (%i/%[^)])",
                              name, &number, protocol)
                      != 3)
                    {
                      number = atoi (field);
                      protocol[0] = '\0';
                    }
                  tracef ("   server got note port, number: %i, protocol: %s\n",
                          number, protocol);

                  set_message_port_number (current_message, number);
                  set_message_port_protocol (current_message, protocol);
                  set_message_port_string (current_message, g_strdup (field));

                  set_server_state (SERVER_NOTE_DESCRIPTION);
                  break;
                }
              case SERVER_NOTE_OID:
                {
                  if (current_message != NULL
                      && current_server_task != (task_t) NULL)
                    {
                      char* oid = g_strdup (field);
                      set_message_oid (current_message, oid);

                      append_note_message (current_server_task, current_message);
                      free_message (current_message);
                      current_message = NULL;
                    }
                  set_server_state (SERVER_DONE);
                  switch (parse_server_done (&messages))
                    {
                      case -1: return -1;
                      case -2:
                        /* Need more input. */
                        if (sync_buffer ()) return -1;
                        return 0;
                    }
                  break;
                }
              case SERVER_PLUGIN_DEPENDENCY_NAME:
                {
                  if (strlen (field) == 0 && field[1] == '|')
                    {
                      set_server_state (SERVER_DONE);
                      switch (parse_server_done (&messages))
                        {
                          case -1: return -1;
                          case -2:
                            /* Need more input. */
                            if (sync_buffer ()) return -1;
                            return 0;
                        }
                      break;
                    }
                  {
                    char* name = g_strdup (field);
                    make_current_server_plugin_dependency (name);
                    set_server_state (SERVER_PLUGIN_DEPENDENCY_DEPENDENCY);
                    if (parse_server_plugin_dependency_dependency (&messages))
                      {
                        /* Need more input for a <|>. */
                        if (sync_buffer ()) return -1;
                        return 0;
                      }
                  }
                  break;
                }
              case SERVER_PLUGIN_DEPENDENCY_DEPENDENCY:
                {
                  char* dep = g_strdup (field);
                  append_to_current_server_plugin_dependency (dep);
                  if (parse_server_plugin_dependency_dependency (&messages))
                    {
                      /* Need more input for a <|>. */
                      if (sync_buffer ()) return -1;
                      return 0;
                    }
                  break;
                }
              case SERVER_PLUGIN_LIST_OID:
                {
                  if (strlen (field) == 0 && field[1] == '|')
                    {
                      nvtis_free (server.plugins);
                      server.plugins = current_plugins;
                      current_plugins = NULL;
                      set_server_state (SERVER_DONE);
                      switch (parse_server_done (&messages))
                        {
                          case  0:
                            if (server_init_state == SERVER_INIT_SENT_COMPLETE_LIST)
                              set_server_init_state (SERVER_INIT_GOT_PLUGINS);
                            break;
                          case -1: return -1;
                          case -2:
                            /* Need more input. */
                            if (sync_buffer ()) return -1;
                            return 0;
                        }
                      break;
                    }
                  assert (current_plugin == NULL);
                  current_plugin = nvti_new ();
                  if (current_plugin == NULL) abort (); // FIX
                  nvti_set_oid (current_plugin, field);
                  set_server_state (SERVER_PLUGIN_LIST_NAME);
                  break;
                }
              case SERVER_PLUGIN_LIST_NAME:
                {
                  nvti_set_name (current_plugin, field);
                  set_server_state (SERVER_PLUGIN_LIST_CATEGORY);
                  break;
                }
              case SERVER_PLUGIN_LIST_CATEGORY:
                {
                  // FIX parse category number from field
                  nvti_set_category (current_plugin, 0);
                  set_server_state (SERVER_PLUGIN_LIST_COPYRIGHT);
                  break;
                }
              case SERVER_PLUGIN_LIST_COPYRIGHT:
                {
                  nvti_set_copyright (current_plugin, field);
                  set_server_state (SERVER_PLUGIN_LIST_DESCRIPTION);
                  break;
                }
              case SERVER_PLUGIN_LIST_DESCRIPTION:
                {
                  nvti_set_description (current_plugin, field);
                  set_server_state (SERVER_PLUGIN_LIST_SUMMARY);
                  break;
                }
              case SERVER_PLUGIN_LIST_SUMMARY:
                {
                  nvti_set_summary (current_plugin, field);
                  set_server_state (SERVER_PLUGIN_LIST_FAMILY);
                  break;
                }
              case SERVER_PLUGIN_LIST_FAMILY:
                {
                  nvti_set_family (current_plugin, field);
                  set_server_state (SERVER_PLUGIN_LIST_PLUGIN_VERSION);
                  break;
                }
              case SERVER_PLUGIN_LIST_PLUGIN_VERSION:
                {
                  nvti_set_version (current_plugin, field);
                  set_server_state (SERVER_PLUGIN_LIST_CVE_ID);
                  break;
                }
              case SERVER_PLUGIN_LIST_CVE_ID:
                {
                  nvti_set_cve (current_plugin, field);
                  set_server_state (SERVER_PLUGIN_LIST_BUGTRAQ_ID);
                  break;
                }
              case SERVER_PLUGIN_LIST_BUGTRAQ_ID:
                {
                  nvti_set_bid (current_plugin, field);
                  set_server_state (SERVER_PLUGIN_LIST_XREFS);
                  break;
                }
              case SERVER_PLUGIN_LIST_XREFS:
                {
                  nvti_set_xref (current_plugin, field);
                  set_server_state (SERVER_PLUGIN_LIST_FPRS);
                  break;
                }
              case SERVER_PLUGIN_LIST_FPRS:
                {
                  nvti_set_sign_key_ids (current_plugin, field);
                  set_server_state (SERVER_PLUGIN_LIST_TAGS);
                  switch (parse_server_plugin_list_tags (&messages))
                    {
                      case -2:
                        /* Need more input. */
                        if (sync_buffer ()) return -1;
                        return 0;
                    }
                  break;
                }
              case SERVER_PLUGINS_MD5:
                {
                  char* md5 = g_strdup (field);
                  tracef ("   server got plugins_md5: %s\n", md5);
                  if (server.plugins_md5) g_free (server.plugins_md5);
                  server.plugins_md5 = md5;
                  set_server_state (SERVER_DONE);
                  switch (parse_server_done (&messages))
                    {
                      case  0:
                        // FIX introduce plugin cache
                        //if (acknowledge_md5sum ()) return -1;
                        //if (acknowledge_md5sum_sums ()) return -1;
                        if (server_init_state == SERVER_INIT_SENT_PASSWORD)
                          set_server_init_state (SERVER_INIT_GOT_MD5SUM);
                        else if (acknowledge_md5sum_info ())
                          return -1;
                        break;
                      case -1: return -1;
                      case -2:
                        /* Need more input. */
                        if (sync_buffer ()) return -1;
                        return 0;
                    }
                  break;
                }
              case SERVER_PORT_HOST:
                {
                  //if (strcasecmp ("chiles", field) == 0) // FIX
                  set_server_state (SERVER_PORT_NUMBER);
                  break;
                }
              case SERVER_PORT_NUMBER:
                {
                  if (current_server_task)
                    {
                      int number;
                      char *name = g_malloc0 (strlen (field));
                      char *protocol = g_malloc0 (strlen (field));

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
                      g_free (name);
                      g_free (protocol);
                    }
                  set_server_state (SERVER_DONE);
                  switch (parse_server_done (&messages))
                    {
                      case -1: return -1;
                      case -2:
                        /* Need more input. */
                        if (sync_buffer ()) return -1;
                        return 0;
                    }
                  break;
                }
              case SERVER_PREFERENCE_NAME:
                {
                  if (strlen (field) == 0 && field[1] == '|')
                    {
                      set_server_state (SERVER_DONE);
                      switch (parse_server_done (&messages))
                        {
                          case -1: return -1;
                          case -2:
                            /* Need more input. */
                            if (sync_buffer ()) return -1;
                            return 0;
                        }
                      break;
                    }
                  {
                    current_server_preference = g_strdup (field);
                    set_server_state (SERVER_PREFERENCE_VALUE);
                    switch (parse_server_preference_value (&messages))
                      {
                        case -2:
                          /* Need more input. */
                          if (sync_buffer ()) return -1;
                          return 0;
                      }
                  }
                  break;
                }
              case SERVER_RULE:
                /* A <|> following a rule. */
                set_server_state (SERVER_DONE);
                switch (parse_server_done (&messages))
                  {
                    case -1: return -1;
                    case -2:
                      /* Need more input. */
                      if (sync_buffer ()) return -1;
                      return 0;
                  }
                break;
              case SERVER_SERVER:
                if (strcasecmp ("BYE", field) == 0)
                  set_server_state (SERVER_BYE);
                else if (strcasecmp ("DEBUG", field) == 0)
                  set_server_state (SERVER_HOLE_HOST);
                else if (strcasecmp ("HOLE", field) == 0)
                  set_server_state (SERVER_HOLE_HOST);
                else if (strcasecmp ("INFO", field) == 0)
                  set_server_state (SERVER_INFO_HOST);
                else if (strcasecmp ("LOG", field) == 0)
                  set_server_state (SERVER_LOG_HOST);
                else if (strcasecmp ("NOTE", field) == 0)
                  set_server_state (SERVER_NOTE_HOST);
                else if (strcasecmp ("PLUGINS_MD5", field) == 0)
                  set_server_state (SERVER_PLUGINS_MD5);
                else if (strcasecmp ("PLUGIN_LIST", field) == 0)
                  {
                    /* current_plugins may be allocated already due to a
                     * request for the list before the end of the previous
                     * request.  In this case just let the responses mix.
                     * FIX depends what server does on multiple requests
                     */
                    if (current_plugins == NULL)
                      current_plugins = nvtis_new ();
                    set_server_state (SERVER_PLUGIN_LIST_OID);
                  }
                else if (strcasecmp ("PORT", field) == 0)
                  set_server_state (SERVER_PORT_HOST);
                else if (strcasecmp ("PREFERENCES", field) == 0)
                  {
                    make_server_preferences ();
                    set_server_state (SERVER_PREFERENCE_NAME);
                  }
                else if (strcasecmp ("RULES", field) == 0)
                  {
                    maybe_free_server_rules ();
                    make_server_rules ();
                    set_server_state (SERVER_RULE);
                    while (1)
                      {
                        switch (parse_server_rule (&messages))
                          {
                            case  0: continue;     /* Read a rule. */
                            case -1: break;        /* At final <|>. */
                            case -2:
                              /* Need more input. */
                              if (sync_buffer ()) return -1;
                              return 0;
                          }
                        break;
                      }
                    break;
                  }
                else if (strcasecmp ("TIME", field) == 0)
                  {
                    set_server_state (SERVER_TIME);
                  }
                else if (strcasecmp ("STATUS", field) == 0)
                  {
                    set_server_state (SERVER_STATUS_HOST);
                  }
                else
                  {
                    tracef ("New server command to implement: %s\n",
                            field);
                    return -1;
                  }
                break;
              case SERVER_STATUS_ATTACK_STATE:
                {
                  if (current_host)
                    {
                      char* state = g_strdup (field);
                      set_scan_attack_state (current_report,
                                             current_host,
                                             state);
                    }
                  set_server_state (SERVER_STATUS_PORTS);
                  break;
                }
              case SERVER_STATUS_HOST:
                {
                  assert (current_host == NULL);
                  current_host = g_strdup (field);
                  set_server_state (SERVER_STATUS_ATTACK_STATE);
                  break;
                }
              case SERVER_STATUS_PORTS:
                {
                  assert (current_report);
                  if (current_report && current_host)
                    {
                      unsigned int current, max;
                      tracef ("   server got ports: %s\n", field);
                      if (sscanf (field, "%u/%u", &current, &max) == 2)
                        set_scan_ports (current_report,
                                        current_host,
                                        current,
                                        max);
                    }
                  if (current_host)
                    {
                      g_free (current_host);
                      current_host = NULL;
                    }
                  set_server_state (SERVER_DONE);
                  switch (parse_server_done (&messages))
                    {
                      case -1: return -1;
                      case -2:
                        /* Need more input. */
                        if (sync_buffer ()) return -1;
                        return 0;
                    }
                  break;
                }
              case SERVER_TIME:
                {
                  if (strcasecmp ("HOST_START", field) == 0)
                    set_server_state (SERVER_TIME_HOST_START_HOST);
                  else if (strcasecmp ("HOST_END", field) == 0)
                    set_server_state (SERVER_TIME_HOST_END_HOST);
                  else if (strcasecmp ("SCAN_START", field) == 0)
                    set_server_state (SERVER_TIME_SCAN_START);
                  else if (strcasecmp ("SCAN_END", field) == 0)
                    set_server_state (SERVER_TIME_SCAN_END);
                  else
                    abort (); // FIX read all fields up to <|> SERVER?
                  break;
                }
              case SERVER_TIME_HOST_START_HOST:
                {
                  assert (current_host == NULL);
                  current_host = g_strdup (field);
                  set_server_state (SERVER_TIME_HOST_START_TIME);
                  break;
                }
              case SERVER_TIME_HOST_START_TIME:
                {
                  if (current_server_task)
                    {
                      assert (current_host);
                      set_scan_host_start_time (current_report,
                                                current_host,
                                                field);
                      g_free (current_host);
                      current_host = NULL;
                    }
                  set_server_state (SERVER_DONE);
                  switch (parse_server_done (&messages))
                    {
                      case -1: return -1;
                      case -2:
                        /* Need more input. */
                        if (sync_buffer ()) return -1;
                        return 0;
                    }
                  break;
                }
              case SERVER_TIME_HOST_END_HOST:
                {
                  assert (current_host == NULL);
                  current_host = g_strdup (field);
                  set_server_state (SERVER_TIME_HOST_END_TIME);
                  break;
                }
              case SERVER_TIME_HOST_END_TIME:
                {
                  if (current_server_task)
                    {
                      assert (current_host);
                      set_scan_host_end_time (current_report,
                                              current_host,
                                              field);
                      g_free (current_host);
                      current_host = NULL;
                    }
                  set_server_state (SERVER_DONE);
                  switch (parse_server_done (&messages))
                    {
                      case -1: return -1;
                      case -2:
                        /* Need more input. */
                        if (sync_buffer ()) return -1;
                        return 0;
                    }
                  break;
                }
              case SERVER_TIME_SCAN_START:
                {
                  if (current_server_task)
                    {
                      set_task_run_status (current_server_task,
                                           TASK_STATUS_RUNNING);
                      set_task_start_time (current_server_task,
                                           g_strdup (field));
                      set_scan_start_time (current_report, field);
                    }
                  set_server_state (SERVER_DONE);
                  switch (parse_server_done (&messages))
                    {
                      case -1: return -1;
                      case -2:
                        /* Need more input. */
                        if (sync_buffer ()) return -1;
                        return 0;
                    }
                  break;
                }
              case SERVER_TIME_SCAN_END:
                {
                  if (current_server_task)
                    {
                      switch (task_run_status (current_server_task))
                        {
                          case TASK_STATUS_STOP_REQUESTED:
                            set_task_run_status (current_server_task,
                                                 TASK_STATUS_STOPPED);
                            break;
                          case TASK_STATUS_DELETE_REQUESTED:
                            delete_task (current_server_task);
                            current_report = (report_t) NULL;
                            break;
                          default:
                            set_task_run_status (current_server_task,
                                                 TASK_STATUS_DONE);
                            set_task_end_time (current_server_task,
                                               g_strdup (field));
                        }
                      if (current_report)
                        {
                          set_scan_end_time (current_report, field);
                          current_report = (report_t) NULL;
                        }
                      current_server_task = (task_t) NULL;
                    }
                  set_server_state (SERVER_DONE);
                  switch (parse_server_done (&messages))
                    {
                      case -1: return -1;
                      case -2:
                        /* Need more input. */
                        if (sync_buffer ()) return -1;
                        return 0;
                    }
                  break;
                }
              case SERVER_TOP:
              default:
                tracef ("   switch t\n");
                tracef ("   cmp %i\n", strcasecmp ("SERVER", field));
                if (strcasecmp ("SERVER", field))
                  return -1;
                set_server_state (SERVER_SERVER);
                /* Look for any newline delimited server commands. */
                switch (parse_server_server (&messages))
                  {
                    case  0: break;        /* Found newline delimited command. */
                    case -1: return -1;    /* Error. */
                    case -2:
                      /* Need more input. */
                      if (sync_buffer ()) return -1;
                      return 0;
                    case -3: break;        /* Next <|> is before next \n. */
                    case -4: break;        /* Failed to find \n, try for <|>. */
                  }
                break;
            }

          tracef ("   server new state: %i\n", server_state);
        }
      else
        {
          from_start += match + 1 - input;
          input = match + 1;
        }
    }

  if (sync_buffer ()) return -1;
  return 0;
}
