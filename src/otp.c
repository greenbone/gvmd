/* OpenVAS Manager
 * $Id$
 * Description: Module for OpenVAS Manager: the OTP library.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
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
 * The library provides a single function, \ref process_otp_scanner_input.
 * This function parses a given string of OTP text and adjusts local
 * task records according to the OTP messages in the string.
 */

/**
 * @todo
 * Ensure that the globals used to store information across the XML
 * parser callbacks (for example, current_scanner_preferences) are freed in
 * the failure cases.
 */

#include "otp.h"
#include "manage.h"
#include "manage_sql.h"
#include "tracef.h"
#include "types.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openvas/base/openvas_string.h>
#include <openvas/misc/nvt_categories.h>

#ifdef S_SPLINT_S
#include "splint.h"
#endif

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md    otp"

/** @todo As with the OMP version, this should most likely be passed to and from
 *        the client in a data structure like an otp_parser_t. */
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

/**
 * @brief Return the number associated with a category name.
 *
 * @param  category  The category name.
 *
 * @return The number of the category.
 */
static int
category_number (const char *category)
{
  static const char *categories[] = { ACT_STRING_LIST_ALL };
  int index;
  for (index = ACT_FIRST; index <= ACT_END; index++)
    if (strcmp (category, categories[index]) == 0)
      return index;
  return ACT_UNKNOWN;
}

/** @brief Replace any control characters in string with spaces.
 *
 * @param[in,out]  string  String to replace in.
 */
static void
blank_control_chars (char *string)
{
  for (; *string; string++)
    if (iscntrl (*string) && *string != '\n') *string = ' ';
}


/* Ports. */

/** @todo Currently in manage.h. */
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

/** @todo Currently in manage.c. */
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
  /** @todo Calc subnet (__host2subnet in openvas-client/nessus/parser.c). */
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
 * @param[in]  task     The task with which to associate the message.
 * @param[in]  message  The message.
 * @param[in]  type     The message type (for example "Security Warning").
 */
static void
write_message (task_t task, message_t* message, char* type)
{
  result_t result;

  assert (current_report);

  manage_transaction_start ();
  result = make_result (task, message->subnet, message->host,
                        message->port.string, message->oid, type,
                        message->description);
  if (current_report) report_add_result (current_report, result);
}

/**
 * @brief Append a error message to a report.
 *
 * @param[in]  task         Task.
 * @param[in]  message      Message.
 */
static void
append_error_message (task_t task, message_t* message)
{
  write_message (task, message, "Error Message");
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
  assert (current_report);

  if (message->port.string
      && (strcmp (message->port.string, "general/Host_Details") == 0))
    {
      int len;
      /* Strip trailing \n. */
      len = strlen (message->description);
      if ((len > 2)
          && (message->description[len - 1] == 'n')
          && (message->description[len - 2] == '\\'))
        message->description[len - 2] = '\0';
      /* Add detail to report. */
      if (manage_report_host_detail (current_report,
                                     message->host,
                                     message->description))
        g_warning ("%s: Failed to add report detail for host '%s': %s\n",
                   __FUNCTION__,
                   message->host,
                   message->description);
    }
  else
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


/* Scanner preferences. */

/**
 * @brief The current scanner preference, during reading of scanner preferences.
 */
/*@null@*/ /*@only@*/
static char* current_scanner_preference = NULL;


/* Scanner plugins. */

/**
 * @brief The current plugin, during reading of scanner plugin list.
 */
/*@only@*/
static nvti_t* current_plugin = NULL;


/* Scanner plugin dependencies. */

/**
 * @brief The current scanner plugin, during reading of scanner plugin dependencies.
 */
/*@only@*/
static char* current_scanner_plugin_dependency_name = NULL;

/**
 * @brief The plugins required by the current scanner plugin.
 */
/*@only@*/
static GSList* current_scanner_plugin_dependency_dependencies = NULL;

/**
 * @brief Make the scanner plugins dependencies.
 */
static void
make_scanner_plugins_dependencies ()
{
  if (scanner.plugins_dependencies)
    {
      g_hash_table_destroy (scanner.plugins_dependencies);
      scanner.plugins_dependencies = NULL;
    }
  scanner.plugins_dependencies = g_hash_table_new_full (g_str_hash,
                                                        g_str_equal,
                                                        g_free,
                                                        free_g_slist);
}

/**
 * @brief Add a plugin to the scanner dependencies.
 *
 * @param[in]  name          The name of the plugin.
 * @param[in]  requirements  The plugins required by the plugin.
 */
static void
add_scanner_plugins_dependency (/*@keep@*/ char* name,
                                /*@keep@*/ GSList* requirements)
{
  assert (scanner.plugins_dependencies != NULL);
  tracef ("   scanner new dependency name: %s\n", name);
  g_hash_table_insert (scanner.plugins_dependencies, name, requirements);
}

/**
 * @brief Set the current plugin.
 *
 * @param[in]  name  The name of the plugin.  Used directly, freed by
 *                   maybe_free_current_scanner_plugin_dependency.
 */
static void
make_current_scanner_plugin_dependency (/*@only@*/ char* name)
{
  assert (current_scanner_plugin_dependency_name == NULL);
  assert (current_scanner_plugin_dependency_dependencies == NULL);
  current_scanner_plugin_dependency_name = name;
  current_scanner_plugin_dependency_dependencies = NULL; /* Empty list. */
}

/**
 * @brief Append a requirement to the current plugin.
 *
 * @param[in]  requirement  The name of the required plugin.  Used directly,
 *                          freed when the dependencies are freed in
 *                          make_scanner_plugins_dependencies.
 */
static void
append_to_current_scanner_plugin_dependency (/*@keep@*/ char* requirement)
{
  tracef ("   scanner appending plugin requirement: %s\n", requirement);
  current_scanner_plugin_dependency_dependencies
    = g_slist_append (current_scanner_plugin_dependency_dependencies,
                      requirement);
}

/**
 * @brief Add the current plugin to the scanner dependencies.
 */
static void
finish_current_scanner_plugin_dependency ()
{
  assert (current_scanner_plugin_dependency_name != NULL);
  add_scanner_plugins_dependency (current_scanner_plugin_dependency_name,
                                  current_scanner_plugin_dependency_dependencies);
  current_scanner_plugin_dependency_name = NULL;
  current_scanner_plugin_dependency_dependencies = NULL;
}


/* Scanner rules. */

/**
 * @brief Free a scanner rule.
 *
 * @param[in]  rule   The scanner rule.
 * @param[in]  dummy  Dummy parameter, to please g_ptr_array_foreach.
 */
static void
free_rule (/*@only@*/ /*@out@*/ void* rule, /*@unused@*/ void* dummy)
{
  if (rule) free (rule);
}

/**
 * @brief Free any scanner rules.
 */
static void
maybe_free_scanner_rules ()
{
  if (scanner.rules)
    {
      g_ptr_array_foreach (scanner.rules, free_rule, NULL);
      (void) g_ptr_array_free (scanner.rules, TRUE);
      scanner.rules_size = 0;
    }
}

/**
 * @brief Create the scanner rules.
 */
static void
make_scanner_rules ()
{
  scanner.rules = g_ptr_array_new ();
  scanner.rules_size = 0;
}

/**
 * @brief Add a rule to the scanner rules.
 *
 * The rule is used directly and is freed with the other scanner rules.
 *
 * @param[in]  rule  The rule.
 */
static void
add_scanner_rule (/*@keep@*/ char* rule)
{
  g_ptr_array_add (scanner.rules, rule);
  scanner.rules_size++;
}


/* Scanner state. */

/**
 * @brief Initialise OTP library data.
 *
 * This must run once, before the first call to \ref process_otp_scanner_input.
 */
void
init_otp_data ()
{
  scanner.certificates = NULL;
  scanner.rules = NULL;
  scanner.plugins_md5 = NULL;
}

/**
 * @brief Possible states of the scanner.
 */
typedef enum
{
  SCANNER_BYE,
  SCANNER_CERTIFICATE_FINGERPRINT,
  SCANNER_CERTIFICATE_LENGTH,
  SCANNER_CERTIFICATE_OWNER,
  SCANNER_CERTIFICATE_PUBLIC_KEY,
  SCANNER_CERTIFICATE_TRUST_LEVEL,
  SCANNER_DONE,
  SCANNER_ERRMSG_DESCRIPTION,
  SCANNER_ERRMSG_HOST,
  SCANNER_ERRMSG_NUMBER,
  SCANNER_ERRMSG_OID,
  SCANNER_ERROR,
  SCANNER_HOLE_DESCRIPTION,
  SCANNER_HOLE_HOST,
  SCANNER_HOLE_NUMBER,
  SCANNER_HOLE_OID,
  SCANNER_INFO_DESCRIPTION,
  SCANNER_INFO_HOST,
  SCANNER_INFO_NUMBER,
  SCANNER_INFO_OID,
  SCANNER_LOG_DESCRIPTION,
  SCANNER_LOG_HOST,
  SCANNER_LOG_NUMBER,
  SCANNER_LOG_OID,
  SCANNER_NOTE_DESCRIPTION,
  SCANNER_NOTE_HOST,
  SCANNER_NOTE_NUMBER,
  SCANNER_NOTE_OID,
  SCANNER_PLUGINS_MD5,
  SCANNER_PLUGIN_LIST_BUGTRAQ_ID,
  SCANNER_PLUGIN_LIST_CATEGORY,
  SCANNER_PLUGIN_LIST_COPYRIGHT,
  SCANNER_PLUGIN_LIST_CVE_ID,
  SCANNER_PLUGIN_LIST_DESCRIPTION,
  SCANNER_PLUGIN_LIST_FAMILY,
  SCANNER_PLUGIN_LIST_FPRS,
  SCANNER_PLUGIN_LIST_NAME,
  SCANNER_PLUGIN_LIST_OID,
  SCANNER_PLUGIN_LIST_PLUGIN_VERSION,
  SCANNER_PLUGIN_LIST_SUMMARY,
  SCANNER_PLUGIN_LIST_TAGS,
  SCANNER_PLUGIN_LIST_XREFS,
  SCANNER_PLUGIN_DEPENDENCY_NAME,
  SCANNER_PLUGIN_DEPENDENCY_DEPENDENCY,
  SCANNER_PORT_HOST,
  SCANNER_PORT_NUMBER,
  SCANNER_PREFERENCE_NAME,
  SCANNER_PREFERENCE_VALUE,
  SCANNER_RULE,
  SCANNER_SERVER,
  SCANNER_STATUS,
  SCANNER_STATUS_ATTACK_STATE,
  SCANNER_STATUS_HOST,
  SCANNER_STATUS_PORTS,
  SCANNER_STATUS_PROGRESS,
  SCANNER_TIME,
  SCANNER_TIME_HOST_START_HOST,
  SCANNER_TIME_HOST_START_TIME,
  SCANNER_TIME_HOST_END_HOST,
  SCANNER_TIME_HOST_END_TIME,
  SCANNER_TIME_SCAN_START,
  SCANNER_TIME_SCAN_END,
  SCANNER_TOP
} scanner_state_t;

/**
 * @brief The state of the scanner.
 */
static scanner_state_t scanner_state = SCANNER_TOP;

/**
 * @brief Set the scanner state, \ref scanner_state.
 */
static void
set_scanner_state (scanner_state_t state)
{
  scanner_state = state;
  tracef ("   scanner state set: %i\n", scanner_state);
}

/**
 * @brief The initialisation state of the scanner.
 */
scanner_init_state_t scanner_init_state = SCANNER_INIT_TOP;

/**
 * @brief Offset into initialisation string being sent to scanner.
 */
int scanner_init_offset = 0;

/**
 * @brief Set the scanner initialisation state, \ref scanner_init_state.
 */
void
set_scanner_init_state (scanner_init_state_t state)
{
  scanner_init_state = state;
  tracef ("   scanner init state set: %i\n", scanner_init_state);
}


/* Scanner certificates. */

/**
 * @brief The current certificates, during reading of scanner certificates.
 */
/*@only@*/
static certificates_t* current_certificates = NULL;

/**
 * @brief The current certificate, during reading of scanner certificates.
 */
/*@only@*/
static certificate_t* current_certificate = NULL;


/* OTP input processor. */

/** @todo As with the OMP version, these should most likely be passed to and
 *        from the client in a data structure like an otp_parser_t. */
extern char from_scanner[];
extern buffer_size_t from_scanner_start;
extern buffer_size_t from_scanner_end;

/**
 * @brief "Synchronise" the \ref from_scanner buffer.
 *
 * Move any OTP in the \ref from_scanner buffer to the front of the buffer.
 *
 * @return 0 success, -1 \ref from_scanner is full.
 */
static int
sync_buffer ()
{
  if (from_scanner_start > 0 && from_scanner_start == from_scanner_end)
    {
      from_scanner_start = from_scanner_end = 0;
      tracef ("   scanner start caught end\n");
    }
  else if (from_scanner_start == 0)
    {
      if (from_scanner_end == from_buffer_size)
        {
          /** @todo If the buffer is entirely full here then exit.
           *     (Or will hang waiting for buffer to empty.)
           *     Could happen if scanner sends a field longer than the buffer.
           *         Could realloc buffer instead.
           *             which may eventually use all mem and bring down manager
           *                 would only bring down process serving the client
           *                 may lead to out of mem in other processes?
           *                 could realloc to an upper limit within avail mem
           *         Could process some OTP to empty space in the buffer.
           **/
          tracef ("   scanner buffer full\n");
          return -1;
        }
    }
  else
    {
      /* Move the remaining partial line to the front of the buffer.  This
       * ensures that there is space after the partial line into which
       * serve_omp can read the rest of the line. */
      char* start = from_scanner + from_scanner_start;
      from_scanner_end -= from_scanner_start;
      memmove (from_scanner, start, from_scanner_end);
      from_scanner_start = 0;
#if TRACE
      from_scanner[from_scanner_end] = '\0';
      //tracef ("   new from_scanner: %s\n", from_scanner);
      tracef ("   new from_scanner_start: %" BUFFER_SIZE_T_FORMAT "\n",
              from_scanner_start);
      tracef ("   new from_scanner_end: %" BUFFER_SIZE_T_FORMAT "\n",
              from_scanner_end);
#endif
    }
  return 0;
}

/** @todo Complete ISO to UTF-8 hack.
 *
 * In all of these "messages" parsing functions, convert to UTF before
 * passing into rest of Manager.
 */

/**
 * @brief Parse the final field of a certificate in a certificate list.
 *
 * @param  messages  A pointer into the OTP input buffer.
 *
 * @return 0 success, -2 too few characters (need more input).
 */
static int
parse_scanner_certificate_public_key (char** messages)
{
  gchar *value;
  char *end, *match;
  assert (current_certificate != NULL);
  end = *messages + from_scanner_end - from_scanner_start;
  while (*messages < end && ((*messages)[0] == ' '))
    { (*messages)++; from_scanner_start++; }
  if ((match = memchr (*messages,
                       (int) '\n',
                       from_scanner_end - from_scanner_start)))
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
      set_scanner_state (SCANNER_CERTIFICATE_FINGERPRINT);
      from_scanner_start += match + 1 - *messages;
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
parse_scanner_done (char** messages)
{
  char *end = *messages + from_scanner_end - from_scanner_start;
  while (*messages < end && ((*messages)[0] == ' ' || (*messages)[0] == '\n'))
    { (*messages)++; from_scanner_start++; }
  if ((int) (end - *messages) < 6)
    /* Too few characters to be the end marker, return to select to
     * wait for more input. */
    return -2;
  if (strncasecmp ("SERVER", *messages, 6))
    {
      tracef ("   scanner fail: expected final \"SERVER\"\n");
      return -1;
    }
  set_scanner_state (SCANNER_TOP);
  from_scanner_start += 6;
  (*messages) += 6;
  return 0;
}

/**
 * @brief Check for a bad login response from the scanner.
 *
 * @param  messages  A pointer into the OTP input buffer.
 *
 * @return 0 if there is a bad login response, else 1.
 */
static int
parse_scanner_bad_login (char** messages)
{
  /*@dependent@*/ char *end, *match;
  end = *messages + from_scanner_end - from_scanner_start;
  while (*messages < end && ((*messages)[0] == ' '))
    { (*messages)++; from_scanner_start++; }
  if ((match = memchr (*messages,
                       (int) '\n',
                       from_scanner_end - from_scanner_start)))
    {
      /** @todo Are there 19 characters available? */
      if (strncasecmp ("Bad login attempt !", *messages, 19) == 0)
        {
          tracef ("match bad login\n");
          from_scanner_start += match + 1 - *messages;
          *messages = match + 1;
          set_scanner_init_state (SCANNER_INIT_TOP);
          return 0;
        }
    }
  return 1;
}

/**
 * @brief Parse the description in an ERROR message.
 *
 * @param  messages  A pointer into the OTP input buffer.
 *
 * @return 0 success, -1 fail, -2 too few characters (need more input).
 */
static int
parse_scanner_error (char** messages)
{
  char err;
  char *end = *messages + from_scanner_end - from_scanner_start;

  /* OTP has two error messages.  One ends with a newline, the other ends
   * with a "<|> SERVER" field (and a newline).  The GTK client is
   * hardcoded to handle these two error types. */

  while (*messages < end && ((*messages)[0] == ' ' || (*messages)[0] == '\n'))
    { (*messages)++; from_scanner_start++; }
  if ((int) (end - *messages) < 5)
    /* Too few characters to be the error number, return to select to
     * wait for more input. */
    return -2;
  if (sscanf (*messages, "E00%c ", &err) != 1)
    {
      tracef ("   scanner fail: failed to parse error message number\n");
      return -1;
    }
  from_scanner_start += 5;
  (*messages) += 5;
  switch (err)
    {
      case '1':
        {
          int length = strlen ("- Invalid port range <|>");

          /* Parse "- Invalid port range". */

          if ((int) (end - *messages) < length)
            /* Too few characters, return to select to wait for more input. */
            return -2;

          if (strncmp (*messages, "- Invalid port range <|>", length))
            {
              tracef ("   scanner fail: failed to parse error description\n");
              tracef ("   scanner fail: messages was: %.*s\n",
                      length,
                      *messages);
              return -1;
            }

          g_warning ("%s: Received \"invalid port range\" ERROR message\n",
                     __FUNCTION__);

          from_scanner_start += length;
          (*messages) += length;

          if (current_scanner_task)
            set_task_run_status (current_scanner_task,
                                 TASK_STATUS_INTERNAL_ERROR);

          set_scanner_state (SCANNER_DONE);
          switch (parse_scanner_done (messages))
            {
              case -1: return -1;
              case -2:
                /* Need more input. */
                if (sync_buffer ()) return -1;
                return -1;
            }
        }
        break;

      case '2':
        {
          char *match;
          if ((match = memchr (*messages,
                               (int) '\n',
                               from_scanner_end - from_scanner_start)))
            {
              from_scanner_start += match - *messages;
              *messages = match;

              /** @todo Parse the list of hosts and note that permissions
               *        prevented those scans. */

              set_scanner_state (SCANNER_TOP);
            }
          else
            /* Need more input for a newline. */
            return -2;
        }
        break;
    }

  return 0;
}

/** @todo Update doc. */
/**
 * @brief Parse the final SERVER field of an OTP message.
 *
 * @param  messages  A pointer into the OTP input buffer.
 *
 * @return 0 success, -2 too few characters (need more input).
 */
static int
parse_scanner_preference_value (char** messages)
{
  char *value, *end, *match;
  end = *messages + from_scanner_end - from_scanner_start;
  while (*messages < end && ((*messages)[0] == ' '))
    { (*messages)++; from_scanner_start++; }
  if ((match = memchr (*messages,
                       (int) '\n',
                       from_scanner_end - from_scanner_start)))
    {
      match[0] = '\0';
      value = g_strdup (*messages);
      if (current_scanner_preference)
        {
          if (scanner_init_state == SCANNER_INIT_DONE_CACHE_MODE)
            manage_nvt_preference_add (current_scanner_preference, value, 0);
          else if (scanner_init_state == SCANNER_INIT_DONE_CACHE_MODE_UPDATE)
            manage_nvt_preference_add (current_scanner_preference, value, 1);
        }
      set_scanner_state (SCANNER_PREFERENCE_NAME);
      from_scanner_start += match + 1 - *messages;
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
parse_scanner_plugin_list_tags (char** messages)
{
  char *value, *end, *match;
  assert (current_plugin != NULL);
  end = *messages + from_scanner_end - from_scanner_start;
  while (*messages < end && ((*messages)[0] == ' '))
    { (*messages)++; from_scanner_start++; }
  if ((match = memchr (*messages,
                       (int) '\n',
                       from_scanner_end - from_scanner_start)))
    {
      match[0] = '\0';
      value = g_strdup (*messages);
      if (value != NULL)
        {
          char* pos = value;
          while (*pos)
            {
              if (*pos == ';')
                *pos = '\n';
              pos++;
            }
        }
      if (current_plugin)
        {
          gchar *tags, *cvss_base, *risk_factor;
          parse_tags (value, &tags, &cvss_base, &risk_factor);
          nvti_set_tag (current_plugin, tags);
          nvti_set_cvss_base (current_plugin, cvss_base);
          g_free (tags);
          g_free (cvss_base);
          g_free (risk_factor);
          make_nvt_from_nvti (current_plugin,
                              scanner_init_state
                              == SCANNER_INIT_SENT_COMPLETE_LIST_UPDATE);
          current_plugin = NULL;
        }
      set_scanner_state (SCANNER_PLUGIN_LIST_OID);
      from_scanner_start += match + 1 - *messages;
      *messages = match + 1;
      g_free (value);
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
parse_scanner_rule (char** messages)
{
  char *end, *match;
  end = *messages + from_scanner_end - from_scanner_start;
  while (*messages < end && ((*messages)[0] == '\n'))
    { (*messages)++; from_scanner_start++; }
  while (*messages < end && ((*messages)[0] == ' '))
    { (*messages)++; from_scanner_start++; }
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
                       from_scanner_end - from_scanner_start)))
    {
      char* rule;
      match[0] = '\0';
      rule = g_strdup (*messages);
      add_scanner_rule (rule);
      from_scanner_start += match + 1 - *messages;
      *messages = match + 1;
      return 0;
    }
  return -2;
}

/**
 * @brief Parse the dependency of a scanner plugin.
 *
 * @param  messages  A pointer into the OTP input buffer.
 *
 * @return TRUE if a <|> follows in the buffer, otherwise FALSE.
 */
static gboolean
parse_scanner_plugin_dependency_dependency (/*@dependent@*/ char** messages)
{
  /* Look for the end of dependency marker: a newline that comes before
   * the next <|>. */
  char *separator, *end, *match, *input;
  buffer_size_t from_start, from_end;
  separator = NULL;
  /* Look for <|>. */
  input = *messages;
  from_start = from_scanner_start;
  from_end = from_scanner_end;
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
  end = *messages + from_scanner_end - from_scanner_start;
  while (*messages < end && ((*messages)[0] == ' '))
    { (*messages)++; from_scanner_start++; }
  if ((match = memchr (*messages,
                       (int) '\n',
                       from_scanner_end - from_scanner_start)))
    {
      /* Compare newline position to <|> position. */
      if ((separator == NULL) || (match < separator))
        {
          finish_current_scanner_plugin_dependency ();
          from_scanner_start += match + 1 - *messages;
          *messages = match + 1;
          set_scanner_state (SCANNER_PLUGIN_DEPENDENCY_NAME);
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
parse_scanner_server (/*@dependent@*/ char** messages)
{
  /*@dependent@*/ char *end, *match;
  end = *messages + from_scanner_end - from_scanner_start;
  while (*messages < end && ((*messages)[0] == ' '))
    { (*messages)++; from_scanner_start++; }
  if ((match = memchr (*messages,
                       (int) '\n',
                       from_scanner_end - from_scanner_start)))
    {
      /*@dependent@*/ char* newline;
      /*@dependent@*/ char* input;
      buffer_size_t from_start, from_end;
      match[0] = '\0';
      /** @todo Is there ever whitespace before the newline? */
      while (*messages < end && ((*messages)[0] == ' '))
        { (*messages)++; from_scanner_start++; }
      /** @todo Are there 20 characters available? */
      if (strncasecmp ("PLUGINS_DEPENDENCIES", *messages, 20) == 0)
        {
          from_scanner_start += match + 1 - *messages;
          *messages = match + 1;
          make_scanner_plugins_dependencies ();
          set_scanner_state (SCANNER_PLUGIN_DEPENDENCY_NAME);
          return 0;
        }
      /** @todo Are there 12 characters available? */
      if (strncasecmp ("CERTIFICATES", *messages, 12) == 0)
        {
          from_scanner_start += match + 1 - *messages;
          *messages = match + 1;
          /* current_certificates may be allocated already due to a
           * request for the list before the end of the previous
           * request.  In this case just let the responses mix.
           */
          /** @todo Investigate what the Scanner really does in this
           *        multiple request situation. */
          if (current_certificates == NULL)
            {
              current_certificates = certificates_create ();
              if (current_certificates == NULL) abort ();
            }
          set_scanner_state (SCANNER_CERTIFICATE_FINGERPRINT);
          return 0;
        }
      newline = match;
      newline[0] = '\n';
      /* Check for a <|>. */
      input = *messages;
      from_start = from_scanner_start;
      from_end = from_scanner_end;
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
 * @brief Process any lines available in \ref from_scanner.
 *
 * Update scanner information according to the input from the scanner.
 *
 * \if STATIC
 *
 * This includes updating the scanner state with \ref set_scanner_state
 * and \ref set_scanner_init_state, and updating scanner records with functions
 * like \ref manage_nvt_preference_add and \ref append_task_open_port.
 *
 * \endif
 *
 * This function simply records input from the scanner.  Output to the scanner
 * or client is almost always done via \ref process_omp_client_input in
 * reaction to client requests, the only exception being stop requests
 * initiated in other processes.
 *
 * @return 0 success, 1 received scanner BYE, 2 bad login, -1 error.
 */
int
process_otp_scanner_input ()
{
  /*@dependent@*/ char* match = NULL;
  /*@dependent@*/ char* messages = from_scanner + from_scanner_start;
  /*@dependent@*/ char* input;
  buffer_size_t from_start, from_end;
  //tracef ("   consider %.*s\n", from_scanner_end - from_scanner_start, messages);

  /* Before processing the input, check if another manager process has stopped
   * the current task.  If so, send the stop request to the scanner.  This is
   * the only place in this file that writes to the to_scanner buffer, and hence
   * the only place that requires that the writes to to_scanner in the OMP XML
   * handlers must be whole OTP commands. */

  if (manage_check_current_task () == -1)
    {
      /* Out of space in to_scanner.  Just treat it as an error for now. */
      return -1;
    }

  /* First, handle special scanner states where the input from the scanner
   * ends in something other than <|> (usually a newline). */

  switch (scanner_init_state)
    {
      case SCANNER_INIT_SENT_VERSION:
        /* Read over any whitespace left by the previous session. */
        while (from_scanner_start < from_scanner_end
               && (messages[0] == ' ' || messages[0] == '\n'))
          from_scanner_start++, messages++;
        if (from_scanner_end - from_scanner_start < 12)
          {
            /* Need more input. */
            if (sync_buffer ()) return -1;
            return 0;
          }
        if (strncasecmp ("< OTP/1.0 >\n", messages, 12)
            && strncasecmp ("< OTP/1.1 >\n", messages, 12))
          {
            tracef ("   scanner fail: expected \"< OTP/1.0 >\""
                    " or \"< OTP/1.1 >\", got \"%.12s\"\n\n",
                    messages);
            return -1;
          }
        from_scanner_start += 12;
        messages += 12;
        set_scanner_init_state (SCANNER_INIT_GOT_VERSION);
        /* Fall through to attempt next step. */
        /*@fallthrough@*/
      case SCANNER_INIT_GOT_VERSION:
        if (from_scanner_end - from_scanner_start < 7)
          {
            /* Need more input. */
            if (sync_buffer ()) return -1;
            return 0;
          }
        if (strncasecmp ("User : ", messages, 7))
          {
            tracef ("   scanner fail: expected \"User : \", got \"%7s\"\n",
                    messages);
            return -1;
          }
        from_scanner_start += 7;
        messages += 7;
        set_scanner_init_state (SCANNER_INIT_GOT_USER);
        if (sync_buffer ()) return -1;
        return 0;
      case SCANNER_INIT_GOT_USER:
        /* Input from scanner after "User : " and before user name sent. */
        return -1;
      case SCANNER_INIT_SENT_USER:
        if (from_scanner_end - from_scanner_start < 11)
          {
            /* Need more input. */
            if (sync_buffer ()) return -1;
            return 0;
          }
        if (strncasecmp ("Password : ", messages, 11))
          {
            tracef ("   scanner fail: expected \"Password : \", got \"%11s\"\n",
                    messages);
            return -1;
          }
        from_scanner_start += 11;
        messages += 11;
        set_scanner_init_state (SCANNER_INIT_GOT_PASSWORD);
        if (sync_buffer ()) return -1;
        return 0;
      case SCANNER_INIT_GOT_PASSWORD:
        /* Input from scanner after "Password : " and before password sent. */
        return -1;
      case SCANNER_INIT_GOT_MD5SUM:
        /* Somehow called to process the input from the scanner that followed
         * the initial md5sum, before the initial response to the md5sum has
         * been sent.  A programming error, most likely in setting up for
         * select in serve_omp. */
        assert (0);
        return -1;
      case SCANNER_INIT_GOT_PLUGINS:
        /* Somehow called to process the input from the scanner that followed
         * the initial plugin list, before the initial response to the list has
         * been sent.  A programming error, most likely in setting up for
         * select in serve_omp. */
        assert (0);
        return -1;
      case SCANNER_INIT_CONNECT_INTR:
      case SCANNER_INIT_CONNECTED:
        /* Input from scanner before version string sent. */
        return -1;
      case SCANNER_INIT_SENT_COMPLETE_LIST:
      case SCANNER_INIT_SENT_COMPLETE_LIST_UPDATE:
      case SCANNER_INIT_SENT_PASSWORD:
      case SCANNER_INIT_DONE:
      case SCANNER_INIT_DONE_CACHE_MODE:
      case SCANNER_INIT_DONE_CACHE_MODE_UPDATE:
      case SCANNER_INIT_TOP:
        if (scanner_state == SCANNER_TOP)
          switch (parse_scanner_bad_login (&messages))
            {
              case 0: return 2;    /* Found bad login response. */
              case 1: break;
            }
        else if (scanner_state == SCANNER_CERTIFICATE_PUBLIC_KEY)
          switch (parse_scanner_certificate_public_key (&messages))
            {
              case -2:
                /* Need more input. */
                if (sync_buffer ()) return -1;
                return 0;
            }
        else if (scanner_state == SCANNER_DONE)
          switch (parse_scanner_done (&messages))
            {
              case -1: return -1;
              case -2:
                /* Need more input. */
                if (sync_buffer ()) return -1;
                return 0;
            }
        else if (scanner_state == SCANNER_PLUGIN_LIST_TAGS)
          switch (parse_scanner_plugin_list_tags (&messages))
            {
              case -2:
                /* Need more input. */
                if (sync_buffer ()) return -1;
                return 0;
            }
        else if (scanner_state == SCANNER_PREFERENCE_VALUE)
          {
            switch (parse_scanner_preference_value (&messages))
              {
                case -2:
                  /* Need more input. */
                  if (sync_buffer ()) return -1;
                  return 0;
              }
            g_free (current_scanner_preference);
            current_scanner_preference = NULL;
          }
        else if (scanner_state == SCANNER_RULE)
          while (1)
            {
              switch (parse_scanner_rule (&messages))
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
        else if (scanner_state == SCANNER_SERVER)
          /* Look for any newline delimited scanner commands. */
          switch (parse_scanner_server (&messages))
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
        else if (scanner_state == SCANNER_PLUGIN_DEPENDENCY_DEPENDENCY
                 && parse_scanner_plugin_dependency_dependency (&messages))
          {
            /* Need more input for a <|>. */
            if (sync_buffer ()) return -1;
            return 0;
          }
        break;
    } /* switch (scanner_init_state) */

  /* Parse and handle any fields ending in <|>. */

  input = messages;
  from_start = from_scanner_start;
  from_end = from_scanner_end;
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
#if SCANNER_SENDS_UTF8
          tracef ("   scanner messages: %.*s...\n",
                  from_scanner_end - from_scanner_start < 200
                  ? from_scanner_end - from_scanner_start
                  : 200,
                  messages);
#endif
          message = messages;
          *match = '\0';
          from_scanner_start += match + 3 - messages;
          from_start = from_scanner_start;
          messages = match + 3;
          input = messages;
#ifdef SCANNER_SENDS_UTF8
          tracef ("   scanner message: %s\n", message);
#endif

          /* Strip leading and trailing whitespace. */
#ifdef SCANNER_SENDS_UTF8
          /* What to do when the scanner sends UTF-8. */
          field = openvas_strip_space (message, match);
#else
          /* ISO-8859-1 input to UTF-8 hack. */
          {
            gsize size_dummy;
            gchar *compressed;
            char* iso_field;

            iso_field = openvas_strip_space (message, match);
            compressed = g_strcompress (iso_field);
            blank_control_chars (compressed);
            field = g_convert (compressed, strlen (compressed),
                               "UTF-8", "ISO_8859-1",
                               NULL, &size_dummy, NULL);
            g_free (compressed);
            if (field == NULL) abort ();
          }
#endif

          tracef ("   scanner old state %i\n", scanner_state);
          tracef ("   scanner field: %s\n", field);
          switch (scanner_state)
            {
              case SCANNER_BYE:
                if (strcasecmp ("BYE", field))
                  goto return_error;
                /* It's up to the caller to set the init state, as the
                 * caller must flush the ACK. */
                set_scanner_state (SCANNER_DONE);
                switch (parse_scanner_done (&messages))
                  {
                    case  0:
                      if (sync_buffer ()) goto return_error;
                      scanner_active = 0;
                      if (acknowledge_bye ()) goto return_error;
                      goto return_bye;
                    case -1: goto return_error;
                    case -2:
                      /* Need more input. */
                      if (sync_buffer ()) goto return_error;
                      goto return_need_more;
                  }
                break;
              case SCANNER_CERTIFICATE_FINGERPRINT:
                {
                  /* Use match[1] instead of field[1] for UTF-8 hack. */
                  if (strlen (field) == 0 && match[1] == '|')
                    {
                      certificates_free (scanner.certificates);
                      scanner.certificates = current_certificates;
                      current_certificates = NULL;
                      set_scanner_state (SCANNER_DONE);
                      switch (parse_scanner_done (&messages))
                        {
                          case -1: goto return_error;
                          case -2:
                            /* Need more input. */
                            if (sync_buffer ()) goto return_error;
                            goto return_need_more;
                        }
                      break;
                    }
                  current_certificate = certificate_create ();
                  if (current_certificate == NULL) abort ();
                  if (certificate_set_fingerprint (current_certificate, field))
                    abort ();
                  set_scanner_state (SCANNER_CERTIFICATE_OWNER);
                  break;
                }
              case SCANNER_CERTIFICATE_LENGTH:
                {
                  /* Read over the length. */
                  /** @todo Consider using this to read the next field. */
                  set_scanner_state (SCANNER_CERTIFICATE_PUBLIC_KEY);
                  switch (parse_scanner_certificate_public_key (&messages))
                    {
                      case -2:
                        /* Need more input. */
                        if (sync_buffer ()) goto return_error;
                        goto return_need_more;
                    }
                  break;
                }
              case SCANNER_CERTIFICATE_OWNER:
                {
                  if (certificate_set_owner (current_certificate, field))
                    abort ();
                  set_scanner_state (SCANNER_CERTIFICATE_TRUST_LEVEL);
                  break;
                }
              case SCANNER_CERTIFICATE_TRUST_LEVEL:
                {
                  certificate_set_trusted (current_certificate,
                                           strcasecmp (field, "trusted") == 0);
                  set_scanner_state (SCANNER_CERTIFICATE_LENGTH);
                  break;
                }
              case SCANNER_ERRMSG_DESCRIPTION:
                {
                  if (current_message)
                    {
                      /** @todo Replace "\n" with newline in description. */
                      char* description = g_strdup (field);
                      set_message_description (current_message, description);
                    }
                  set_scanner_state (SCANNER_ERRMSG_OID);
                  break;
                }
              case SCANNER_ERRMSG_HOST:
                {
                  assert (current_message == NULL);
                  current_message = make_message (field);
                  set_scanner_state (SCANNER_ERRMSG_NUMBER);
                  break;
                }
              case SCANNER_ERRMSG_NUMBER:
                {
                  /** @todo Field could be "general". */
                  int number;
                  char *name;
                  char *protocol;

                  assert (current_message);

                  name = g_newa (char, strlen (field));
                  protocol = g_newa (char, strlen (field));

                  /* RATS: ignore, buffers are allocated to field length. */
                  if (sscanf (field, "%s (%i/%[^)])",
                              name, &number, protocol)
                      != 3)
                    {
                      number = atoi (field);
                      protocol[0] = '\0';
                    }
                  tracef ("   scanner got debug port, number: %i, protocol: %s\n",
                          number, protocol);

                  set_message_port_number (current_message, number);
                  set_message_port_protocol (current_message, protocol);
                  set_message_port_string (current_message, g_strdup (field));

                  set_scanner_state (SCANNER_ERRMSG_DESCRIPTION);
                  break;
                }
              case SCANNER_ERRMSG_OID:
                {
                  if (current_message != NULL
                      && current_scanner_task != (task_t) 0)
                    {
                      char* oid = g_strdup (field);
                      set_message_oid (current_message, oid);

                      append_error_message (current_scanner_task, current_message);
                      free_message (current_message);
                      current_message = NULL;
                    }
                  set_scanner_state (SCANNER_DONE);
                  switch (parse_scanner_done (&messages))
                    {
                      case -1: goto return_error;
                      case -2:
                        /* Need more input. */
                        if (sync_buffer ()) goto return_error;
                        goto return_need_more;
                    }
                  break;
                }
              case SCANNER_ERROR:
                assert (0);
                break;
              case SCANNER_HOLE_DESCRIPTION:
                {
                  if (current_message)
                    {
                      /** @todo Replace "\n" with newline in description. */
                      char* description = g_strdup (field);
                      set_message_description (current_message, description);
                    }
                  set_scanner_state (SCANNER_HOLE_OID);
                  break;
                }
              case SCANNER_HOLE_HOST:
                {
                  assert (current_message == NULL);
                  current_message = make_message (field);
                  set_scanner_state (SCANNER_HOLE_NUMBER);
                  break;
                }
              case SCANNER_HOLE_NUMBER:
                {
                  /** @todo Field could be "general". */
                  int number;
                  char *name;
                  char *protocol;

                  assert (current_message);

                  name = g_newa (char, strlen (field));
                  protocol = g_newa (char, strlen (field));

                  /* RATS: ignore, buffers are allocated to field length. */
                  if (sscanf (field, "%s (%i/%[^)])",
                              name, &number, protocol)
                      != 3)
                    {
                      number = atoi (field);
                      protocol[0] = '\0';
                    }
                  tracef ("   scanner got hole port, number: %i, protocol: %s\n",
                          number, protocol);

                  set_message_port_number (current_message, number);
                  set_message_port_protocol (current_message, protocol);
                  set_message_port_string (current_message, g_strdup (field));

                  set_scanner_state (SCANNER_HOLE_DESCRIPTION);
                  break;
                }
              case SCANNER_HOLE_OID:
                {
                  if (current_message != NULL
                      && current_scanner_task != (task_t) 0)
                    {
                      char* oid = g_strdup (field);
                      set_message_oid (current_message, oid);

                      append_hole_message (current_scanner_task, current_message);
                      free_message (current_message);
                      current_message = NULL;
                    }
                  set_scanner_state (SCANNER_DONE);
                  switch (parse_scanner_done (&messages))
                    {
                      case -1: goto return_error;
                      case -2:
                        /* Need more input. */
                        if (sync_buffer ()) goto return_error;
                        goto return_need_more;
                    }
                  break;
                }
              case SCANNER_INFO_DESCRIPTION:
                {
                  if (current_message)
                    {
                      /** @todo Replace "\n" with newline in description. */
                      char* description = g_strdup (field);
                      set_message_description (current_message, description);
                    }
                  set_scanner_state (SCANNER_INFO_OID);
                  break;
                }
              case SCANNER_INFO_HOST:
                {
                  assert (current_message == NULL);
                  current_message = make_message (field);
                  set_scanner_state (SCANNER_INFO_NUMBER);
                  break;
                }
              case SCANNER_INFO_NUMBER:
                {
                  /** @todo Field could be "general". */
                  int number;
                  char *name;
                  char *protocol;

                  assert (current_message);

                  name = g_newa (char, strlen (field));
                  protocol = g_newa (char, strlen (field));

                  /* RATS: ignore, buffers are allocated to field length. */
                  if (sscanf (field, "%s (%i/%[^)])",
                              name, &number, protocol)
                      != 3)
                    {
                      number = atoi (field);
                      protocol[0] = '\0';
                    }
                  tracef ("   scanner got info port, number: %i, protocol: %s\n",
                          number, protocol);

                  set_message_port_number (current_message, number);
                  set_message_port_protocol (current_message, protocol);
                  set_message_port_string (current_message, g_strdup (field));

                  set_scanner_state (SCANNER_INFO_DESCRIPTION);
                  break;
                }
              case SCANNER_INFO_OID:
                {
                  if (current_message != NULL
                      && current_scanner_task != (task_t) 0)
                    {
                      char* oid = g_strdup (field);
                      set_message_oid (current_message, oid);

                      append_info_message (current_scanner_task, current_message);
                      free_message (current_message);
                      current_message = NULL;
                    }
                  set_scanner_state (SCANNER_DONE);
                  switch (parse_scanner_done (&messages))
                    {
                      case -1: goto return_error;
                      case -2:
                        /* Need more input. */
                        if (sync_buffer ()) goto return_error;
                        goto return_need_more;
                    }
                  break;
                }
              case SCANNER_LOG_DESCRIPTION:
                {
                  if (current_message)
                    {
                      /** @todo Replace "\n" with newline in description. */
                      char* description = g_strdup (field);
                      set_message_description (current_message, description);
                    }
                  set_scanner_state (SCANNER_LOG_OID);
                  break;
                }
              case SCANNER_LOG_HOST:
                {
                  assert (current_message == NULL);
                  current_message = make_message (field);
                  set_scanner_state (SCANNER_LOG_NUMBER);
                  break;
                }
              case SCANNER_LOG_NUMBER:
                {
                  /** @todo Field could be "general". */
                  int number;
                  char *name;
                  char *protocol;

                  assert (current_message);

                  name = g_newa (char, strlen (field));
                  protocol = g_newa (char, strlen (field));

                  /* RATS: ignore, buffers are allocated to field length. */
                  if (sscanf (field, "%s (%i/%[^)])",
                              name, &number, protocol)
                      != 3)
                    {
                      number = atoi (field);
                      protocol[0] = '\0';
                    }
                  tracef ("   scanner got log port, number: %i, protocol: %s\n",
                          number, protocol);

                  set_message_port_number (current_message, number);
                  set_message_port_protocol (current_message, protocol);
                  set_message_port_string (current_message, g_strdup (field));

                  set_scanner_state (SCANNER_LOG_DESCRIPTION);
                  break;
                }
              case SCANNER_LOG_OID:
                {
                  if (current_message != NULL
                      && current_scanner_task != (task_t) 0)
                    {
                      char* oid = g_strdup (field);
                      set_message_oid (current_message, oid);

                      append_log_message (current_scanner_task, current_message);
                      free_message (current_message);
                      current_message = NULL;
                    }
                  set_scanner_state (SCANNER_DONE);
                  switch (parse_scanner_done (&messages))
                    {
                      case -1: goto return_error;
                      case -2:
                        /* Need more input. */
                        if (sync_buffer ()) goto return_error;
                        goto return_need_more;
                    }
                  break;
                }
              case SCANNER_NOTE_DESCRIPTION:
                {
                  if (current_message)
                    {
                      /** @todo Replace "\n" with newline in description. */
                      char* description = g_strdup (field);
                      set_message_description (current_message, description);
                    }
                  set_scanner_state (SCANNER_NOTE_OID);
                  break;
                }
              case SCANNER_NOTE_HOST:
                {
                  assert (current_message == NULL);
                  current_message = make_message (field);
                  set_scanner_state (SCANNER_NOTE_NUMBER);
                  break;
                }
              case SCANNER_NOTE_NUMBER:
                {
                  /** @todo Field could be "general". */
                  int number;
                  char *name;
                  char *protocol;

                  assert (current_message);

                  name = g_newa (char, strlen (field));
                  protocol = g_newa (char, strlen (field));

                  /* RATS: ignore, buffers are allocated to field length. */
                  if (sscanf (field, "%s (%i/%[^)])",
                              name, &number, protocol)
                      != 3)
                    {
                      number = atoi (field);
                      protocol[0] = '\0';
                    }
                  tracef ("   scanner got note port, number: %i, protocol: %s\n",
                          number, protocol);

                  set_message_port_number (current_message, number);
                  set_message_port_protocol (current_message, protocol);
                  set_message_port_string (current_message, g_strdup (field));

                  set_scanner_state (SCANNER_NOTE_DESCRIPTION);
                  break;
                }
              case SCANNER_NOTE_OID:
                {
                  if (current_message != NULL
                      && current_scanner_task != (task_t) 0)
                    {
                      char* oid = g_strdup (field);
                      set_message_oid (current_message, oid);

                      append_note_message (current_scanner_task, current_message);
                      free_message (current_message);
                      current_message = NULL;
                    }
                  set_scanner_state (SCANNER_DONE);
                  switch (parse_scanner_done (&messages))
                    {
                      case -1: goto return_error;
                      case -2:
                        /* Need more input. */
                        if (sync_buffer ()) goto return_error;
                        goto return_need_more;
                    }
                  break;
                }
              case SCANNER_PLUGIN_DEPENDENCY_NAME:
                {
                  /* Use match[1] instead of field[1] for UTF-8 hack. */
                  if (strlen (field) == 0 && match[1] == '|')
                    {
                      set_scanner_state (SCANNER_DONE);
                      switch (parse_scanner_done (&messages))
                        {
                          case -1: goto return_error;
                          case -2:
                            /* Need more input. */
                            if (sync_buffer ()) goto return_error;
                            goto return_need_more;
                        }
                      break;
                    }
                  {
                    char* name = g_strdup (field);
                    make_current_scanner_plugin_dependency (name);
                    set_scanner_state (SCANNER_PLUGIN_DEPENDENCY_DEPENDENCY);
                    if (parse_scanner_plugin_dependency_dependency (&messages))
                      {
                        /* Need more input for a <|>. */
                        if (sync_buffer ()) goto return_error;
                        goto return_need_more;
                      }
                  }
                  break;
                }
              case SCANNER_PLUGIN_DEPENDENCY_DEPENDENCY:
                {
                  char* dep = g_strdup (field);
                  append_to_current_scanner_plugin_dependency (dep);
                  if (parse_scanner_plugin_dependency_dependency (&messages))
                    {
                      /* Need more input for a <|>. */
                      if (sync_buffer ()) goto return_error;
                      goto return_need_more;
                    }
                  break;
                }
              case SCANNER_PLUGIN_LIST_OID:
                {
                  /* Use match[1] instead of field[1] for UTF-8 hack. */
                  if (strlen (field) == 0 && match[1] == '|')
                    {
                      set_scanner_state (SCANNER_DONE);
                      switch (parse_scanner_done (&messages))
                        {
                          case  0:
                            if (scanner_init_state
                                == SCANNER_INIT_SENT_COMPLETE_LIST
                                || scanner_init_state
                                   == SCANNER_INIT_SENT_COMPLETE_LIST_UPDATE)
                              {
                                set_scanner_init_state (SCANNER_INIT_GOT_PLUGINS);
                                set_nvts_md5sum (scanner.plugins_md5);
                              }
                            break;
                          case -1: goto return_error;
                          case -2:
                            /* Need more input. */
                            if (sync_buffer ()) goto return_error;
                            goto return_need_more;
                        }
                      break;
                    }
                  assert (current_plugin == NULL);
                  current_plugin = nvti_new ();
                  if (current_plugin == NULL) abort ();
                  nvti_set_oid (current_plugin, field);
                  set_scanner_state (SCANNER_PLUGIN_LIST_NAME);
                  break;
                }
              case SCANNER_PLUGIN_LIST_NAME:
                {
                  nvti_set_name (current_plugin, field);
                  set_scanner_state (SCANNER_PLUGIN_LIST_CATEGORY);
                  break;
                }
              case SCANNER_PLUGIN_LIST_CATEGORY:
                {
                  nvti_set_category (current_plugin, category_number (field));
                  set_scanner_state (SCANNER_PLUGIN_LIST_COPYRIGHT);
                  break;
                }
              case SCANNER_PLUGIN_LIST_COPYRIGHT:
                {
                  nvti_set_copyright (current_plugin, field);
                  set_scanner_state (SCANNER_PLUGIN_LIST_DESCRIPTION);
                  break;
                }
              case SCANNER_PLUGIN_LIST_DESCRIPTION:
                {
                  /* Un"escape" description (replace ';' by '\n'). */
                  if (field != NULL)
                    {
                      char* pos = field;
                      while ((pos = strchr (pos, ';')))
                        pos[0] = '\n';
                    }

                  nvti_set_description (current_plugin, field);
                  set_scanner_state (SCANNER_PLUGIN_LIST_SUMMARY);
                  break;
                }
              case SCANNER_PLUGIN_LIST_SUMMARY:
                {
                  nvti_set_summary (current_plugin, field);
                  set_scanner_state (SCANNER_PLUGIN_LIST_FAMILY);
                  break;
                }
              case SCANNER_PLUGIN_LIST_FAMILY:
                {
                  nvti_set_family (current_plugin, field);
                  set_scanner_state (SCANNER_PLUGIN_LIST_PLUGIN_VERSION);
                  break;
                }
              case SCANNER_PLUGIN_LIST_PLUGIN_VERSION:
                {
                  nvti_set_version (current_plugin, field);
                  set_scanner_state (SCANNER_PLUGIN_LIST_CVE_ID);
                  break;
                }
              case SCANNER_PLUGIN_LIST_CVE_ID:
                {
                  nvti_set_cve (current_plugin, field);
                  set_scanner_state (SCANNER_PLUGIN_LIST_BUGTRAQ_ID);
                  break;
                }
              case SCANNER_PLUGIN_LIST_BUGTRAQ_ID:
                {
                  nvti_set_bid (current_plugin, field);
                  set_scanner_state (SCANNER_PLUGIN_LIST_XREFS);
                  break;
                }
              case SCANNER_PLUGIN_LIST_XREFS:
                {
                  nvti_set_xref (current_plugin, field);
                  set_scanner_state (SCANNER_PLUGIN_LIST_FPRS);
                  break;
                }
              case SCANNER_PLUGIN_LIST_FPRS:
                {
                  nvti_set_sign_key_ids (current_plugin, field);
                  set_scanner_state (SCANNER_PLUGIN_LIST_TAGS);
                  switch (parse_scanner_plugin_list_tags (&messages))
                    {
                      case -2:
                        /* Need more input. */
                        if (sync_buffer ()) goto return_error;
                        goto return_need_more;
                    }
                  break;
                }
              case SCANNER_PLUGINS_MD5:
                {
                  char* md5 = g_strdup (field);
                  tracef ("   scanner got plugins_md5: %s\n", md5);
                  if (scanner.plugins_md5) g_free (scanner.plugins_md5);
                  scanner.plugins_md5 = md5;
                  set_scanner_state (SCANNER_DONE);
                  switch (parse_scanner_done (&messages))
                    {
                      case  0:
                        if (scanner_init_state == SCANNER_INIT_SENT_PASSWORD)
                          set_scanner_init_state (SCANNER_INIT_GOT_MD5SUM);
                        else if (acknowledge_md5sum_info ())
                          goto return_error;
                        break;
                      case -1: goto return_error;
                      case -2:
                        /* Need more input. */
                        if (sync_buffer ()) goto return_error;
                        goto return_need_more;
                    }
                  break;
                }
              case SCANNER_PORT_HOST:
                {
                  current_host = g_strdup (field);
                  set_scanner_state (SCANNER_PORT_NUMBER);
                  break;
                }
              case SCANNER_PORT_NUMBER:
                {
                  if (current_scanner_task)
                    append_task_open_port (current_scanner_task,
                                           current_host,
                                           field);
                  g_free (current_host);
                  current_host = NULL;
                  set_scanner_state (SCANNER_DONE);
                  switch (parse_scanner_done (&messages))
                    {
                      case -1: goto return_error;
                      case -2:
                        /* Need more input. */
                        if (sync_buffer ()) goto return_error;
                        goto return_need_more;
                    }
                  break;
                }
              case SCANNER_PREFERENCE_NAME:
                {
                  /* Use match[1] instead of field[1] for UTF-8 hack. */
                  if (strlen (field) == 0 && match[1] == '|')
                    {
                      set_scanner_state (SCANNER_DONE);
                      switch (parse_scanner_done (&messages))
                        {
                          case -1: goto return_error;
                          case -2:
                            /* Need more input. */
                            if (sync_buffer ()) goto return_error;
                            goto return_need_more;
                        }
                      if (scanner_init_state == SCANNER_INIT_DONE_CACHE_MODE
                          || scanner_init_state
                             == SCANNER_INIT_DONE_CACHE_MODE_UPDATE)
                        {
                          manage_complete_nvt_cache_update
                           (scanner_init_state == SCANNER_INIT_DONE_CACHE_MODE
                            ? -2 : -1);
                          set_scanner_init_state (SCANNER_INIT_DONE);
                          manage_nvt_preferences_enable ();
                          /* Return 1, as though the scanner sent BYE. */
                          /** @todo Exit more formally with Scanner? */
                          scanner_active = 0;
                          goto return_bye;
                        }
                      break;
                    }

                  {
                    int value_start = -1, value_end = -1, count;
                    char name[21];
                    /* LDAPsearch[entry]:Timeout value */
                    count = sscanf (field, "%20[^[][%*[^]]]:%n%*[ -~]%n",
                                    name, &value_start, &value_end);
                    if (count == 1 && value_start > 0 && value_end > 0
                        && ((strcmp (name, "SSH Authorization") == 0)
                            || (strcmp (name, "SMB Authorization") == 0)))
                      current_scanner_preference = NULL;
                    else
                      current_scanner_preference = g_strdup (field);
                    set_scanner_state (SCANNER_PREFERENCE_VALUE);
                    switch (parse_scanner_preference_value (&messages))
                      {
                        case -2:
                          /* Need more input. */
                          if (sync_buffer ()) goto return_error;
                          goto return_need_more;
                      }
                    g_free (current_scanner_preference);
                    current_scanner_preference = NULL;
                  }
                  break;
                }
              case SCANNER_RULE:
                /* A <|> following a rule. */
                set_scanner_state (SCANNER_DONE);
                switch (parse_scanner_done (&messages))
                  {
                    case -1: goto return_error;
                    case -2:
                      /* Need more input. */
                      if (sync_buffer ()) goto return_error;
                      goto return_need_more;
                  }
                break;
              case SCANNER_SERVER:
                if (strcasecmp ("BYE", field) == 0)
                  set_scanner_state (SCANNER_BYE);
                else if (strcasecmp ("ERRMSG", field) == 0)
                  set_scanner_state (SCANNER_ERRMSG_HOST);
                else if (strcasecmp ("ERROR", field) == 0)
                  {
                    set_scanner_state (SCANNER_ERROR);
                    switch (parse_scanner_error (&messages))
                      {
                        case 0:
                          /* parse_scanner_error can read across a <|>,
                           * because one ERROR case is newline terminated
                           * while the other is "<|> SERVER" terminated,
                           * so adjust input. */
                          input = messages;
                          break;
                        case -1: goto return_error;
                        case -2:
                          /* Need more input. */
                          if (sync_buffer ()) goto return_error;
                          goto return_need_more;
                      }
                  }
                else if (strcasecmp ("FILE_ACCEPTED", field) == 0)
                  {
                    set_scanner_state (SCANNER_DONE);
                    switch (parse_scanner_done (&messages))
                      {
                        case -1: goto return_error;
                        case -2:
                          /* Need more input. */
                          if (sync_buffer ()) goto return_error;
                          goto return_need_more;
                      }
                  }
                else if (strcasecmp ("HOLE", field) == 0)
                  set_scanner_state (SCANNER_HOLE_HOST);
                else if (strcasecmp ("INFO", field) == 0)
                  set_scanner_state (SCANNER_INFO_HOST);
                else if (strcasecmp ("LOG", field) == 0)
                  set_scanner_state (SCANNER_LOG_HOST);
                else if (strcasecmp ("NOTE", field) == 0)
                  set_scanner_state (SCANNER_NOTE_HOST);
                else if (strcasecmp ("PLUGINS_MD5", field) == 0)
                  set_scanner_state (SCANNER_PLUGINS_MD5);
                else if (strcasecmp ("PLUGIN_LIST", field) == 0)
                  {
                    set_scanner_state (SCANNER_PLUGIN_LIST_OID);
                  }
                else if (strcasecmp ("PORT", field) == 0)
                  set_scanner_state (SCANNER_PORT_HOST);
                else if (strcasecmp ("PREFERENCES", field) == 0)
                  {
                    assert (current_scanner_preference == NULL);
                    set_scanner_state (SCANNER_PREFERENCE_NAME);
                  }
                else if (strcasecmp ("RULES", field) == 0)
                  {
                    maybe_free_scanner_rules ();
                    make_scanner_rules ();
                    set_scanner_state (SCANNER_RULE);
                    while (1)
                      {
                        switch (parse_scanner_rule (&messages))
                          {
                            case  0: continue;     /* Read a rule. */
                            case -1: break;        /* At final <|>. */
                            case -2:
                              /* Need more input. */
                              if (sync_buffer ()) goto return_error;
                              goto return_need_more;
                          }
                        break;
                      }
                    break;
                  }
                else if (strcasecmp ("TIME", field) == 0)
                  {
                    set_scanner_state (SCANNER_TIME);
                  }
                else if (strcasecmp ("STATUS", field) == 0)
                  {
                    set_scanner_state (SCANNER_STATUS_HOST);
                  }
                else
                  {
                    tracef ("New scanner command to implement: %s\n",
                            field);
                    goto return_error;
                  }
                break;
              case SCANNER_STATUS_ATTACK_STATE:
                {
                  if (current_report && current_host)
                    {
                      if (strcmp (field, "portscan"))
                        {
                          if (current_scanner_task)
                            {
                              if (strcmp (field, "pause") == 0)
                                set_task_run_status (current_scanner_task,
                                                     TASK_STATUS_PAUSED);
                              else if (strcmp (field, "resume") == 0)
                                set_task_run_status (current_scanner_task,
                                                     TASK_STATUS_RUNNING);
                            }
                          else
                            {
                              char* state = g_strdup (field);
                              set_scan_attack_state (current_report,
                                                     current_host,
                                                     state);
                            }
                          set_scanner_state (SCANNER_STATUS_PROGRESS);
                        }
                      else
                        set_scanner_state (SCANNER_STATUS_PORTS);
                    }
                  else
                    set_scanner_state (SCANNER_STATUS_PORTS);
                  break;
                }
              case SCANNER_STATUS_HOST:
                {
                  assert (current_host == NULL);
                  current_host = g_strdup (field);
                  set_scanner_state (SCANNER_STATUS_ATTACK_STATE);
                  break;
                }
              case SCANNER_STATUS_PORTS:
                {
                  /* For now, just read over the ports. */
                  if (current_host)
                    {
                      g_free (current_host);
                      current_host = NULL;
                    }
                  set_scanner_state (SCANNER_DONE);
                  switch (parse_scanner_done (&messages))
                    {
                      case -1: goto return_error;
                      case -2:
                        /* Need more input. */
                        if (sync_buffer ()) goto return_error;
                        goto return_need_more;
                    }
                  break;
                }
              case SCANNER_STATUS_PROGRESS:
                {
                  /* Store the progress in the ports slots in the db. */
                  assert (current_report);
                  if (current_report && current_host)
                    {
                      unsigned int current, max;
                      tracef ("   scanner got ports: %s\n", field);
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
                  set_scanner_state (SCANNER_DONE);
                  switch (parse_scanner_done (&messages))
                    {
                      case -1: goto return_error;
                      case -2:
                        /* Need more input. */
                        if (sync_buffer ()) goto return_error;
                        goto return_need_more;
                    }
                  break;
                }
              case SCANNER_TIME:
                {
                  if (strcasecmp ("HOST_START", field) == 0)
                    set_scanner_state (SCANNER_TIME_HOST_START_HOST);
                  else if (strcasecmp ("HOST_END", field) == 0)
                    set_scanner_state (SCANNER_TIME_HOST_END_HOST);
                  else if (strcasecmp ("SCAN_START", field) == 0)
                    set_scanner_state (SCANNER_TIME_SCAN_START);
                  else if (strcasecmp ("SCAN_END", field) == 0)
                    set_scanner_state (SCANNER_TIME_SCAN_END);
                  else
                    /** @todo Consider reading all fields up to <|> SERVER? */
                    abort ();
                  break;
                }
              case SCANNER_TIME_HOST_START_HOST:
                {
                  assert (current_host == NULL);
                  current_host = g_strdup (field);
                  set_scanner_state (SCANNER_TIME_HOST_START_TIME);
                  break;
                }
              case SCANNER_TIME_HOST_START_TIME:
                {
                  if (current_scanner_task)
                    {
                      assert (current_host);
                      set_scan_host_start_time_otp (current_report,
                                                    current_host,
                                                    field);
                      g_free (current_host);
                      current_host = NULL;
                    }
                  set_scanner_state (SCANNER_DONE);
                  switch (parse_scanner_done (&messages))
                    {
                      case -1: goto return_error;
                      case -2:
                        /* Need more input. */
                        if (sync_buffer ()) goto return_error;
                        goto return_need_more;
                    }
                  break;
                }
              case SCANNER_TIME_HOST_END_HOST:
                {
                  assert (current_host == NULL);
                  current_host = g_strdup (field);
                  set_scanner_state (SCANNER_TIME_HOST_END_TIME);
                  break;
                }
              case SCANNER_TIME_HOST_END_TIME:
                {
                  if (current_scanner_task)
                    {
                      assert (current_host);
                      set_scan_host_end_time_otp (current_report,
                                                  current_host,
                                                  field);
                      g_free (current_host);
                      current_host = NULL;
                    }
                  set_scanner_state (SCANNER_DONE);
                  switch (parse_scanner_done (&messages))
                    {
                      case -1: goto return_error;
                      case -2:
                        /* Need more input. */
                        if (sync_buffer ()) goto return_error;
                        goto return_need_more;
                    }
                  break;
                }
              case SCANNER_TIME_SCAN_START:
                {
                  if (current_scanner_task)
                    {
                      if (task_run_status (current_scanner_task)
                          == TASK_STATUS_REQUESTED)
                        {
                          set_task_run_status (current_scanner_task,
                                               TASK_STATUS_RUNNING);
                          set_task_start_time_otp (current_scanner_task,
                                                   g_strdup (field));
                          set_scan_start_time_otp (current_report, field);
                        }
                    }
                  set_scanner_state (SCANNER_DONE);
                  switch (parse_scanner_done (&messages))
                    {
                      case -1: goto return_error;
                      case -2:
                        /* Need more input. */
                        if (sync_buffer ()) goto return_error;
                        goto return_need_more;
                    }
                  break;
                }
              case SCANNER_TIME_SCAN_END:
                {
                  if (current_scanner_task)
                    {
                      switch (task_run_status (current_scanner_task))
                        {
                          case TASK_STATUS_INTERNAL_ERROR:
                            break;
                          case TASK_STATUS_PAUSE_REQUESTED:
                          case TASK_STATUS_PAUSE_WAITING:
                          case TASK_STATUS_PAUSED:
                          case TASK_STATUS_RESUME_REQUESTED:
                          case TASK_STATUS_RESUME_WAITING:
                          case TASK_STATUS_STOP_REQUESTED:
                          case TASK_STATUS_STOP_WAITING:
                            set_task_run_status (current_scanner_task,
                                                 TASK_STATUS_STOPPED);
                            break;
                          case TASK_STATUS_DELETE_REQUESTED:
                          case TASK_STATUS_DELETE_WAITING:
                            delete_task_lock (current_scanner_task, 0);
                            set_task_run_status (current_scanner_task,
                                                 TASK_STATUS_STOPPED);
                            current_report = (report_t) 0;
                            break;
                          case TASK_STATUS_DELETE_ULTIMATE_REQUESTED:
                          case TASK_STATUS_DELETE_ULTIMATE_WAITING:
                            delete_task_lock (current_scanner_task, 1);
                            current_report = (report_t) 0;
                            break;
                          default:
                            set_task_run_status (current_scanner_task,
                                                 TASK_STATUS_DONE);
                            set_task_end_time (current_scanner_task,
                                               g_strdup (field));
                        }
                      if (current_report)
                        {
                          set_scan_end_time_otp (current_report, field);
                          current_report = (report_t) 0;
                        }
                      manage_transaction_stop (TRUE);
                      current_scanner_task = (task_t) 0;
                    }
                  set_scanner_state (SCANNER_DONE);
                  switch (parse_scanner_done (&messages))
                    {
                      case -1: goto return_error;
                      case -2:
                        /* Need more input. */
                        if (sync_buffer ()) goto return_error;
                        goto return_need_more;
                    }
                  break;
                }
              case SCANNER_TOP:
              default:
                tracef ("   switch t\n");
                tracef ("   cmp %i\n", strcasecmp ("SERVER", field));
                if (strcasecmp ("SERVER", field))
                  goto return_error;
                set_scanner_state (SCANNER_SERVER);
                /* Look for any newline delimited scanner commands. */
                switch (parse_scanner_server (&messages))
                  {
                    case  0: break;        /* Found newline delimited command. */
                    case -1: goto return_error;    /* Error. */
                    case -2:
                      /* Need more input. */
                      if (sync_buffer ()) goto return_error;
                      goto return_need_more;
                    case -3: break;        /* Next <|> is before next \n. */
                    case -4: break;        /* Failed to find \n, try for <|>. */
                  }
                break;
            }

          tracef ("   scanner new state: %i\n", scanner_state);

          /* The jumps are for the UTF-8 hack. */

          g_free (field);
          continue;

         return_error:
          g_free (field);
          return -1;

         return_need_more:
          g_free (field);
          return 0;

         return_bye:
          g_free (field);
          return 1;
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
