/* OpenVAS Manager
 * $Id$
 * Description: Module for OpenVAS Manager: the OMP library.
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
 * @file  omp.c
 * @brief The OpenVAS Manager OMP library.
 *
 * This file defines an OpenVAS Management Protocol (OMP) library, for
 * implementing OpenVAS managers such as the OpenVAS Manager daemon.
 *
 * The library provides \ref process_omp_client_input.
 * This function parses a given string of OMP XML and tracks and manipulates
 * tasks in reaction to the OMP commands in the string.
 */

#include "omp.h"
#include "manage.h"
#include "otp.h"      // FIX for access to server_t server
#include "string.h"
#include "tracef.h"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include <openvas/nvti.h>

#ifdef S_SPLINT_S
#include "splint.h"
#endif

/**
 * @brief Installation prefix.
 */
#ifndef PREFIX
#define PREFIX ""
#endif


/* Help message. */

static char* help_text = "\n"
"    ABORT_TASK             Abort a running task.\n"
"    AUTHENTICATE           Authenticate with the manager.\n"
"    DELETE_REPORT          Delete an existing report.\n"
"    DELETE_TASK            Delete an existing task.\n"
"    GET_DEPENDENCIES       Get dependencies for all available NVTs.\n"
"    GET_NVT_ALL            Get IDs and names of all available NVTs.\n"
"    GET_NVT_FEED_CHECKSUM  Get checksum for entire NVT collection.\n"
"    GET_NVT_DETAILS        Get all details for all available NVTs.\n"
"    GET_PREFERENCES        Get preferences for all available NVTs.\n"
"    GET_REPORT             Get a report identified by its unique ID.\n"
"    GET_RULES              Get the rules for the authenticated user.\n"
"    HELP                   Get this help text.\n"
"    MODIFY_REPORT          Modify an existing report.\n"
"    MODIFY_TASK            Update an existing task.\n"
"    CREATE_TASK            Create a new task.\n"
"    GET_VERSION            Get the OpenVAS Manager Protocol version.\n"
"    START_TASK             Manually start an existing task.\n"
"    STATUS                 Get task status information.\n";


/* Status codes. */

/* HTTP status codes used:
 *
 *     200 OK
 *     201 Created
 *     202 Accepted
 *     400 Bad request
 *     401 Must auth
 *     404 Missing
 */

#define STATUS_ERROR_SYNTAX       "400"
#define STATUS_ERROR_MUST_AUTH    "401"
#define STATUS_ERROR_MISSING      "404"
#define STATUS_ERROR_AUTH_FAILED  "400"

#define STATUS_OK                 "200"
#define STATUS_OK_CREATED         "201"
#define STATUS_OK_REQUESTED       "202"

#define STATUS_INTERNAL_ERROR     "500"
#define STATUS_SERVICE_DOWN       "503"


/* Global variables. */

/**
 * @brief Buffer of output to the client.
 */
char to_client[TO_CLIENT_BUFFER_SIZE];

/**
 * @brief The start of the data in the \ref to_client buffer.
 */
buffer_size_t to_client_start = 0;
/**
 * @brief The end of the data in the \ref to_client buffer.
 */
buffer_size_t to_client_end = 0;

/**
 * @brief Current client task during commands like CREATE_TASK and MODIFY_TASK.
 */
/*@null@*/ /*@dependent@*/
static task_t current_client_task = (task_t) NULL;

/**
 * @brief Current report or task UUID, during a few operations.
 */
static /*@null@*/ /*@only@*/ char*
current_uuid = NULL;

/**
 * @brief Parameter name during OMP MODIFY_TASK.
 */
static /*@null@*/ /*@only@*/ char*
modify_task_parameter = NULL;

/**
 * @brief Parameter value during OMP MODIFY_TASK.
 */
static /*@null@*/ /*@only@*/ char*
modify_task_value = NULL;

/**
 * @brief Client input parsing context.
 */
static /*@null@*/ /*@only@*/ GMarkupParseContext*
xml_context = NULL;

/**
 * @brief Client input parser.
 */
static GMarkupParser xml_parser;


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
  CLIENT_DELETE_REPORT,
  CLIENT_DELETE_REPORT_ID,
  CLIENT_DELETE_TASK,
  CLIENT_DELETE_TASK_TASK_ID,
  CLIENT_GET_DEPENDENCIES,
  CLIENT_GET_NVT_ALL,
  CLIENT_GET_NVT_FEED_CHECKSUM,
  CLIENT_GET_NVT_DETAILS,
  CLIENT_GET_NVT_DETAILS_OID,
  CLIENT_GET_PREFERENCES,
  CLIENT_GET_REPORT,
  CLIENT_GET_REPORT_ID,
  CLIENT_GET_RULES,
  CLIENT_HELP,
  CLIENT_MODIFY_REPORT,
  CLIENT_MODIFY_REPORT_REPORT_ID,
  CLIENT_MODIFY_REPORT_PARAMETER,
  CLIENT_MODIFY_REPORT_VALUE,
  CLIENT_MODIFY_TASK,
  CLIENT_MODIFY_TASK_TASK_ID,
  CLIENT_MODIFY_TASK_PARAMETER,
  CLIENT_MODIFY_TASK_VALUE,
  CLIENT_CREATE_TASK,
  CLIENT_CREATE_TASK_COMMENT,
  CLIENT_CREATE_TASK_IDENTIFIER,
  CLIENT_CREATE_TASK_TASK_FILE,
  CLIENT_START_TASK,
  CLIENT_START_TASK_TASK_ID,
  CLIENT_STATUS,
  CLIENT_STATUS_TASK_ID,
  CLIENT_VERSION
} client_state_t;

/**
 * @brief The state of the client.
 */
static client_state_t client_state = CLIENT_TOP;

/**
 * @brief Set the client state.
 */
static void
set_client_state (client_state_t state)
{
  client_state = state;
  tracef ("   client state set: %i\n", client_state);
}


/* Communication. */

/**
 * @brief Send a response message to the client.
 *
 * Queue a message in \ref to_client.
 *
 * @param[in]  msg  The message, a string.
 *
 * @return TRUE if out of space in to_client, else FALSE.
 */
static gboolean
send_to_client (char* msg)
{
  assert (to_client_end <= TO_CLIENT_BUFFER_SIZE);
  if (((buffer_size_t) TO_CLIENT_BUFFER_SIZE) - to_client_end
      < strlen (msg))
    return TRUE;
  memmove (to_client + to_client_end, msg, strlen (msg));
  tracef ("-> client: %s\n", msg);
  to_client_end += strlen (msg);
  return FALSE;
}

/**
 * @brief Set an out of space parse error on a GError.
 *
 * @param [out]  error  The error.
 */
static void
error_send_to_client (GError** error)
{
  tracef ("   send_to_client out of space in to_client\n");
  g_set_error (error, G_MARKUP_ERROR, G_MARKUP_ERROR_PARSE,
               "Manager out of space for reply to client.");
}


/* XML parser handlers. */

/**
 * @brief Handle the start of an OMP XML element.
 *
 * React to the start of an XML element according to the current value
 * of \ref client_state, usually adjusting \ref client_state to indicate
 * the change (with \ref set_client_state).  Call \ref send_to_client to
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
static void
omp_xml_handle_start_element (/*@unused@*/ GMarkupParseContext* context,
                              const gchar *element_name,
                              /*@unused@*/ const gchar **attribute_names,
                              /*@unused@*/ const gchar **attribute_values,
                              /*@unused@*/ gpointer user_data,
                              GError **error)
{
  tracef ("   XML  start: %s (%i)\n", element_name, client_state);

  switch (client_state)
    {
      case CLIENT_TOP:
        if (strncasecmp ("AUTHENTICATE", element_name, 12) == 0)
          {
// FIX
#if 0
            assert (tasks == NULL);
            assert (current_credentials.username == NULL);
            assert (current_credentials.password == NULL);
#endif
            set_client_state (CLIENT_AUTHENTICATE);
          }
        else
          {
            // TODO: If one of other commands, STATUS_ERROR_AUTHENTICATE
            if (send_to_client ("<omp_response>"
                                "<status>" STATUS_ERROR_SYNTAX "</status>"
                                "</omp_response>"))
              {
                error_send_to_client (error);
                return;
              }
            g_set_error (error, G_MARKUP_ERROR, G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Must authenticate first.");
          }
        break;

      case CLIENT_AUTHENTIC:
        if (strncasecmp ("AUTHENTICATE", element_name, 12) == 0)
          {
            // FIX Could check if reauthenticating current credentials, to
            // save the loading of the tasks.
            if (save_tasks ()) abort ();
            free_tasks ();
            free_credentials (&current_credentials);
            set_client_state (CLIENT_AUTHENTICATE);
          }
        else if (strncasecmp ("ABORT_TASK", element_name, 10) == 0)
          {
            append_text (&current_uuid, "", 0);
            set_client_state (CLIENT_ABORT_TASK);
          }
        else if (strncasecmp ("DELETE_REPORT", element_name, 13) == 0)
          {
            append_text (&current_uuid, "", 0);
            set_client_state (CLIENT_DELETE_REPORT);
          }
        else if (strncasecmp ("DELETE_TASK", element_name, 11) == 0)
          {
            append_text (&current_uuid, "", 0);
            set_client_state (CLIENT_DELETE_TASK);
          }
        else if (strncasecmp ("GET_DEPENDENCIES", element_name, 16) == 0)
          set_client_state (CLIENT_GET_DEPENDENCIES);
        else if (strncasecmp ("GET_NVT_ALL", element_name, 11) == 0)
          set_client_state (CLIENT_GET_NVT_ALL);
        else if (strncasecmp ("GET_NVT_FEED_CHECKSUM", element_name, 21) == 0)
          set_client_state (CLIENT_GET_NVT_FEED_CHECKSUM);
        else if (strncasecmp ("GET_NVT_DETAILS", element_name, 20) == 0)
          set_client_state (CLIENT_GET_NVT_DETAILS);
        else if (strncasecmp ("GET_PREFERENCES", element_name, 15) == 0)
          set_client_state (CLIENT_GET_PREFERENCES);
        else if (strncasecmp ("GET_REPORT", element_name, 10) == 0)
          {
            append_text (&current_uuid, "", 0);
            set_client_state (CLIENT_GET_REPORT);
          }
        else if (strncasecmp ("GET_RULES", element_name, 9) == 0)
          set_client_state (CLIENT_GET_RULES);
        else if (strncasecmp ("HELP", element_name, 4) == 0)
          set_client_state (CLIENT_HELP);
        else if (strncasecmp ("MODIFY_REPORT", element_name, 13) == 0)
          {
            append_text (&current_uuid, "", 0);
            set_client_state (CLIENT_MODIFY_REPORT);
          }
        else if (strncasecmp ("MODIFY_TASK", element_name, 11) == 0)
          {
            append_text (&current_uuid, "", 0);
            set_client_state (CLIENT_MODIFY_TASK);
          }
        else if (strncasecmp ("CREATE_TASK", element_name, 11) == 0)
          {
            assert (current_client_task == (task_t) NULL);
            current_client_task = make_task (NULL, 0, NULL);
            if (current_client_task == (task_t) NULL) abort (); // FIX
            set_client_state (CLIENT_CREATE_TASK);
          }
        else if (strncasecmp ("GET_VERSION", element_name, 11) == 0)
          set_client_state (CLIENT_VERSION);
        else if (strncasecmp ("START_TASK", element_name, 10) == 0)
          {
            append_text (&current_uuid, "", 0);
            set_client_state (CLIENT_START_TASK);
          }
        else if (strncasecmp ("STATUS", element_name, 6) == 0)
          {
            append_text (&current_uuid, "", 0);
            set_client_state (CLIENT_STATUS);
          }
        else
          {
            if (send_to_client ("<omp_response>"
                                "<status>" STATUS_ERROR_SYNTAX "</status>"
                                "</omp_response>"))
              {
                error_send_to_client (error);
                return;
              }
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
            if (send_to_client ("<authenticate_response>"
                                "<status>" STATUS_ERROR_SYNTAX "</status>"
                                "</authenticate_response>"))
              {
                error_send_to_client (error);
                return;
              }
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
            if (send_to_client ("<authenticate_response>"
                                "<status>" STATUS_ERROR_SYNTAX "</status>"
                                "</authenticate_response>"))
              {
                error_send_to_client (error);
                return;
              }
            free_credentials (&current_credentials);
            set_client_state (CLIENT_TOP);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_DELETE_REPORT:
        if (strncasecmp ("REPORT_ID", element_name, 9) == 0)
          set_client_state (CLIENT_DELETE_REPORT_ID);
        else
          {
            if (send_to_client ("<delete_report_response>"
                                "<status>" STATUS_ERROR_SYNTAX "</status>"
                                "</delete_report_response>"))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
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
            if (send_to_client ("<delete_task_response>"
                                "<status>" STATUS_ERROR_SYNTAX "</status>"
                                "</delete_task_response>"))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_GET_DEPENDENCIES:
          {
            if (send_to_client ("<get_dependencies_response>"
                                "<status>" STATUS_ERROR_SYNTAX "</status>"
                                "</get_dependencies_response>"))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_GET_NVT_ALL:
          {
            if (send_to_client ("<get_nvt_all>"
                                "<status>" STATUS_ERROR_SYNTAX "</status>"
                                "</get_nvt_all>"))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_GET_NVT_FEED_CHECKSUM:
          {
            if (send_to_client ("<get_nvt_feed_checksum>"
                                "<status>" STATUS_ERROR_SYNTAX "</status>"
                                "</get_nvt_feed_checksum>"))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_GET_NVT_DETAILS:
        if (strncasecmp ("OID", element_name, 3) == 0)
          set_client_state (CLIENT_GET_NVT_DETAILS_OID);
        else
          {
            if (send_to_client ("<get_nvt_details>"
                                "<status>" STATUS_ERROR_SYNTAX "</status>"
                                "</get_nvt_details>"))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_GET_PREFERENCES:
          {
            if (send_to_client ("<get_preferences_response>"
                                "<status>" STATUS_ERROR_SYNTAX "</status>"
                                "</get_preferences_response>"))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_GET_REPORT:
        if (strncasecmp ("REPORT_ID", element_name, 9) == 0)
          set_client_state (CLIENT_GET_REPORT_ID);
        else
          {
            if (send_to_client ("<get_report_response>"
                                "<status>" STATUS_ERROR_SYNTAX "</status>"
                                "</get_report_response>"))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_GET_RULES:
          {
            if (send_to_client ("<get_rules_response>"
                                "<status>" STATUS_ERROR_SYNTAX "</status>"
                                "</get_rules_response>"))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_HELP:
        {
          if (send_to_client ("<help_response>"
                              "<status>" STATUS_ERROR_SYNTAX "</status>"
                              "</help_response>"))
            {
              error_send_to_client (error);
              return;
            }
          set_client_state (CLIENT_AUTHENTIC);
          g_set_error (error,
                       G_MARKUP_ERROR,
                       G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                       "Error");
        }
        break;

      case CLIENT_MODIFY_REPORT:
        if (strncasecmp ("REPORT_ID", element_name, 9) == 0)
          set_client_state (CLIENT_MODIFY_REPORT_REPORT_ID);
        else if (strncasecmp ("PARAMETER", element_name, 9) == 0)
          set_client_state (CLIENT_MODIFY_REPORT_PARAMETER);
        else if (strncasecmp ("VALUE", element_name, 5) == 0)
          set_client_state (CLIENT_MODIFY_REPORT_VALUE);
        else
          {
            if (send_to_client ("<modify_report_response>"
                                "<status>" STATUS_ERROR_SYNTAX "</status>"
                                "</modify_report_response>"))
              {
                error_send_to_client (error);
                return;
              }
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
            if (send_to_client ("<modify_task_response>"
                                "<status>" STATUS_ERROR_SYNTAX "</status>"
                                "</modify_task_response>"))
              {
                error_send_to_client (error);
                return;
              }
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
            if (send_to_client ("<abort_task_response>"
                                "<status>" STATUS_ERROR_SYNTAX "</status>"
                                "</abort_task_response>"))
              {
                error_send_to_client (error);
                return;
              }
            set_client_state (CLIENT_AUTHENTIC);
            g_set_error (error,
                         G_MARKUP_ERROR,
                         G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                         "Error");
          }
        break;

      case CLIENT_CREATE_TASK:
        if (strncasecmp ("TASK_FILE", element_name, 9) == 0)
          set_client_state (CLIENT_CREATE_TASK_TASK_FILE);
        else if (strncasecmp ("IDENTIFIER", element_name, 10) == 0)
          set_client_state (CLIENT_CREATE_TASK_IDENTIFIER);
        else if (strncasecmp ("COMMENT", element_name, 7) == 0)
          set_client_state (CLIENT_CREATE_TASK_COMMENT);
        else
          {
            if (send_to_client ("<create_task_response>"
                                "<status>" STATUS_ERROR_SYNTAX "</status>"
                                "</create_task_response>"))
              {
                error_send_to_client (error);
                return;
              }
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
            if (send_to_client ("<start_task_response>"
                                "<status>" STATUS_ERROR_SYNTAX "</status>"
                                "</start_task_response>"))
              {
                error_send_to_client (error);
                return;
              }
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
            if (send_to_client ("<status_response>"
                                "<status>" STATUS_ERROR_SYNTAX "</status>"
                                "</status_response>"))
              {
                error_send_to_client (error);
                return;
              }
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
}

/**
 * @brief Send XML for a requirement of a plugin.
 *
 * @param[in]  element  The required plugin.
 * @param[in]  dummy    Dummy variable for g_hash_table_find.
 *
 * @return 0 if out of space in to_client buffer, else 1.
 */
static gint
send_requirement (gconstpointer element, /*@unused@*/ gconstpointer dummy)
{
  gboolean fail;
  gchar* text = g_markup_escape_text ((char*) element,
                                      strlen ((char*) element));
  gchar* msg = g_strdup_printf ("<need>%s</need>", text);
  g_free (text);

  fail = send_to_client (msg);
  g_free (msg);
  return fail ? 0 : 1;
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
static gboolean
send_dependency (gpointer key, gpointer value, /*@unused@*/ gpointer dummy)
{
  /* \todo Do these reallocations affect performance? */
  gchar* key_text = g_markup_escape_text ((char*) key, strlen ((char*) key));
  gchar* msg = g_strdup_printf ("<dependency><needer>%s</needer>",
                                key_text);
  g_free (key_text);
  if (send_to_client (msg))
    {
      g_free (msg);
      return TRUE;
    }

  if (g_slist_find_custom ((GSList*) value, NULL, send_requirement))
    {
      g_free (msg);
      return TRUE;
    }

  if (send_to_client ("</dependency>"))
    {
      g_free (msg);
      return TRUE;
    }

  g_free (msg);
  return FALSE;
}

/**
 * @brief Send XML for a plugin.
 *
 * @param[in]  key    The plugin OID.
 * @param[in]  value  The plugin.
 * @param[in]  dummy  Dummy variable, for nvtis_find.
 *
 * @return TRUE if out of space in to_client buffer, else FALSE.
 */
static gboolean
send_plugin (gpointer oid_gp, gpointer plugin_gp, gpointer details_gp)
{
  nvti_t* plugin = (nvti_t*) plugin_gp;
  char* oid = (char*) oid_gp;
  char* name = nvti_name (plugin);
  int details = (int) details_gp;
  gchar* msg;

  gchar* name_text = g_markup_escape_text (name, strlen (name));
  if (details)
    {
      gsize dummy;

#define stringify (x) #x

#define DEF(x)                                                    \
      char* x = nvti_ ## x (plugin);                              \
      /* FIX The g_convert is a temp hack. */                     \
      gchar* x ## _utf8 = x ? g_convert (x, strlen (x),           \
                                         "UTF-8", "ISO_8859-1",   \
                                         NULL, &dummy, NULL)      \
                            : NULL;                               \
      gchar* x ## _text = x ## _utf8                              \
                          ? g_markup_escape_text (x ## _utf8, -1) \
                          : g_strdup ("");                        \
      g_free (x ## _utf8);

      DEF (copyright);
      DEF (description);
      DEF (summary);
      DEF (family);
      DEF (version);
      DEF (tag);

#undef DEF

      msg = g_strdup_printf ("<nvt>"
                             "<oid>%s</oid>"
                             "<name>%s</name>"
                             "<category>%i</category>"
                             "<copyright>%s</copyright>"
                             "<description>%s</description>"
                             "<summary>%s</summary>"
                             "<family>%s</family>"
                             "<version>%s</version>"
                             // FIX spec has multiple <cve_id>s
                             "<cve_id>%s</cve_id>"
                             "<bugtraq_id>%s</bugtraq_id>"
                             "<xrefs>%s</xrefs>"
                             "<fingerprints>%s</fingerprints>"
                             "<tags>%s</tags>"
#if 0
                             // FIX implement
                             "<checksum>"
                             "<algorithm>md5</algorithm>"
                             "%s"
                             "</checksum>"
#endif
                             "</nvt>",
                             oid,
                             name_text,
                             nvti_category (plugin),
                             copyright_text,
                             description_text,
                             summary_text,
                             family_text,
                             version_text,
                             nvti_cve (plugin),
                             nvti_bid (plugin),
                             nvti_xref (plugin),
                             nvti_sign_key_ids (plugin),
                             tag_text);
      g_free (copyright_text);
      g_free (description_text);
      g_free (summary_text);
      g_free (family_text);
      g_free (version_text);
      g_free (tag_text);
    }
  else
    msg = g_strdup_printf ("<nvt>"
                           "<oid>%s</oid>"
                           "<name>%s</name>"
#if 0
                           // FIX implement
                           "<checksum>"
                           "<algorithm>md5</algorithm>"
                           "%s"
                           "</checksum>"
#endif
                           "</nvt>",
                           oid,
                           name_text);
  g_free (name_text);
  if (send_to_client (msg))
    {
      g_free (msg);
      return TRUE;
    }
  g_free (msg);
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
static gboolean
send_preference (gpointer key, gpointer value, /*@unused@*/ gpointer dummy)
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
  if (send_to_client (msg))
    {
      g_free (msg);
      return TRUE;
    }
  g_free (msg);
  return FALSE;
}

/**
 * @brief Send XML for a rule.
 *
 * @param[in]  rule  The rule.
 *
 * @return TRUE if out of space in to_client buffer, else FALSE.
 */
static gboolean
send_rule (gpointer rule)
{
  /* \todo Do these reallocations affect performance? */
  gchar* rule_text = g_markup_escape_text ((char*) rule,
                                           strlen ((char*) rule));
  gchar* msg = g_strdup_printf ("<rule>%s</rule>", rule_text);
  g_free (rule_text);
  if (send_to_client (msg))
    {
      g_free (msg);
      return TRUE;
    }
  g_free (msg);
  return FALSE;
}

/**
 * @brief Send XML for the reports of a task.
 *
 * @param[in]  task  The task.
 *
 * @return 0 success, -1 task ID error, -2 credentials missing,
 *         failed to open task dir, -4 out of space in to_client.
 */
static int
send_reports (task_t task)
{
  // FIX Abstract report iterator and move it to manage.c.

  gchar* dir_name;
  char* tsk_uuid;
  struct dirent ** names;
  int count, index;
  gchar* msg;

  if (task_uuid (task, &tsk_uuid)) return -1;

  if (current_credentials.username == NULL)
    {
      free (tsk_uuid);
      return -2;
    }

  dir_name = g_build_filename (PREFIX
                               "/var/lib/openvas/mgr/users/",
                               current_credentials.username,
                               "tasks",
                               tsk_uuid,
                               "reports",
                               NULL);
  free (tsk_uuid);

  count = scandir (dir_name, &names, NULL, alphasort);
  if (count < 0)
    {
      if (errno == ENOENT)
        {
          free (dir_name);
          return 0;
        }
      fprintf (stderr, "Failed to open dir %s: %s\n",
               dir_name,
               strerror (errno));
      g_free (dir_name);
      return -3;
    }

  msg = NULL;
  for (index = 0; index < count; index++)
    {
      /*@dependent@*/ const char* report_name = names[index]->d_name;

      if (report_name[0] == '.')
        {
          free (names[index]);
          continue;
        }

      if (strlen (report_name) == OVAS_MANAGE_REPORT_ID_LENGTH)
        {
#if 0
          report_dir_name = g_build_filename (dir_name, report_name, NULL);
#endif

          tracef ("     %s\n", report_name);

          msg = g_strdup_printf ("<report>"
                                 "<id>%s</id>"
                                 "<timestamp>FIX</timestamp>"
                                 "<messages>"
                                 // FIX
                                 "<hole>0</hole>"
                                 "<info>0</info>"
                                 "<log>0</log>"
                                 "<debug>0</debug>"
                                 "</messages>"
                                 "</report>",
                                 report_name);
          if (send_to_client (msg))
            {
              g_free (msg);
              while (index < count) { free (names[index++]); }
              free (names);
              g_free (dir_name);
              return -4;
            }
          g_free (msg);
        }

      free (names[index]);
    }

  free (names);
  g_free (dir_name);
  return 0;
}

/**
 * @brief Send response message to client, returning on fail.
 *
 * Queue a message in \ref to_client with \ref send_to_client.  On failure
 * call \ref error_send_to_client on a GError* called "error" and do a return.
 *
 * @param[in]   msg    The message, a string.
 */
#define SEND_TO_CLIENT_OR_FAIL(msg)                                          \
  do                                                                         \
    {                                                                        \
      if (send_to_client (msg))                                              \
        {                                                                    \
          error_send_to_client (error);                                      \
          return;                                                            \
        }                                                                    \
    }                                                                        \
  while (0)

/**
 * @brief Send response message to client, returning on fail.
 *
 * Queue a message in \ref to_client with \ref send_to_client.  On failure
 * call \ref error_send_to_client on a GError* called "error" and do a return.
 *
 * @param[in]   msg    The message, a string.
 */
#define SENDF_TO_CLIENT_OR_FAIL(format, args...)                             \
  do                                                                         \
    {                                                                        \
      gchar* msg = g_strdup_printf (format , ## args);                       \
      if (send_to_client (msg))                                              \
        {                                                                    \
          g_free (msg);                                                      \
          error_send_to_client (error);                                      \
          return;                                                            \
        }                                                                    \
      g_free (msg);                                                          \
    }                                                                        \
  while (0)

/**
 * @brief Handle the end of an OMP XML element.
 *
 * React to the end of an XML element according to the current value
 * of \ref client_state, usually adjusting \ref client_state to indicate
 * the change (with \ref set_client_state).  Call \ref send_to_client to queue
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
static void
omp_xml_handle_end_element (/*@unused@*/ GMarkupParseContext* context,
                            const gchar *element_name,
                            /*@unused@*/ gpointer user_data,
                            GError **error)
{
  tracef ("   XML    end: %s\n", element_name);
  switch (client_state)
    {
      case CLIENT_TOP:
        assert (0);
        break;

      case CLIENT_ABORT_TASK:
        if (current_uuid)
          {
            task_t task;

            assert (current_client_task == (task_t) NULL);

            if (find_task (current_uuid, &task))
              SEND_TO_CLIENT_OR_FAIL ("<abort_task_response>"
                                      "<status>"
                                      STATUS_ERROR_MISSING
                                      "</status>"
                                      "</abort_task_response>");
            else if (stop_task (task))
              {
                /* to_server is full. */
                // FIX revert parsing for retry
                // process_omp_client_input must return -2
                abort ();
              }
            else
              SEND_TO_CLIENT_OR_FAIL ("<abort_task_response>"
                                      "<status>" STATUS_OK_REQUESTED "</status>"
                                      "</abort_task_response>");
            free_string_var (&current_uuid);
          }
        else
          SEND_TO_CLIENT_OR_FAIL ("<abort_task_response>"
                                  "<status>" STATUS_INTERNAL_ERROR "</status>"
                                  "</abort_task_response>");
        set_client_state (CLIENT_AUTHENTIC);
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
        switch (authenticate (&current_credentials))
          {
            case 0:
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
              break;
            case 1:
              SEND_TO_CLIENT_OR_FAIL ("<authenticate_response>"
                                      "<status>"
                                      STATUS_ERROR_AUTH_FAILED
                                      "</status>"
                                      "</authenticate_response>");
              free_credentials (&current_credentials);
              set_client_state (CLIENT_TOP);
              break;
            case -1:
            default:
              SEND_TO_CLIENT_OR_FAIL ("<authenticate_response>"
                                      "<status>"
                                      STATUS_INTERNAL_ERROR
                                      "</status>"
                                      "</authenticate_response>");
              free_credentials (&current_credentials);
              set_client_state (CLIENT_TOP);
              break;
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
            SEND_TO_CLIENT_OR_FAIL ("<get_preferences_response>"
                                    "<status>" STATUS_OK "</status>");
            if (g_hash_table_find (server.preferences, send_preference, NULL))
              {
                error_send_to_client (error);
                return;
              }
            SEND_TO_CLIENT_OR_FAIL ("</get_preferences_response>");
          }
        else
          SEND_TO_CLIENT_OR_FAIL ("<get_preferences_response>"
                                  "<status>" STATUS_SERVICE_DOWN "</status>"
                                  "</get_preferences_response>");
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_GET_DEPENDENCIES:
        if (server.plugins_dependencies)
          {
            SEND_TO_CLIENT_OR_FAIL ("<get_dependencies_response>"
                                    "<status>" STATUS_OK "</status>");
            if (g_hash_table_find (server.plugins_dependencies,
                                   send_dependency,
                                   NULL))
              {
                error_send_to_client (error);
                return;
              }
            SEND_TO_CLIENT_OR_FAIL ("</get_dependencies_response>");
          }
        else
          SEND_TO_CLIENT_OR_FAIL ("<get_dependencies_response>"
                                  "<status>" STATUS_SERVICE_DOWN "</status>"
                                  "</get_dependencies_response>");
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_GET_NVT_ALL:
        if (server.plugins)
          {
            SEND_TO_CLIENT_OR_FAIL ("<get_nvt_all_response>"
                                    "<status>" STATUS_OK "</status>");
            SENDF_TO_CLIENT_OR_FAIL ("<nvt_count>%u</nvt_count>",
                                     nvtis_size (server.plugins));
            if (server.plugins_md5)
              {
                SEND_TO_CLIENT_OR_FAIL ("<feed_checksum>"
                                        "<algorithm>md5</algorithm>");
                SEND_TO_CLIENT_OR_FAIL (server.plugins_md5);
                SEND_TO_CLIENT_OR_FAIL ("</feed_checksum>");
              }
            if (nvtis_find (server.plugins, send_plugin, (gpointer) 0))
              {
                error_send_to_client (error);
                return;
              }
            SEND_TO_CLIENT_OR_FAIL ("</get_nvt_all_response>");
          }
        else
          {
            SEND_TO_CLIENT_OR_FAIL ("<get_nvt_all_response>"
                                    "<status>" STATUS_SERVICE_DOWN "</status>"
                                    "</get_nvt_all_response>");
            /* \todo TODO Sort out a cache for this. */
            if (request_plugin_list ())
              {
                /* to_server is full. */
                // FIX ~ revert parsing for retry
                // process_omp_client_input must return -2
                abort ();
              }
          }
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_GET_NVT_FEED_CHECKSUM:
        if (server.plugins_md5)
          {
            SEND_TO_CLIENT_OR_FAIL ("<get_nvt_feed_checksum_response>"
                                    "<status>" STATUS_OK "</status>"
                                    "<algorithm>md5</algorithm>");
            SEND_TO_CLIENT_OR_FAIL (server.plugins_md5);
            SEND_TO_CLIENT_OR_FAIL ("</get_nvt_feed_checksum_response>");
          }
        else
          SEND_TO_CLIENT_OR_FAIL ("<get_nvt_feed_checksum_response>"
                                  "<status>" STATUS_SERVICE_DOWN "</status>"
                                  "</get_nvt_feed_checksum_response>");
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_GET_NVT_DETAILS:
        if (server.plugins)
          {
            SEND_TO_CLIENT_OR_FAIL ("<get_nvt_details_response>");
            if (current_uuid)
              {
                nvti_t* plugin = find_nvti (server.plugins, current_uuid);
                if (plugin)
                  {
                    SEND_TO_CLIENT_OR_FAIL ("<status>" STATUS_OK "</status>");
                    send_plugin (plugin->oid, plugin, (gpointer) 1);
                  }
                else
                  {
                    SEND_TO_CLIENT_OR_FAIL ("<status>"
                                            STATUS_ERROR_MISSING
                                            "</status>");
                  }
              }
            else
              {
                SENDF_TO_CLIENT_OR_FAIL ("<nvt_count>%u</nvt_count>",
                                         nvtis_size (server.plugins));
                if (server.plugins_md5)
                  {
                    SEND_TO_CLIENT_OR_FAIL ("<feed_checksum>"
                                            "<algorithm>md5</algorithm>");
                    SEND_TO_CLIENT_OR_FAIL (server.plugins_md5);
                    SEND_TO_CLIENT_OR_FAIL ("</feed_checksum>");
                  }
                if (nvtis_find (server.plugins, send_plugin, (gpointer) 1))
                  {
                    error_send_to_client (error);
                    return;
                  }
              }
            SEND_TO_CLIENT_OR_FAIL ("</get_nvt_details_response>");
          }
        else
          {
            SEND_TO_CLIENT_OR_FAIL ("<get_nvt_details_response>"
                                    "<status>" STATUS_SERVICE_DOWN "</status>"
                                    "</get_nvt_details_response>");
            /* \todo TODO Sort out a cache for this. */
            if (request_plugin_list ())
              {
                /* to_server is full. */
                // FIX ~ revert parsing for retry
                // process_omp_client_input must return -2
                abort ();
              }
          }
        set_client_state (CLIENT_AUTHENTIC);
        break;
      case CLIENT_GET_NVT_DETAILS_OID:
        assert (strncasecmp ("OID", element_name, 3) == 0);
        set_client_state (CLIENT_GET_NVT_DETAILS);
        break;

      case CLIENT_DELETE_REPORT:
        assert (strncasecmp ("DELETE_REPORT", element_name, 13) == 0);
        SEND_TO_CLIENT_OR_FAIL ("<delete_report_response>");
        if (current_uuid)
          {
            // FIX check syntax of current_uuid  STATUS_ERROR_SYNTAX
            int ret = delete_report (current_uuid);
            free_string_var (&current_uuid);
            switch (ret)
              {
                case 0:
                  SEND_TO_CLIENT_OR_FAIL ("<status>" STATUS_OK "</status>");
                  break;
                case -1: /* Failed to find associated task. */
                case -2: /* Report file missing. */
                  SEND_TO_CLIENT_OR_FAIL ("<status>"
                                          STATUS_ERROR_MISSING
                                          "</status>");
                  break;
                case -3: /* Failed to read link. */
                case -4: /* Failed to remove report. */
                default:
                  free_string_var (&current_uuid);
                  SEND_TO_CLIENT_OR_FAIL ("<status>"
                                          STATUS_INTERNAL_ERROR
                                          "</status>");
                  break;
              }
          }
        else
          SEND_TO_CLIENT_OR_FAIL ("<status>" STATUS_INTERNAL_ERROR "</status>");
        SEND_TO_CLIENT_OR_FAIL ("</delete_report_response>");
        set_client_state (CLIENT_AUTHENTIC);
        break;
      case CLIENT_DELETE_REPORT_ID:
        assert (strncasecmp ("REPORT_ID", element_name, 9) == 0);
        set_client_state (CLIENT_DELETE_REPORT);
        break;

      case CLIENT_GET_REPORT:
        assert (strncasecmp ("GET_REPORT", element_name, 10) == 0);
        if (current_uuid != NULL
            && current_credentials.username != NULL)
          {
            gchar* name = g_build_filename (PREFIX
                                            "/var/lib/openvas/mgr/users/",
                                            current_credentials.username,
                                            "reports",
                                            current_uuid,
                                            "report.nbe",
                                            NULL);
            free_string_var (&current_uuid);
            // FIX glib access setuid note
            if (g_file_test (name, G_FILE_TEST_EXISTS))
              {
                gboolean success;
                gchar* content;
                gsize content_length = 0;
                GError* content_error = NULL;
                success = g_file_get_contents (name,
                                               &content,
                                               &content_length,
                                               &content_error);
                g_free (name);
                if (success == FALSE)
                  {
                    if (content_error)
                      g_error_free (content_error);
                    SEND_TO_CLIENT_OR_FAIL ("<get_report_response>"
                                            "<status>"
                                            STATUS_ERROR_MISSING
                                            "</status>");
                  }
                else
                  {
                    gchar* base64_content;
                    SEND_TO_CLIENT_OR_FAIL ("<get_report_response>"
                                            "<status>" STATUS_OK "</status>"
                                            "<report>");
                    base64_content = g_base64_encode ((guchar*) content,
                                                      content_length);
                    g_free (content);
                    if (send_to_client (base64_content))
                      {
                        g_free (base64_content);
                        error_send_to_client (error);
                        return;
                      }
                    g_free (base64_content);
                    SEND_TO_CLIENT_OR_FAIL ("</report>");
                  }
              }
            else
              {
                g_free (name);
                SEND_TO_CLIENT_OR_FAIL ("<get_report_response>"
                                        "<status>"
                                        STATUS_ERROR_MISSING
                                        "</status>");
              }
          }
        else
          {
            free_string_var (&current_uuid);
            SEND_TO_CLIENT_OR_FAIL ("<get_report_response>"
                                    "<status>"
                                    STATUS_INTERNAL_ERROR
                                    "</status>");
          }
        SEND_TO_CLIENT_OR_FAIL ("</get_report_response>");
        set_client_state (CLIENT_AUTHENTIC);
        break;
      case CLIENT_GET_REPORT_ID:
        assert (strncasecmp ("REPORT_ID", element_name, 9) == 0);
        set_client_state (CLIENT_GET_REPORT);
        break;

      case CLIENT_GET_RULES:
        if (server.rules)
          {
            int index;
            SEND_TO_CLIENT_OR_FAIL ("<get_rules_response>"
                                    "<status>" STATUS_OK "</status>");
            for (index = 0; index < server.rules_size; index++)
              if (send_rule (g_ptr_array_index (server.rules, index)))
                {
                  error_send_to_client (error);
                  return;
                }
            SEND_TO_CLIENT_OR_FAIL ("</get_rules_response>");
          }
        else
          SEND_TO_CLIENT_OR_FAIL ("<get_rules_response>"
                                  "<status>" STATUS_INTERNAL_ERROR "</status>"
                                  "</get_rules_response>");
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_VERSION:
        SEND_TO_CLIENT_OR_FAIL ("<get_version_response>"
                                "<status>" STATUS_OK "</status>"
                                "<version><preferred/>1.0</version>"
                                "</get_version_response>");
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_DELETE_TASK:
        if (current_uuid)
          {
            assert (current_client_task == (task_t) NULL);
            task_t task;
            if (find_task (current_uuid, &task))
              SEND_TO_CLIENT_OR_FAIL ("<delete_task_response>"
                                      "<status>"
                                      STATUS_ERROR_MISSING
                                      "</status>"
                                      "</delete_task_response>");
            else if (request_delete_task (&task))
              {
                /* to_server is full. */
                // FIX or some other error
                // FIX revert parsing for retry
                // process_omp_client_input must return -2
                tracef ("delete_task failed\n");
                abort ();
              }
            else
              SEND_TO_CLIENT_OR_FAIL ("<delete_task_response>"
                                      "<status>" STATUS_OK_REQUESTED "</status>"
                                      "</delete_task_response>");
            free_string_var (&current_uuid);
          }
        else
          SEND_TO_CLIENT_OR_FAIL ("<delete_task_response>"
                                  "<status>" STATUS_INTERNAL_ERROR "</status>"
                                  "</delete_task_response>");
        set_client_state (CLIENT_AUTHENTIC);
        break;
      case CLIENT_DELETE_TASK_TASK_ID:
        assert (strncasecmp ("TASK_ID", element_name, 7) == 0);
        set_client_state (CLIENT_DELETE_TASK);
        break;

      case CLIENT_HELP:
        SEND_TO_CLIENT_OR_FAIL ("<help_response>"
                                "<status>" STATUS_OK "</status>");
        SEND_TO_CLIENT_OR_FAIL (help_text);
        SEND_TO_CLIENT_OR_FAIL ("</help_response>");
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_MODIFY_REPORT:
        if (current_uuid != NULL
            && modify_task_parameter != NULL
            && modify_task_value != NULL)
          {
            int ret = set_report_parameter (current_uuid,
                                            modify_task_parameter,
                                            modify_task_value);
            free_string_var (&modify_task_parameter);
            free_string_var (&modify_task_value);
            free_string_var (&current_uuid);
            switch (ret)
              {
                case 0:
                  SEND_TO_CLIENT_OR_FAIL ("<modify_report_response>"
                                          "<status>" STATUS_OK "</status>");
                  break;
                case -2: /* Parameter name error. */
                  SEND_TO_CLIENT_OR_FAIL ("<modify_report_response>"
                                          "<status>"
                                          STATUS_ERROR_SYNTAX
                                          "</status>");
                  break;
                case -3: /* Failed to write to disk. */
                default:
                  SEND_TO_CLIENT_OR_FAIL ("<modify_report_response>"
                                          "<status>"
                                          STATUS_INTERNAL_ERROR
                                          "</status>");
                  break;
              }
          }
        else
          {
            free_string_var (&modify_task_parameter);
            free_string_var (&modify_task_value);
            free_string_var (&current_uuid);
            SEND_TO_CLIENT_OR_FAIL ("<modify_report_response>"
                                    "<status>"
                                    STATUS_INTERNAL_ERROR
                                    "</status>");
          }
        SEND_TO_CLIENT_OR_FAIL ("</modify_report_response>");
        set_client_state (CLIENT_AUTHENTIC);
        break;
      case CLIENT_MODIFY_REPORT_PARAMETER:
        assert (strncasecmp ("PARAMETER", element_name, 9) == 0);
        set_client_state (CLIENT_MODIFY_REPORT);
        break;
      case CLIENT_MODIFY_REPORT_REPORT_ID:
        assert (strncasecmp ("REPORT_ID", element_name, 9) == 0);
        set_client_state (CLIENT_MODIFY_REPORT);
        break;
      case CLIENT_MODIFY_REPORT_VALUE:
        assert (strncasecmp ("VALUE", element_name, 5) == 0);
        set_client_state (CLIENT_MODIFY_REPORT);
        break;

      case CLIENT_MODIFY_TASK:
        if (current_uuid)
          {
            assert (current_client_task == (task_t) NULL);
            task_t task;
            if (find_task (current_uuid, &task))
              SEND_TO_CLIENT_OR_FAIL ("<modify_task_response>"
                                      "<status>"
                                      STATUS_ERROR_MISSING
                                      "</status>"
                                      "</modify_task_response>");
            else
              {
                // FIX check if param,value else respond fail
                int fail = set_task_parameter (task,
                                               modify_task_parameter,
                                               modify_task_value);
                free (modify_task_parameter);
                if (fail)
                  {
                    free (modify_task_value);
                    modify_task_value = NULL;
                    if (fail == -4)
                      SEND_TO_CLIENT_OR_FAIL ("<modify_task_response>"
                                              "<status>"
                                              STATUS_INTERNAL_ERROR
                                              "</status>"
                                              "</modify_task_response>");
                    else
                      SEND_TO_CLIENT_OR_FAIL ("<modify_task_response>"
                                              "<status>"
                                              STATUS_ERROR_SYNTAX
                                              "</status>"
                                              "</modify_task_response>");
                  }
                else
                  {
                    modify_task_value = NULL;
                    SEND_TO_CLIENT_OR_FAIL ("<modify_task_response>"
                                            "<status>"
                                            STATUS_OK_REQUESTED
                                            "</status>"
                                            "</modify_task_response>");
                  }
              }
            free_string_var (&current_uuid);
          }
        else
          SEND_TO_CLIENT_OR_FAIL ("<modify_task_response>"
                                  "<status>" STATUS_INTERNAL_ERROR "</status>"
                                  "</modify_task_response>");
        set_client_state (CLIENT_AUTHENTIC);
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

      case CLIENT_CREATE_TASK:
        {
          char* tsk_uuid;

          assert (strncasecmp ("CREATE_TASK", element_name, 11) == 0);
          assert (current_client_task != (task_t) NULL);

          // FIX if all rqrd fields given then ok, else respond fail
          // FIX only here should the task be added to tasks
          //       eg on err half task could be saved (or saved with base64 file)

          if (task_uuid (current_client_task, &tsk_uuid))
            SEND_TO_CLIENT_OR_FAIL ("<create_task_response>"
                                    "<status>" STATUS_ERROR_MISSING "</status>"
                                    "</create_task_response>");
          else
            {
              gchar* msg;
              msg = g_strdup_printf ("<create_task_response>"
                                     "<status>" STATUS_OK_CREATED "</status>"
                                     "<task_id>%s</task_id>"
                                     "</create_task_response>",
                                     tsk_uuid);
              free (tsk_uuid);
              if (send_to_client (msg))
                {
                  g_free (msg);
                  error_send_to_client (error);
                  return;
                }
              g_free (msg);
            }
          current_client_task = (task_t) NULL;
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      case CLIENT_CREATE_TASK_COMMENT:
        assert (strncasecmp ("COMMENT", element_name, 12) == 0);
        set_client_state (CLIENT_CREATE_TASK);
        break;
      case CLIENT_CREATE_TASK_IDENTIFIER:
        assert (strncasecmp ("IDENTIFIER", element_name, 10) == 0);
        set_client_state (CLIENT_CREATE_TASK);
        break;
      case CLIENT_CREATE_TASK_TASK_FILE:
        assert (strncasecmp ("TASK_FILE", element_name, 9) == 0);
        if (current_client_task)
          {
            gsize out_len;
            guchar* out;
            char* description = task_description (current_client_task);
            out = g_base64_decode (description, &out_len);
            free (description);
            set_task_description (current_client_task, (char*) out, out_len);
            set_client_state (CLIENT_CREATE_TASK);
          }
        break;

      case CLIENT_START_TASK:
        if (current_uuid)
          {
            assert (current_client_task == (task_t) NULL);
            task_t task;
            if (find_task (current_uuid, &task))
              SEND_TO_CLIENT_OR_FAIL ("<start_task_response>"
                                      "<status>"
                                      STATUS_ERROR_MISSING
                                      "</status>"
                                      "</start_task_response>");
            else if (start_task (task))
              {
                /* to_server is full. */
                // FIX revert parsing for retry
                // process_omp_client_input must return -2
                abort ();
              }
            else
              SEND_TO_CLIENT_OR_FAIL ("<start_task_response>"
                                      "<status>" STATUS_OK_REQUESTED "</status>"
                                      "</start_task_response>");
            free_string_var (&current_uuid);
          }
        else
          SEND_TO_CLIENT_OR_FAIL ("<start_task_response>"
                                  "<status>" STATUS_INTERNAL_ERROR "</status>"
                                  "<start_task_response>");
        set_client_state (CLIENT_AUTHENTIC);
        break;
      case CLIENT_START_TASK_TASK_ID:
        assert (strncasecmp ("TASK_ID", element_name, 7) == 0);
        set_client_state (CLIENT_START_TASK);
        break;

      case CLIENT_STATUS:
        assert (strncasecmp ("STATUS", element_name, 6) == 0);
        if (current_uuid && strlen (current_uuid))
          {
            task_t task;
            if (find_task (current_uuid, &task))
              SEND_TO_CLIENT_OR_FAIL ("<status_response>"
                                      "<status>"
                                      STATUS_ERROR_MISSING
                                      "</status>");
            else
              {
                char* tsk_uuid;

                if (task_uuid (task, &tsk_uuid))
                  SEND_TO_CLIENT_OR_FAIL ("<status_response>"
                                          "<status>"
                                          STATUS_INTERNAL_ERROR
                                          "</status>"
                                          "</status_response>");
                else
                  {
                    int ret;
                    gchar* response;
                    char* name;

                    name = task_name (task);
                    response = g_strdup_printf ("<status_response>"
                                                "<status>" STATUS_OK "</status>"
                                                "<task_id>%s</task_id>"
                                                "<identifier>%s</identifier>"
                                                "<status>%s</status>" // FIX again!
                                                "<messages>"
                                                "<debug>%i</debug>"
                                                "<hole>%i</hole>"
                                                "<info>%i</info>"
                                                "<log>%i</log>"
                                                "<warning>%i</warning>"
                                                "</messages>"
                                                "<report_count>%u</report_count>",
                                                tsk_uuid,
                                                name,
                                                task_run_status_name (task),
                                                task_debugs_size (task),
                                                task_holes_size (task),
                                                task_infos_size (task),
                                                task_logs_size (task),
                                                task_notes_size (task),
                                                task_report_count (task));
                    ret = send_to_client (response);
                    g_free (response);
                    g_free (name);
                    g_free (tsk_uuid);
                    if (ret)
                      {
                        error_send_to_client (error);
                        return;
                      }
                    // FIX need to handle err cases before send status
                    (void) send_reports (task);
                  }
              }
            free_string_var (&current_uuid);
          }
        else if (current_uuid)
          {
            gchar* response;
            task_iterator_t iterator;
            task_t index;

            free_string_var (&current_uuid);

            SEND_TO_CLIENT_OR_FAIL ("<status_response>"
                                    "<status>" STATUS_OK "</status>");
            response = g_strdup_printf ("<task_count>%u</task_count>",
                                        task_count ());
            if (send_to_client (response))
              {
                g_free (response);
                error_send_to_client (error);
                return;
              }
            g_free (response);

            init_task_iterator (&iterator);
            while (next_task (&iterator, &index))
              {
                gchar* line;
                char* name = task_name (index);
                char* tsk_uuid;

                // FIX buffer entire response so this can respond on err
                if (task_uuid (index, &tsk_uuid)) abort ();

                line = g_strdup_printf ("<task>"
                                        "<task_id>%s</task_id>"
                                        "<identifier>%s</identifier>"
                                        "<status>%s</status>"
                                        "<messages>"
                                        "<debug>%i</debug>"
                                        "<hole>%i</hole>"
                                        "<info>%i</info>"
                                        "<log>%i</log>"
                                        "<warning>%i</warning>"
                                        "</messages>"
                                        "</task>",
                                        tsk_uuid,
                                        name,
                                        task_run_status_name (index),
                                        task_debugs_size (index),
                                        task_holes_size (index),
                                        task_infos_size (index),
                                        task_logs_size (index),
                                        task_notes_size (index));
                free (name);
                free (tsk_uuid);
                if (send_to_client (line))
                  {
                    g_free (line);
                    error_send_to_client (error);
                    return;
                  }
                g_free (line);
              }
          }
        else
          SEND_TO_CLIENT_OR_FAIL ("<status_response>"
                                  "<status>"
                                  STATUS_INTERNAL_ERROR
                                  "</status>");
        SEND_TO_CLIENT_OR_FAIL ("</status_response>");
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
}

/**
 * @brief Handle the addition of text to an OMP XML element.
 *
 * React to the addition of text to the value of an XML element.
 * React according to the current value of \ref client_state,
 * usually appending the text to some part of the current task
 * (\ref current_client_task) with functions like \ref append_text,
 * \ref add_task_description_line and \ref append_to_task_comment.
 *
 * @param[in]  context           Parser context.
 * @param[in]  text              The text.
 * @param[in]  text_len          Length of the text.
 * @param[in]  user_data         Dummy parameter.
 * @param[in]  error             Error parameter.
 */
static void
omp_xml_handle_text (/*@unused@*/ GMarkupParseContext* context,
                     const gchar *text,
                     gsize text_len,
                     /*@unused@*/ gpointer user_data,
                     /*@unused@*/ GError **error)
{
  if (text_len == 0) return;
  tracef ("   XML   text: %s\n", text);
  switch (client_state)
    {
      case CLIENT_MODIFY_REPORT_PARAMETER:
        append_text (&modify_task_parameter, text, text_len);
        break;
      case CLIENT_MODIFY_REPORT_VALUE:
        append_text (&modify_task_value, text, text_len);
        break;

      case CLIENT_MODIFY_TASK_PARAMETER:
        append_text (&modify_task_parameter, text, text_len);
        break;
      case CLIENT_MODIFY_TASK_VALUE:
        append_text (&modify_task_value, text, text_len);
        break;

      case CLIENT_CREDENTIALS_USERNAME:
        append_to_credentials_username (&current_credentials, text, text_len);
        break;
      case CLIENT_CREDENTIALS_PASSWORD:
        append_to_credentials_password (&current_credentials, text, text_len);
        break;

      case CLIENT_CREATE_TASK_COMMENT:
        append_to_task_comment (current_client_task, text, text_len);
        break;
      case CLIENT_CREATE_TASK_IDENTIFIER:
        append_to_task_identifier (current_client_task, text, text_len);
        break;
      case CLIENT_CREATE_TASK_TASK_FILE:
        /* Append the text to the task description. */
        if (add_task_description_line (current_client_task,
                                       text,
                                       text_len))
          abort (); // FIX out of mem
        break;

      case CLIENT_ABORT_TASK_TASK_ID:
      case CLIENT_DELETE_REPORT_ID:
      case CLIENT_DELETE_TASK_TASK_ID:
      case CLIENT_GET_REPORT_ID:
      case CLIENT_GET_NVT_DETAILS_OID:
      case CLIENT_MODIFY_REPORT_REPORT_ID:
      case CLIENT_MODIFY_TASK_TASK_ID:
      case CLIENT_START_TASK_TASK_ID:
      case CLIENT_STATUS_TASK_ID:
        append_text (&current_uuid, text, text_len);
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
static void
omp_xml_handle_error (/*@unused@*/ GMarkupParseContext* context,
                      GError *error,
                      /*@unused@*/ gpointer user_data)
{
  tracef ("   XML ERROR %s\n", error->message);
}


/* OMP input processor. */

// FIX probably should pass to process_omp_client_input
extern char from_client[];
extern buffer_size_t from_client_start;
extern buffer_size_t from_client_end;

/**
 * @brief Initialise OMP library.
 *
 * @return 0 on success, else -1.
 */
int
init_omp ()
{
  return init_manage ();
}

/**
 * @brief Initialise OMP library data for a process.
 *
 * This should run once per process, before the first call to \ref
 * process_omp_client_input.
 */
void
init_omp_process ()
{
  init_manage_process ();
  /* Create the XML parser. */
  xml_parser.start_element = omp_xml_handle_start_element;
  xml_parser.end_element = omp_xml_handle_end_element;
  xml_parser.text = omp_xml_handle_text;
  xml_parser.passthrough = NULL;
  xml_parser.error = omp_xml_handle_error;
  if (xml_context) g_free (xml_context);
  xml_context = g_markup_parse_context_new (&xml_parser,
                                            0,
                                            NULL,
                                            NULL);
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
 * the client in \ref to_client (using \ref send_to_client).
 *
 * @return 0 success, -1 error, -2 or -3 too little space in \ref to_client
 *         or \ref to_server.
 */
int
process_omp_client_input ()
{
  gboolean success;
  GError* error = NULL;

  if (xml_context == NULL) return -1;

  success = g_markup_parse_context_parse (xml_context,
                                          from_client + from_client_start,
                                          from_client_end - from_client_start,
                                          &error);
  if (success == FALSE)
    {
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
        }
      /* In all error cases return -1 to close the connection, because it
         would be too hard, if possible at all, to figure out where the
         next command starts. */
      return -1;
    }
  from_client_end = from_client_start = 0;
  return 0;
}

/**
 * @brief Return whether the server is active.
 *
 * @return 1 if the server is doing something that the manager
 *         must wait for, else 0.
 */
short
server_is_active ()
{
  return server_active;
}
