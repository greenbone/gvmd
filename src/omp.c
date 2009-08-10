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
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <openvas/certificate.h>
#include <openvas/nvti.h>
#include <openvas/openvas_logging.h>

#ifdef S_SPLINT_S
#include "splint.h"
#endif

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md    omp"


/* Help message. */

static char* help_text = "\n"
"    ABORT_TASK             Abort a running task.\n"
"    AUTHENTICATE           Authenticate with the manager.\n"
"    CREATE_CONFIG          Create a new config.\n"
"    CREATE_TARGET          Create a new target.\n"
"    CREATE_TASK            Create a new task.\n"
"    DELETE_CONFIG          Delete an existing config.\n"
"    DELETE_REPORT          Delete an existing report.\n"
"    DELETE_TARGET          Delete an existing target.\n"
"    DELETE_TASK            Delete an existing task.\n"
"    GET_CERTIFICATES       Get all available certificates.\n"
"    GET_CONFIGS            Get all configs.\n"
"    GET_DEPENDENCIES       Get dependencies for all available NVTs.\n"
"    GET_NVT_ALL            Get IDs and names of all available NVTs.\n"
"    GET_NVT_DETAILS        Get all details for all available NVTs.\n"
"    GET_NVT_FEED_CHECKSUM  Get checksum for entire NVT collection.\n"
"    GET_PREFERENCES        Get preferences for all available NVTs.\n"
"    GET_REPORT             Get a report identified by its unique ID.\n"
"    GET_RULES              Get the rules for the authenticated user.\n"
"    GET_STATUS             Get task status information.\n"
"    GET_TARGETS            Get all targets.\n"
"    GET_VERSION            Get the OpenVAS Manager Protocol version.\n"
"    HELP                   Get this help text.\n"
"    MODIFY_REPORT          Modify an existing report.\n"
"    MODIFY_TASK            Update an existing task.\n"
"    START_TASK             Manually start an existing task.\n";


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

/**
 * @brief Response code for a syntax error.
 */
#define STATUS_ERROR_SYNTAX       "400"

/**
 * @brief Response code when authorisation is required.
 */
#define STATUS_ERROR_MUST_AUTH    "401"

/**
 * @brief Response code for a missing resource.
 */
#define STATUS_ERROR_MISSING      "404"

/**
 * @brief Response code when authorisation failed.
 */
#define STATUS_ERROR_AUTH_FAILED  "400"

/**
 * @brief Response code on success.
 */
#define STATUS_OK                 "200"

/**
 * @brief Response code on success, when a resource is created.
 */
#define STATUS_OK_CREATED         "201"

/**
 * @brief Response code on success, when the operation will finish later.
 */
#define STATUS_OK_REQUESTED       "202"

/**
 * @brief Response code for an internal error.
 */
#define STATUS_INTERNAL_ERROR     "500"

/**
 * @brief Response code when a service is down.
 */
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
 * @brief Current format of report, during GET_REPORT.
 */
static /*@null@*/ /*@only@*/ char*
current_format = NULL;

/**
 * @brief Parameter name during OMP MODIFY_TASK.
 */
static /*@null@*/ /*@only@*/ char*
modify_task_parameter = NULL;

/**
 * @brief Comment during OMP MODIFY_TASK.
 */
static /*@null@*/ /*@only@*/ char*
modify_task_comment = NULL;

/**
 * @brief Name during OMP MODIFY_TASK.
 */
static /*@null@*/ /*@only@*/ char*
modify_task_name = NULL;

/**
 * @brief RC file during OMP MODIFY_TASK.
 */
static /*@null@*/ /*@only@*/ char*
modify_task_rcfile = NULL;

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
  // FIX
#if 0
  CLIENT_ABORT_TASK_CRITERION,
#endif
  CLIENT_AUTHENTICATE,
  CLIENT_CREATE_CONFIG,
  CLIENT_CREATE_CONFIG_NAME,
  CLIENT_CREATE_CONFIG_RCFILE,
  CLIENT_CREATE_TARGET,
  CLIENT_CREATE_TARGET_HOSTS,
  CLIENT_CREATE_TARGET_NAME,
  CLIENT_CREATE_TASK,
  CLIENT_CREATE_TASK_COMMENT,
  CLIENT_CREATE_TASK_NAME,
  CLIENT_CREATE_TASK_RCFILE,
  CLIENT_CREDENTIALS,
  CLIENT_CREDENTIALS_PASSWORD,
  CLIENT_CREDENTIALS_USERNAME,
  CLIENT_DELETE_CONFIG,
  CLIENT_DELETE_CONFIG_NAME,
  CLIENT_DELETE_REPORT,
  CLIENT_DELETE_TASK,
  CLIENT_DELETE_TARGET,
  CLIENT_DELETE_TARGET_NAME,
  CLIENT_GET_CERTIFICATES,
  CLIENT_GET_CONFIGS,
  CLIENT_GET_DEPENDENCIES,
  CLIENT_GET_NVT_ALL,
  CLIENT_GET_NVT_DETAILS,
  CLIENT_GET_NVT_FEED_CHECKSUM,
  CLIENT_GET_PREFERENCES,
  CLIENT_GET_REPORT,
  CLIENT_GET_RULES,
  CLIENT_GET_STATUS,
  CLIENT_GET_TARGETS,
  CLIENT_HELP,
  CLIENT_MODIFY_REPORT,
  CLIENT_MODIFY_REPORT_PARAMETER,
  CLIENT_MODIFY_TASK,
  CLIENT_MODIFY_TASK_COMMENT,
  CLIENT_MODIFY_TASK_NAME,
  CLIENT_MODIFY_TASK_PARAMETER,
  CLIENT_MODIFY_TASK_RCFILE,
  CLIENT_START_TASK,
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
    {
      tracef ("   send_to_client out of space (%i < %i)\n",
              ((buffer_size_t) TO_CLIENT_BUFFER_SIZE) - to_client_end,
              strlen (msg));
      return TRUE;
    }
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
 * @brief Expand to XML for a STATUS_ERROR_SYNTAX response.
 *
 * @param  tag  Name of the command generating the response.
 */
#define XML_ERROR_SYNTAX(tag) "<" tag "_response status=\"" STATUS_ERROR_SYNTAX "\"/>"

/**
 * @brief Expand to XML for a STATUS_ERROR_MISSING response.
 *
 * @param  tag  Name of the command generating the response.
 */
#define XML_ERROR_MISSING(tag) "<" tag "_response status=\"" STATUS_ERROR_MISSING "\"/>"

/**
 * @brief Expand to XML for a STATUS_ERROR_AUTH_FAILED response.
 *
 * @param  tag  Name of the command generating the response.
 */
#define XML_ERROR_AUTH_FAILED(tag) "<" tag "_response status=\"" STATUS_ERROR_AUTH_FAILED "\"/>"

/**
 * @brief Expand to XML for a STATUS_OK response.
 *
 * @param  tag  Name of the command generating the response.
 */
#define XML_OK(tag) "<" tag "_response status=\"" STATUS_OK "\"/>"

/**
 * @brief Expand to XML for a STATUS_OK_CREATED response.
 *
 * @param  tag  Name of the command generating the response.
 */
#define XML_OK_CREATED(tag) "<" tag "_response status=\"" STATUS_OK_CREATED "\"/>"

/**
 * @brief Expand to XML for a STATUS_OK_REQUESTED response.
 *
 * @param  tag  Name of the command generating the response.
 */
#define XML_OK_REQUESTED(tag) "<" tag "_response status=\"" STATUS_OK_REQUESTED "\"/>"

/**
 * @brief Expand to XML for a STATUS_INTERNAL_ERROR response.
 *
 * @param  tag  Name of the command generating the response.
 */
#define XML_INTERNAL_ERROR(tag) "<" tag "_response status=\"" STATUS_INTERNAL_ERROR "\"/>"

/**
 * @brief Expand to XML for a STATUS_SERVICE_DOWN response.
 *
 * @param  tag  Name of the command generating the response.
 */
#define XML_SERVICE_DOWN(tag) "<" tag "_response status=\"" STATUS_SERVICE_DOWN "\"/>"

/**
 * @brief Find an attribute in a parser callback list of attributes.
 *
 * @param[in]   attribute_names   List of names.
 * @param[in]   attribute_values  List of values.
 * @param[in]   attribute_name    Name of sought attribute.
 * @param[out]  attribute_value   Attribute value return.
 *
 * @return 1 if found, else 0.
 */
int
find_attribute (const gchar **attribute_names,
                const gchar **attribute_values,
                const char *attribute_name,
                const gchar **attribute_value)
{
  while (*attribute_names && *attribute_values)
    if (strcmp (*attribute_names, attribute_name))
      attribute_names++, attribute_values++;
    else
      {
        *attribute_value = *attribute_values;
        return 1;
      }
  return 0;
}

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
                              const gchar **attribute_names,
                              const gchar **attribute_values,
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
            if (send_to_client (XML_ERROR_SYNTAX ("omp")))
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
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "task_id", &attribute))
              append_string (&current_uuid, attribute);
            set_client_state (CLIENT_ABORT_TASK);
          }
        else if (strncasecmp ("DELETE_CONFIG", element_name, 13) == 0)
          {
            assert (modify_task_name == NULL);
            append_string (&modify_task_name, "");
            set_client_state (CLIENT_DELETE_CONFIG);
          }
        else if (strncasecmp ("DELETE_REPORT", element_name, 13) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "report_id", &attribute))
              append_string (&current_uuid, attribute);
            set_client_state (CLIENT_DELETE_REPORT);
          }
        else if (strncasecmp ("DELETE_TARGET", element_name, 13) == 0)
          {
            assert (modify_task_name == NULL);
            append_string (&modify_task_name, "");
            set_client_state (CLIENT_DELETE_TARGET);
          }
        else if (strncasecmp ("DELETE_TASK", element_name, 11) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "task_id", &attribute))
              append_string (&current_uuid, attribute);
            set_client_state (CLIENT_DELETE_TASK);
          }
        else if (strncasecmp ("GET_CERTIFICATES", element_name, 16) == 0)
          set_client_state (CLIENT_GET_CERTIFICATES);
        else if (strncasecmp ("GET_CONFIGS", element_name, 11) == 0)
          set_client_state (CLIENT_GET_CONFIGS);
        else if (strncasecmp ("GET_DEPENDENCIES", element_name, 16) == 0)
          set_client_state (CLIENT_GET_DEPENDENCIES);
        else if (strncasecmp ("GET_NVT_ALL", element_name, 11) == 0)
          set_client_state (CLIENT_GET_NVT_ALL);
        else if (strncasecmp ("GET_NVT_FEED_CHECKSUM", element_name, 21) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "algorithm", &attribute))
              append_string (&current_uuid, attribute);
            set_client_state (CLIENT_GET_NVT_FEED_CHECKSUM);
          }
        else if (strncasecmp ("GET_NVT_DETAILS", element_name, 20) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "oid", &attribute))
              append_string (&current_uuid, attribute);
            set_client_state (CLIENT_GET_NVT_DETAILS);
          }
        else if (strncasecmp ("GET_PREFERENCES", element_name, 15) == 0)
          set_client_state (CLIENT_GET_PREFERENCES);
        else if (strncasecmp ("GET_REPORT", element_name, 10) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "report_id", &attribute))
              append_string (&current_uuid, attribute);
            if (find_attribute (attribute_names, attribute_values,
                                "format", &attribute))
              append_string (&current_format, attribute);
            set_client_state (CLIENT_GET_REPORT);
          }
        else if (strncasecmp ("GET_RULES", element_name, 9) == 0)
          set_client_state (CLIENT_GET_RULES);
        else if (strncasecmp ("GET_TARGETS", element_name, 11) == 0)
          set_client_state (CLIENT_GET_TARGETS);
        else if (strncasecmp ("HELP", element_name, 4) == 0)
          set_client_state (CLIENT_HELP);
        else if (strncasecmp ("MODIFY_REPORT", element_name, 13) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "report_id", &attribute))
              append_string (&current_uuid, attribute);
            set_client_state (CLIENT_MODIFY_REPORT);
          }
        else if (strncasecmp ("MODIFY_TASK", element_name, 11) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "task_id", &attribute))
              append_string (&current_uuid, attribute);
            set_client_state (CLIENT_MODIFY_TASK);
          }
        else if (strncasecmp ("CREATE_CONFIG", element_name, 13) == 0)
          {
            assert (modify_task_name == NULL);
            assert (modify_task_value == NULL);
            append_string (&modify_task_name, "");
            append_string (&modify_task_value, "");
            set_client_state (CLIENT_CREATE_CONFIG);
          }
        else if (strncasecmp ("CREATE_TASK", element_name, 11) == 0)
          {
            assert (current_client_task == (task_t) NULL);
            current_client_task = make_task (NULL, 0, NULL);
            if (current_client_task == (task_t) NULL) abort (); // FIX
            set_client_state (CLIENT_CREATE_TASK);
          }
        else if (strncasecmp ("CREATE_TARGET", element_name, 13) == 0)
          {
            assert (modify_task_name == NULL);
            assert (modify_task_value == NULL);
            append_string (&modify_task_name, "");
            append_string (&modify_task_value, "");
            set_client_state (CLIENT_CREATE_TARGET);
          }
        else if (strncasecmp ("GET_VERSION", element_name, 11) == 0)
          set_client_state (CLIENT_VERSION);
        else if (strncasecmp ("START_TASK", element_name, 10) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "task_id", &attribute))
              append_string (&current_uuid, attribute);
            set_client_state (CLIENT_START_TASK);
          }
        else if (strncasecmp ("GET_STATUS", element_name, 10) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "task_id", &attribute))
              append_string (&current_uuid, attribute);
            set_client_state (CLIENT_GET_STATUS);
          }
        else
          {
            if (send_to_client (XML_ERROR_SYNTAX ("omp")))
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
            if (send_to_client (XML_ERROR_SYNTAX ("authenticate")))
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
            if (send_to_client (XML_ERROR_SYNTAX ("authenticate")))
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

      case CLIENT_DELETE_CONFIG:
        if (strncasecmp ("NAME", element_name, 4) == 0)
          set_client_state (CLIENT_DELETE_CONFIG_NAME);
        else
          {
            if (send_to_client (XML_ERROR_SYNTAX ("delete_config")))
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

      case CLIENT_DELETE_REPORT:
        if (send_to_client (XML_ERROR_SYNTAX ("delete_report")))
          {
            error_send_to_client (error);
            return;
          }
        set_client_state (CLIENT_AUTHENTIC);
        g_set_error (error,
                     G_MARKUP_ERROR,
                     G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                     "Error");
        break;

      case CLIENT_DELETE_TARGET:
        if (strncasecmp ("NAME", element_name, 4) == 0)
          set_client_state (CLIENT_DELETE_TARGET_NAME);
        else
          {
            if (send_to_client (XML_ERROR_SYNTAX ("delete_target")))
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
        if (send_to_client (XML_ERROR_SYNTAX ("delete_task")))
          {
            error_send_to_client (error);
            return;
          }
        set_client_state (CLIENT_AUTHENTIC);
        g_set_error (error,
                     G_MARKUP_ERROR,
                     G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                     "Error");
        break;

      case CLIENT_GET_CERTIFICATES:
          {
            if (send_to_client (XML_ERROR_SYNTAX ("get_certificates")))
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

      case CLIENT_GET_CONFIGS:
          {
            if (send_to_client (XML_ERROR_SYNTAX ("get_configs")))
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
            if (send_to_client (XML_ERROR_SYNTAX ("get_dependencies")))
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
            if (send_to_client (XML_ERROR_SYNTAX ("get_nvt_all")))
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
            if (send_to_client (XML_ERROR_SYNTAX ("get_nvt_feed_checksum")))
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
        if (send_to_client (XML_ERROR_SYNTAX ("get_nvt_details")))
          {
            error_send_to_client (error);
            return;
          }
        set_client_state (CLIENT_AUTHENTIC);
        g_set_error (error,
                     G_MARKUP_ERROR,
                     G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                     "Error");
        break;

      case CLIENT_GET_PREFERENCES:
          {
            if (send_to_client (XML_ERROR_SYNTAX ("get_preferences")))
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
        if (send_to_client (XML_ERROR_SYNTAX ("get_report")))
          {
            error_send_to_client (error);
            return;
          }
        set_client_state (CLIENT_AUTHENTIC);
        g_set_error (error,
                     G_MARKUP_ERROR,
                     G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                     "Error");
        break;

      case CLIENT_GET_RULES:
          {
            if (send_to_client (XML_ERROR_SYNTAX ("get_rules")))
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

      case CLIENT_GET_TARGETS:
          {
            if (send_to_client (XML_ERROR_SYNTAX ("get_targets")))
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
          if (send_to_client (XML_ERROR_SYNTAX ("help")))
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
        if (strncasecmp ("PARAMETER", element_name, 9) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "id", &attribute))
              append_string (&modify_task_parameter, attribute);
            set_client_state (CLIENT_MODIFY_REPORT_PARAMETER);
          }
        else
          {
            if (send_to_client (XML_ERROR_SYNTAX ("modify_report")))
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
        if (strncasecmp ("COMMENT", element_name, 7) == 0)
          set_client_state (CLIENT_MODIFY_TASK_COMMENT);
        else if (strncasecmp ("NAME", element_name, 4) == 0)
          set_client_state (CLIENT_MODIFY_TASK_NAME);
        else if (strncasecmp ("PARAMETER", element_name, 9) == 0)
          {
            const gchar* attribute;
            if (find_attribute (attribute_names, attribute_values,
                                "id", &attribute))
              append_string (&modify_task_parameter, attribute);
            set_client_state (CLIENT_MODIFY_TASK_PARAMETER);
          }
        else if (strncasecmp ("RCFILE", element_name, 6) == 0)
          set_client_state (CLIENT_MODIFY_TASK_RCFILE);
        else
          {
            if (send_to_client (XML_ERROR_SYNTAX ("modify_task")))
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
#if 0
        if (strncasecmp ("CRITERION", element_name, 9) == 0)
          set_client_state (CLIENT_ABORT_TASK_CRITERION);
#else
        if (0)
          ;
#endif
        else
          {
            if (send_to_client (XML_ERROR_SYNTAX ("abort_task")))
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

      case CLIENT_CREATE_CONFIG:
        if (strncasecmp ("NAME", element_name, 4) == 0)
          set_client_state (CLIENT_CREATE_CONFIG_NAME);
        else if (strncasecmp ("RCFILE", element_name, 6) == 0)
          set_client_state (CLIENT_CREATE_CONFIG_RCFILE);
        else
          {
            if (send_to_client (XML_ERROR_SYNTAX ("create_config")))
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

      case CLIENT_CREATE_TARGET:
        if (strncasecmp ("HOSTS", element_name, 5) == 0)
          set_client_state (CLIENT_CREATE_TARGET_HOSTS);
        else if (strncasecmp ("NAME", element_name, 4) == 0)
          set_client_state (CLIENT_CREATE_TARGET_NAME);
        else
          {
            if (send_to_client (XML_ERROR_SYNTAX ("create_target")))
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
        if (strncasecmp ("RCFILE", element_name, 6) == 0)
          {
            /* Initialise the task description. */
            if (current_client_task
                && add_task_description_line (current_client_task, "", 0))
              abort (); // FIX out of mem
            set_client_state (CLIENT_CREATE_TASK_RCFILE);
          }
        else if (strncasecmp ("NAME", element_name, 4) == 0)
          set_client_state (CLIENT_CREATE_TASK_NAME);
        else if (strncasecmp ("COMMENT", element_name, 7) == 0)
          set_client_state (CLIENT_CREATE_TASK_COMMENT);
        else
          {
            if (send_to_client (XML_ERROR_SYNTAX ("create_task")))
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
        if (send_to_client (XML_ERROR_SYNTAX ("start_task")))
          {
            error_send_to_client (error);
            return;
          }
        set_client_state (CLIENT_AUTHENTIC);
        g_set_error (error,
                     G_MARKUP_ERROR,
                     G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                     "Error");
        break;

      case CLIENT_GET_STATUS:
        if (send_to_client (XML_ERROR_SYNTAX ("get_status")))
          {
            error_send_to_client (error);
            return;
          }
        set_client_state (CLIENT_AUTHENTIC);
        g_set_error (error,
                     G_MARKUP_ERROR,
                     G_MARKUP_ERROR_UNKNOWN_ELEMENT,
                     "Error");
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
 * @brief Send XML for a certificate.
 *
 * @param[in]  cert_gp  The certificate.
 * @param[in]  dummy    Dummy variable, for certificate_find.
 *
 * @return 0 if out of space in to_client buffer, else 1.
 */
static gint
send_certificate (gpointer cert_gp, gpointer dummy)
{
  certificate_t* cert = (certificate_t*) cert_gp;
  gchar* msg;
  gsize size_dummy;

  const char* public_key = certificate_public_key (cert);
  const char* owner = certificate_owner (cert);
  /* FIX The g_convert is a temp hack. */
  gchar* owner_utf8 = owner ? g_convert (owner, strlen (owner),
                                         "UTF-8", "ISO_8859-1",
                                         NULL, &size_dummy, NULL)
                            : NULL;
  gchar* owner_text = owner_utf8
                      ? g_markup_escape_text (owner_utf8, -1)
                      : g_strdup ("");
  g_free (owner_utf8);

  msg = g_strdup_printf ("<certificate>"
                         "<fingerprint>%s</fingerprint>"
                         "<owner>%s</owner>"
                         "<trust_level>%s</trust_level>"
                         "<length>%u</length>"
                         "<public_key>%s</public_key>"
                         "</certificate>",
                         certificate_fingerprint (cert),
                         owner_utf8,
                         certificate_trusted (cert) ? "trusted" : "notrust",
                         strlen (public_key),
                         public_key);
  g_free (owner_text);
  if (send_to_client (msg))
    {
      g_free (msg);
      return 0;
    }
  g_free (msg);
  return 1;
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
 * @brief Define a code snippet for send_plugin.
 *
 * @param  x  Prefix for names in snippet.
 */
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

      DEF (copyright);
      DEF (description);
      DEF (summary);
      DEF (family);
      DEF (version);
      DEF (tag);

#undef DEF

      msg = g_strdup_printf ("<nvt"
                             " oid=\"%s\">"
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
                             "<checksum>"
                             "<algorithm>md5</algorithm>"
                             // FIX implement
                             "2397586ea5cd3a69f953836f7be9ef7b"
                             "</checksum>"
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
    msg = g_strdup_printf ("<nvt"
                           " oid=\"%s\">"
                           "<name>%s</name>"
                           "<checksum>"
                           "<algorithm>md5</algorithm>"
                           // FIX implement
                           "2397586ea5cd3a69f953836f7be9ef7b"
                           "</checksum>"
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
 * @return 0 success, -4 out of space in to_client,
 *         -5 failed to get report counts, -6 failed to get timestamp.
 */
static int
send_reports (task_t task)
{
  iterator_t iterator;
  report_t index;

  init_report_iterator (&iterator, task);
  while (next_report (&iterator, &index))
    {
      gchar *uuid, *timestamp, *msg;
      int debugs, holes, infos, logs, warnings;

      uuid = report_uuid (index);

      if (report_counts (uuid,
                         &debugs, &holes, &infos, &logs,
                         &warnings))
        {
          free (uuid);
          return -5;
        }

      if (report_timestamp (uuid, &timestamp))
        {
          free (uuid);
          return -6;
        }

      tracef ("     %s\n", uuid);

      msg = g_strdup_printf ("<report"
                             " id=\"%s\">"
                             "<timestamp>%s</timestamp>"
                             "<messages>"
                             "<debug>%i</debug>"
                             "<hole>%i</hole>"
                             "<info>%i</info>"
                             "<log>%i</log>"
                             "<warning>%i</warning>"
                             "</messages>"
                             "</report>",
                             uuid,
                             timestamp,
                             debugs,
                             holes,
                             infos,
                             logs,
                             warnings);
      g_free (timestamp);
      if (send_to_client (msg))
        {
          g_free (msg);
          free (uuid);
          return -4;
        }
      g_free (msg);
      free (uuid);
    }
  cleanup_iterator (&iterator);

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
 * @param[in]   format    Format string for message.
 * @param[in]   args      Arguments for format string.
 */
#define SENDF_TO_CLIENT_OR_FAIL(format, args...)                             \
  do                                                                         \
    {                                                                        \
      gchar* msg = g_markup_printf_escaped (format , ## args);               \
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
 * @brief Print the XML for a report to a file.
 *
 * @param[in]   report    The report.
 * @param[in]   xml_file  File name.
 *
 * @return 0 on success, else -1 with errno set.
 */
static int
print_report_xml (report_t report, gchar* xml_file)
{
  FILE *out;
  iterator_t results, hosts;

  out = fopen (xml_file, "w");

  if (out == NULL)
    {
      g_warning ("%s: fopen failed: %s\n",
                 __FUNCTION__,
                 strerror (errno));
      return -1;
    }

  fprintf (out, "<get_report_response status=\"" STATUS_OK "\"><report>");

  fprintf (out,
           "<scan_start>%s</scan_start>",
           scan_start_time (report));

  init_host_iterator (&hosts, report);
  while (next (&hosts))
    fprintf (out,
             "<host_start><host>%s</host>%s</host_start>",
             host_iterator_host (&hosts),
             host_iterator_start_time (&hosts));
  cleanup_iterator (&hosts);

  init_result_iterator (&results, report, NULL);
  while (next (&results))
    {
      gchar *descr;

      descr = g_markup_escape_text (result_iterator_descr (&results), -1);
      fprintf (out,
               "<result>"
               "<subnet>%s</subnet>"
               "<host>%s</host>"
               "<port>%s</port>"
               "<nvt>%s</nvt>"
               "<type>%s</type>"
               "<description>%s</description>"
               "</result>",
               result_iterator_subnet (&results),
               result_iterator_host (&results),
               result_iterator_port (&results),
               result_iterator_nvt (&results),
               result_iterator_type (&results),
               descr);
      g_free (descr);
    }
  cleanup_iterator (&results);

  init_host_iterator (&hosts, report);
  while (next (&hosts))
    fprintf (out,
             "<host_end><host>%s</host>%s</host_end>",
             host_iterator_host (&hosts),
             host_iterator_end_time (&hosts));
  cleanup_iterator (&hosts);

  fprintf (out, "<scan_end>%s</scan_end>", scan_end_time (report));

  fprintf (out, "</report></get_report_response>");

  if (fclose (out))
    {
      g_warning ("%s: fclose failed: %s\n",
                 __FUNCTION__,
                 strerror (errno));
      return -1;
    }
  return 0;
}

/**
 * @brief Make text safe for LaTeX.
 *
 * Replace LaTeX special characters with LaTeX equivalents.
 *
 * @return A newly allocated version of text.
 */
static gchar*
latex_escape_text (const char *text)
{
  // TODO: Do this better.

  gsize left = strlen (text);
  gchar *new, *ch;

  /* Allocate buffer of a safe length. */
  {
    int bs = 0;
    const char *c = text;
    while (*c) { if (*c == '\\') bs++; c++; }
    new = g_strndup (text,
                     (left - bs) * 2 + bs * (strlen ("$\backslash$") - 1) + 1);
  }

  ch = new;
  while (*ch)
    {
      /* FIX \~ becomes \verb{~} or \~{} */
      if (*ch == '\\')
        {
          ch++;
          switch (*ch)
            {
              case 'r':
                {
                  /* \r is flushed */
                  memmove (ch - 1, ch + 1, left);
                  left--;
                  ch -= 2;
                  break;
                }
              case 'n':
                {
                  /* \n becomes "\n\n" (two newlines) */
                  left--;
                  *(ch - 1) = '\n';
                  *ch = '\n';
                  break;
                }
              default:
                {
                  /* \ becomes $\backslash$ */
                  memmove (ch - 1 + strlen ("$\backslash$"), ch - 1, left);
                  strncpy (ch - 1, "$\backslash$", strlen ("$\backslash$"));
                  ch += (strlen ("$\backslash$") - 1);
                  break;
                }
            }
        }
      else if (   *ch == '#' || *ch == '$' || *ch == '%'
               || *ch == '&' || *ch == '_' || *ch == '^'
               || *ch == '{' || *ch == '}')
        {
          ch++;
          switch (*ch)
            {
              case '\0':
                break;
              default:
                /* & becomes \& */
                memmove (ch, ch - 1, left);
                *(ch - 1) = '\\';
            }
        }
      ch++; left--;
    }
  return new;
}

/**
 * @brief Get the heading associated with a certain result severity.
 *
 * @param[in]  severity  The severity type.
 *
 * @return The heading associated with the given severity (for example,
 *         "Informational").
 */
const char*
latex_severity_heading (const char *severity)
{
  if (strcmp (severity, "Security Hole") == 0)
    return "Vulnerability";
  if (strcmp (severity, "Security Note") == 0)
    return "Informational";
  if (strcmp (severity, "Security Warning") == 0)
    return "Warning";
  return severity;
}

/**
 * @brief Get the colour associated with a certain result severity.
 *
 * @param[in]  severity  The severity type.
 *
 * @return The colour associated with the given severity (for example,
 *         "[rgb]{0.1,0.7,0}" or "{red}").
 */
const char*
latex_severity_colour (const char *severity)
{
  if (strcmp (severity, "Security Hole") == 0)
    return "{openvas_hole}";
  if (strcmp (severity, "Security Note") == 0)
    return "{openvas_note}";
  if (strcmp (severity, "Security Warning") == 0)
    return "{openavs_warning}";
  return severity;
}

/**
 * @brief Header for latex report.
 */
const char* latex_header
  = "\\documentclass{article}\n"
    "\\pagestyle{empty}\n"
    "\n"
    "%\\usepackage{color}\n"
    "\\usepackage{tabularx}\n"
    "\\usepackage{geometry}\n"
    "\\usepackage{comment}\n"
    "\\usepackage{titlesec}\n"
    "\\usepackage{chngpage}\n"
    "\\usepackage{calc}\n"
    "\\usepackage{url}\n"
    "\n"
    "\\usepackage{colortbl}\n"
    "\n"
    "% must come last\n"
    "\\usepackage{hyperref}\n"
    "\\definecolor{linkblue}{rgb}{0.11,0.56,1}\n"
    "\\definecolor{openvas_hole}{rgb}{0.80,0,0}\n"
    "\\definecolor{openvas_note}{rgb}{0.93,0.86,0.5}\n"
    "\\definecolor{openvas_report}{rgb}{0.68,0.74,0.88}\n"
    "\\definecolor{openvas_warning}{rgb}{0.93,0.60,0}\n"
    "\\hypersetup{colorlinks=true,linkcolor=linkblue,urlcolor=blue,bookmarks=true,bookmarksopen=true}\n"
    "\\usepackage[all]{hypcap}\n"
    "\n"
    "%\\geometry{verbose,a4paper,tmargin=24mm,bottom=24mm}\n"
    "\\geometry{verbose,a4paper}\n"
    "\\setlength{\\parskip}{\\smallskipamount}\n"
    "\\setlength{\\parindent}{0pt}\n"
    "\n"
    "\\title{OpenVAS Scan Report}\n"
    "\\pagestyle{headings}\n"
    "\\pagenumbering{arabic}\n"
    "\n"
    "\\begin{document}\n"
    "\n"
    "\\maketitle\n"
    "\n"
    "\\renewcommand{\\abstractname}{Summary}\n";

/**
 * @brief Header for latex report.
 */
const char* latex_footer
  = "\n"
    "\\begin{center}\n"
    "\\medskip\n"
    "\\rule{\\textwidth}{0.1pt}\n"
    "\n"
    "This file was generated by \\href{http://www.openvas.org/}{OpenVAS}, the free security scanner.\n"
    "\\end{center}\n"
    "\n"
    "\\end{document}\n";

/**
 * @brief Print LaTeX for a report to a file.
 *
 * @param[in]   report      The report.
 * @param[in]   latex_file  File name.
 *
 * @return 0 on success, else -1 with errno set.
 */
static int
print_report_latex (report_t report, gchar* latex_file)
{
  FILE *out;
  iterator_t results, hosts;
  int num_hosts = 0, total_holes = 0, total_notes = 0, total_warnings = 0;

  out = fopen (latex_file, "w");

  if (out == NULL)
    {
      g_warning ("%s: fopen failed: %s\n",
                 __FUNCTION__,
                 strerror (errno));
      return -1;
    }

  fputs (latex_header, out);

  fprintf (out,
           "\\begin{abstract}\n"
           "This document reports on the results of an OpenVAS security scan.\n"
           "The scan started at %s and ended at %s.  The\n"
           "report first summarises the results found.  Then, for each host,\n"
           "the report describes every issue found.  Please consider the\n"
           "advice given in each desciption, in order to rectify the issue.\n"
           "\\end{abstract}\n",
           scan_start_time (report),
           scan_end_time (report));

  /* Print the list of hosts. */

  fprintf (out,
           "\\section{Result Overview}\n"
           "\n"
           "\\begin{tabularx}{\\textwidth * 1}{|l|X|l|l|l|l|}\n"
           "\\hline\n"
           "\\rowcolor{openvas_report}"
           "Host&Most Severe Result(s)&Holes&Warnings&Notes&False Positives\\\\\n");

  init_host_iterator (&hosts, report);
  while (next (&hosts))
    {
      int holes, warnings, notes;
      const char *host = host_iterator_host (&hosts);

      report_holes (report, host, &holes);
      report_warnings (report, host, &warnings);
      report_notes (report, host, &notes);

      total_holes += holes;
      total_warnings += warnings;
      total_notes += notes;

      num_hosts++;
      fprintf (out,
               "\\hline\n"
               // FIX 0 (false positives)
               "\\hyperref[host:%s]{%s}&%s&%i&%i&%i&0\\\\\n",
               host,
               host,
               ((holes > 1) ? "Security Holes found"
                : ((holes == 1) ? "Security Hole found"
                   : ((warnings > 1) ? "Security Warnings found"
                      : ((warnings == 1) ? "Security Warning found"
                         : ((notes > 1) ? "Security Notes found"
                            : ((notes == 1) ? "Security Note found"
                               : "")))))),
               holes,
               warnings,
               notes);
    }
  cleanup_iterator (&hosts);

  fprintf (out,
           "\\hline\n"
           // FIX 0 (false positives)
           "Total: %i&&%i&%i&%i&0\\\\\n"
           "\\hline\n"
           "\\end{tabularx}\n"
           "\n"
           "\\section{Results per Host}\n"
           "\n",
           num_hosts,
           total_holes,
           total_warnings,
           total_notes);

  /* Print a section for each host. */

  init_host_iterator (&hosts, report);
  while (next (&hosts))
    {
      gchar *last_port;
      const char *host = host_iterator_host (&hosts);

      /* Print the times. */

      fprintf (out,
               "\\subsection{%s}\n"
               "\\label{host:%s}\n"
               "\n"
               "\\begin{tabular}{ll}\n"
               "Host scan start&%s\\\\\n"
               "Host scan end&%s\\\\\n"
               "\\end{tabular}\n\n",
               host,
               host,
               host_iterator_start_time (&hosts),
               host_iterator_end_time (&hosts));

      /* Print the result summary table. */

      fprintf (out,
               "\\begin{tabular}{|l|l|}\n"
               "\\hline\n"
               "\\rowcolor{openvas_report}Service (Port)&Issue regarding port\\\\\n"
               "\\hline\n");

      init_result_iterator (&results, report, host);
      last_port = NULL;
      /* Results are ordered by port, and then by severity (more severity
       * before less severe). */
      while (next (&results))
        {
          if (last_port
              && (strcmp (last_port, result_iterator_port (&results)) == 0))
            continue;
          if (last_port) g_free (last_port);
          last_port = g_strdup (result_iterator_port (&results));
          fprintf (out,
                   "\\hyperref[port:%s %s]{%s}&%s(s) found\\\\\n"
                   "\\hline\n",
                   host_iterator_host (&hosts),
                   last_port,
                   last_port,
                   result_iterator_type (&results));
        }
      cleanup_iterator (&results);
      if (last_port) g_free (last_port);

      fprintf (out,
               "\\end{tabular}\n"
               "\n"
               "%%\\subsection*{Security Issues and Fixes -- %s}\n\n",
               host_iterator_host (&hosts));

      /* Print the result details. */

      init_result_iterator (&results, report, host);
      last_port = NULL;
      /* Results are ordered by port, and then by severity (more severity
       * before less severe). */
      // FIX severity ordering is alphabetical on severity name
      while (next (&results))
        {
          gchar *descr;
          const char *severity;

          descr = latex_escape_text (result_iterator_descr (&results));

          if (last_port == NULL
              || strcmp (last_port, result_iterator_port (&results)))
            {
              if (last_port)
                {
                  fprintf (out,
                           "\\end{tabularx}\\\\\n"
                           "\\begin{footnotesize}"
                           "\\hyperref[host:%s]{[ return to %s ]}\n"
                           "\\end{footnotesize}"
                           "\\end{tabular}\n",
                           host,
                           host);
                  g_free (last_port);
                  last_port = NULL;
                }
              fprintf (out,
                       "\\subsubsection{%s}\n"
                       "\\label{port:%s %s}\n\n"
                       "\\begin{tabular}{l}\n"
                       "\\begin{tabularx}{\\textwidth * 1}{|X|}\n"
                       "\\hline\n",
                       result_iterator_port (&results),
                       host_iterator_host (&hosts),
                       result_iterator_port (&results));
            }
          if (last_port == NULL)
            last_port = g_strdup (result_iterator_port (&results));
          severity = result_iterator_type (&results);
          fprintf (out,
                   "\\rowcolor%s%s\\\\\n"
                   "\\hline\n"
                   "%s\\\\\n"
                   "OpenVAS ID: \\href{http://www.openvas.org/?oid=\"%s\"}{%s}\\\\\n"
                   "\\hline\n",
                   latex_severity_colour (severity),
                   latex_severity_heading (severity),
                   descr,
                   result_iterator_nvt (&results),
                   result_iterator_nvt (&results));

          g_free (descr);
        }
      if (last_port)
        {
          g_free (last_port);

          fprintf (out,
                   "\\end{tabularx}\n\\\\"
                   "\\begin{footnotesize}"
                   "\\hyperref[host:%s]{[ return to %s ]}"
                   "\\end{footnotesize}\n"
                   "\\end{tabular}\n",
                   host,
                   host);
        }
      cleanup_iterator (&results);
    }
  cleanup_iterator (&hosts);

  /* Close off. */

  fputs (latex_footer, out);

  if (fclose (out))
    {
      g_warning ("%s: fclose failed: %s\n",
                 __FUNCTION__,
                 strerror (errno));
      return -1;
    }
  return 0;
}

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
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("abort_task"));
            else if (task == 0)
              SEND_TO_CLIENT_OR_FAIL (XML_ERROR_MISSING ("abort_task"));
            else switch (stop_task (task))
              {
                case 0:   /* Stopped. */
                  SEND_TO_CLIENT_OR_FAIL (XML_OK ("abort_task"));
                  break;
                case 1:   /* Stop requested. */
                  SEND_TO_CLIENT_OR_FAIL (XML_OK_REQUESTED ("abort_task"));
                  break;
                default:  /* Programming error. */
                  assert (0);
                case -1:
                  /* to_server is full. */
                  // FIX revert parsing for retry
                  // process_omp_client_input must return -2
                  abort ();
              }
            free_string_var (&current_uuid);
          }
        else
          SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("abort_task"));
        set_client_state (CLIENT_AUTHENTIC);
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
                  g_warning ("%s: failed to load tasks\n", __FUNCTION__);
                  g_set_error (error, G_MARKUP_ERROR, G_MARKUP_ERROR_PARSE,
                               "Manager failed to load tasks.");
                  free_credentials (&current_credentials);
                  set_client_state (CLIENT_TOP);
                }
              else
                set_client_state (CLIENT_AUTHENTIC);
              break;
            case 1:
              SEND_TO_CLIENT_OR_FAIL (XML_ERROR_AUTH_FAILED ("authenticate"));
              free_credentials (&current_credentials);
              set_client_state (CLIENT_TOP);
              break;
            case -1:
            default:
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("authenticate"));
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
            SEND_TO_CLIENT_OR_FAIL ("<get_preferences_response"
                                    " status=\"" STATUS_OK "\">");
            if (g_hash_table_find (server.preferences, send_preference, NULL))
              {
                error_send_to_client (error);
                return;
              }
            SEND_TO_CLIENT_OR_FAIL ("</get_preferences_response>");
          }
        else
          SEND_TO_CLIENT_OR_FAIL (XML_SERVICE_DOWN ("get_preferences"));
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_GET_CERTIFICATES:
        if (server.certificates)
          {
            SEND_TO_CLIENT_OR_FAIL ("<get_certificates_response"
                                    " status=\"" STATUS_OK "\">");
            if (certificates_find (server.certificates,
                                   send_certificate,
                                   NULL))
              {
                error_send_to_client (error);
                return;
              }
            SEND_TO_CLIENT_OR_FAIL ("</get_certificates_response>");
          }
        else
          SEND_TO_CLIENT_OR_FAIL (XML_SERVICE_DOWN ("get_certificates"));
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_GET_DEPENDENCIES:
        if (server.plugins_dependencies)
          {
            SEND_TO_CLIENT_OR_FAIL ("<get_dependencies_response"
                                    " status=\"" STATUS_OK "\">");
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
          SEND_TO_CLIENT_OR_FAIL (XML_SERVICE_DOWN ("get_dependencies"));
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_GET_NVT_ALL:
        if (server.plugins)
          {
            SEND_TO_CLIENT_OR_FAIL ("<get_nvt_all_response"
                                    " status=\"" STATUS_OK "\">");
            SENDF_TO_CLIENT_OR_FAIL ("<nvt_count>%u</nvt_count>",
                                     nvtis_size (server.plugins));
            if (server.plugins_md5)
              {
                SEND_TO_CLIENT_OR_FAIL ("<feed_checksum algorithm=\"md5\">");
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
          SEND_TO_CLIENT_OR_FAIL (XML_SERVICE_DOWN ("get_nvt_all"));
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_GET_NVT_FEED_CHECKSUM:
        if (current_uuid && strcasecmp (current_uuid, "md5"))
          SEND_TO_CLIENT_OR_FAIL (XML_ERROR_MISSING ("get_nvt_feed_checksum"));
        else if (server.plugins_md5)
          {
            SEND_TO_CLIENT_OR_FAIL ("<get_nvt_feed_checksum_response"
                                    " status=\"" STATUS_OK "\">"
                                    "<checksum algorithm=\"md5\">");
            SEND_TO_CLIENT_OR_FAIL (server.plugins_md5);
            SEND_TO_CLIENT_OR_FAIL ("</checksum>"
                                    "</get_nvt_feed_checksum_response>");
          }
        else
          SEND_TO_CLIENT_OR_FAIL (XML_SERVICE_DOWN ("get_nvt_feed_checksum"));
        free_string_var (&current_uuid);
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_GET_NVT_DETAILS:
        if (server.plugins)
          {
            if (current_uuid)
              {
                nvti_t* plugin = nvtis_lookup (server.plugins, current_uuid);
                if (plugin)
                 {
                    SEND_TO_CLIENT_OR_FAIL ("<get_nvt_details_response"
                                            " status=\"" STATUS_OK "\">");
                    send_plugin (plugin->oid, plugin, (gpointer) 1);
                    SEND_TO_CLIENT_OR_FAIL ("</get_nvt_details_response>");
                  }
                else
                  SEND_TO_CLIENT_OR_FAIL
                   (XML_ERROR_MISSING ("get_nvt_details"));
              }
            else
              {
                SENDF_TO_CLIENT_OR_FAIL ("<get_nvt_details_response"
                                         " status=\"" STATUS_OK "\">"
                                         "<nvt_count>%u</nvt_count>",
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
                SEND_TO_CLIENT_OR_FAIL ("</get_nvt_details_response>");
              }
          }
        else
          SEND_TO_CLIENT_OR_FAIL (XML_SERVICE_DOWN ("get_nvt_details"));
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_DELETE_REPORT:
        assert (strncasecmp ("DELETE_REPORT", element_name, 13) == 0);
        SEND_TO_CLIENT_OR_FAIL ("<delete_report_response status=\"");
        if (current_uuid)
          {
            report_t report;

            // FIX check syntax of current_uuid  STATUS_ERROR_SYNTAX
            if (find_report (current_uuid, &report))
              SEND_TO_CLIENT_OR_FAIL (STATUS_INTERNAL_ERROR);
            else if (report == 0)
              SEND_TO_CLIENT_OR_FAIL (STATUS_ERROR_MISSING);
            else
              {
                int ret = delete_report (report);
                switch (ret)
                  {
                    case 0:
                      SEND_TO_CLIENT_OR_FAIL (STATUS_OK);
                      break;
                    default:
                      SEND_TO_CLIENT_OR_FAIL (STATUS_INTERNAL_ERROR);
                      break;
                  }
              }
            free_string_var (&current_uuid);
          }
        else
          SEND_TO_CLIENT_OR_FAIL (STATUS_ERROR_SYNTAX);
        SEND_TO_CLIENT_OR_FAIL ("\"/>");
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_GET_REPORT:
        assert (strncasecmp ("GET_REPORT", element_name, 10) == 0);
        if (current_credentials.username == NULL)
          {
            free_string_var (&current_uuid);
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_report"));
            set_client_state (CLIENT_AUTHENTIC);
            break;
          }

        if (current_uuid == NULL)
          SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("get_report"));
        else
          {
            report_t report;
            iterator_t results, hosts;
            GString *nbe;
            gchar *content, *base64_content;

            if (find_report (current_uuid, &report))
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_report"));
            else if (report == 0)
              SEND_TO_CLIENT_OR_FAIL (XML_ERROR_MISSING ("get_report"));
            else if (current_format == NULL
                     || strcasecmp (current_format, "xml") == 0)
              {
                SEND_TO_CLIENT_OR_FAIL ("<get_report_response"
                                        " status=\"" STATUS_OK "\">"
                                        "<report>");

                SENDF_TO_CLIENT_OR_FAIL ("<scan_start>%s</scan_start>",
                                         scan_start_time (report));

                init_host_iterator (&hosts, report);
                while (next (&hosts))
                  SENDF_TO_CLIENT_OR_FAIL ("<host_start><host>%s</host>%s</host_start>",
                                           host_iterator_host (&hosts),
                                           host_iterator_start_time (&hosts));
                cleanup_iterator (&hosts);

                init_result_iterator (&results, report, NULL);
                while (next (&results))
                  SENDF_TO_CLIENT_OR_FAIL ("<result>"
                                           "<subnet>%s</subnet>"
                                           "<host>%s</host>"
                                           "<port>%s</port>"
                                           "<nvt>%s</nvt>"
                                           "<type>%s</type>"
                                           "<description>%s</description>"
                                           "</result>",
                                           result_iterator_subnet (&results),
                                           result_iterator_host (&results),
                                           result_iterator_port (&results),
                                           result_iterator_nvt (&results),
                                           result_iterator_type (&results),
                                           result_iterator_descr (&results));
                cleanup_iterator (&results);

                init_host_iterator (&hosts, report);
                while (next (&hosts))
                  SENDF_TO_CLIENT_OR_FAIL ("<host_end><host>%s</host>%s</host_end>",
                                           host_iterator_host (&hosts),
                                           host_iterator_end_time (&hosts));
                cleanup_iterator (&hosts);

                SENDF_TO_CLIENT_OR_FAIL ("<scan_end>%s</scan_end>",
                                         scan_end_time (report));

                SEND_TO_CLIENT_OR_FAIL ("</report>"
                                        "</get_report_response>");
              }
            else if (strcasecmp (current_format, "nbe") == 0)
              {
                /* TODO: Encode and send in chunks, after each printf. */

                /* Build the NBE in memory. */

                nbe = g_string_new ("");
                g_string_append_printf (nbe,
                                        "timestamps|||scan_start|%s|\n",
                                        scan_start_time (report));

                init_host_iterator (&hosts, report);
                while (next (&hosts))
                  g_string_append_printf (nbe,
                                          "timestamps||%s|host_start|%s|\n",
                                          host_iterator_host (&hosts),
                                          host_iterator_start_time (&hosts));
                cleanup_iterator (&hosts);

                init_result_iterator (&results, report, NULL);
                while (next (&results))
                  g_string_append_printf (nbe,
                                          "results|%s|%s|%s|%s|%s|%s|\n",
                                          result_iterator_subnet (&results),
                                          result_iterator_host (&results),
                                          result_iterator_port (&results),
                                          result_iterator_nvt (&results),
                                          result_iterator_type (&results),
                                          result_iterator_descr (&results));
                cleanup_iterator (&results);

                init_host_iterator (&hosts, report);
                while (next (&hosts))
                  g_string_append_printf (nbe,
                                          "timestamps||%s|host_end|%s|\n",
                                          host_iterator_host (&hosts),
                                          host_iterator_end_time (&hosts));
                cleanup_iterator (&hosts);

                g_string_append_printf (nbe,
                                        "timestamps|||scan_end|%s|\n",
                                        scan_end_time (report));

                /* Encode and send the NBE. */

                SEND_TO_CLIENT_OR_FAIL ("<get_report_response"
                                        " status=\"" STATUS_OK "\">"
                                        "<report format=\"nbe\">");
                content = g_string_free (nbe, FALSE);
                base64_content = g_base64_encode ((guchar*) content,
                                                  strlen (content));
                g_free (content);
                if (send_to_client (base64_content))
                  {
                    g_free (base64_content);
                    error_send_to_client (error);
                    return;
                  }
                g_free (base64_content);
                SEND_TO_CLIENT_OR_FAIL ("</report>"
                                        "</get_report_response>");
              }
            else if (strcasecmp (current_format, "html") == 0)
              {
                gchar *xml_file;
                gint xml_fd;

                xml_file = g_strdup ("/tmp/openvasmd_xml_XXXXXX");

                xml_fd = g_mkstemp (xml_file);

                if (xml_fd == -1)
                  {
                    g_warning ("%s: g_mkstemp failed\n",
                               __FUNCTION__);
                    g_free (xml_file);
                    SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_report"));
                  }
                else if (print_report_xml (report, xml_file))
                  {
                    g_free (xml_file);
                    close (xml_fd);
                    SEND_TO_CLIENT_OR_FAIL (XML_ERROR_MISSING ("get_report"));
                  }
                else
                  {
                    gchar *xsl_file;

                    // TODO: Remove xml_file.

                    close (xml_fd);

                    xsl_file = g_build_filename (OPENVAS_SYSCONF_DIR,
                                                 "openvasmd_report_html.xsl",
                                                 NULL);
                    if (!g_file_test (xsl_file, G_FILE_TEST_EXISTS))
                      {
                        g_warning ("%s: XSL missing: %s\n",
                                   __FUNCTION__,
                                   xsl_file);
                        g_free (xsl_file);
                        g_free (xml_file);
                        SEND_TO_CLIENT_OR_FAIL (XML_ERROR_MISSING ("get_report"));
                      }
                    else
                      {
                        gchar *html_file, *command;
                        gint html_fd;
                        int ret;

                        // TODO: Remove html_file.

                        html_file = g_strdup ("/tmp/openvasmd_html_XXXXXX");

                        html_fd = g_mkstemp (html_file);

                        command = g_strdup_printf ("xsltproc -v %s %s -o %s 2> /dev/null",
                                                   xsl_file,
                                                   xml_file,
                                                   html_file);
                        g_free (xsl_file);
                        g_free (xml_file);

                        g_message ("   command: %s\n", command);

                        if (html_fd == -1)
                          {
                            g_warning ("%s: g_mkstemp failed\n",
                                       __FUNCTION__);
                            g_free (html_file);
                            SEND_TO_CLIENT_OR_FAIL
                             (XML_INTERNAL_ERROR ("get_report"));
                          }
                        else if (ret = system (command),
                                 // FIX ret is always -1
                                 0 && ((ret) == -1
                                       || WEXITSTATUS (ret)))
                          {
                            g_warning ("%s: system failed with ret %i, %i, %s\n",
                                       __FUNCTION__,
                                       ret,
                                       WEXITSTATUS (ret),
                                       command);
                            close (html_fd);
                            g_free (command);
                            g_free (html_file);
                            SEND_TO_CLIENT_OR_FAIL
                             (XML_INTERNAL_ERROR ("get_report"));
                          }
                        else
                          {
                            GError *get_error;
                            gchar *html;
                            gsize html_len;

                            close (html_fd);
                            g_free (command);

                            /* Send the HTML to the client. */

                            get_error = NULL;
                            g_file_get_contents (html_file,
                                                 &html,
                                                 &html_len,
                                                 &get_error);
                            g_free (html_file);
                            if (get_error)
                              {
                                g_warning ("%s: Failed to get HTML: %s\n",
                                           __FUNCTION__,
                                           get_error->message);
                                g_error_free (get_error);
                                SEND_TO_CLIENT_OR_FAIL
                                 (XML_INTERNAL_ERROR ("get_report"));
                              }
                            else
                              {
                                gchar *base64;

                                /* Encode and send the HTML. */

                                SEND_TO_CLIENT_OR_FAIL ("<get_report_response"
                                                        " status=\"" STATUS_OK "\">"
                                                        "<report format=\"html\">");
                                base64 = g_base64_encode ((guchar*) html,
                                                          html_len);
                                g_free (html);
                                if (send_to_client (base64))
                                  {
                                    g_free (base64);
                                    error_send_to_client (error);
                                    return;
                                  }
                                g_free (base64);
                                SEND_TO_CLIENT_OR_FAIL ("</report>"
                                                        "</get_report_response>");
                              }
                          }
                      }
                  }
              }
            else if (strcasecmp (current_format, "html-pdf") == 0)
              {
                gchar *xml_file;
                gint xml_fd;

                // TODO: This block is very similar to the HTML block above.

                xml_file = g_strdup ("/tmp/openvasmd_xml_XXXXXX");

                xml_fd = g_mkstemp (xml_file);

                if (xml_fd == -1)
                  {
                    g_warning ("%s: g_mkstemp failed\n",
                               __FUNCTION__);
                    g_free (xml_file);
                    SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_report"));
                  }
                else if (print_report_xml (report, xml_file))
                  {
                    g_free (xml_file);
                    close (xml_fd);
                    SEND_TO_CLIENT_OR_FAIL (XML_ERROR_MISSING ("get_report"));
                  }
                else
                  {
                    gchar *xsl_file;

                    // TODO: Remove xml_file.

                    close (xml_fd);

                    xsl_file = g_build_filename (OPENVAS_SYSCONF_DIR,
                                                 "openvasmd_report_html.xsl",
                                                 NULL);
                    if (!g_file_test (xsl_file, G_FILE_TEST_EXISTS))
                      {
                        g_warning ("%s: XSL missing: %s\n",
                                   __FUNCTION__,
                                   xsl_file);
                        g_free (xsl_file);
                        g_free (xml_file);
                        SEND_TO_CLIENT_OR_FAIL (XML_ERROR_MISSING ("get_report"));
                      }
                    else
                      {
                        gchar *pdf_file, *command;
                        gint pdf_fd;
                        int ret;

                        // TODO: Remove pdf_file.

                        pdf_file = g_strdup ("/tmp/openvasmd_pdf_XXXXXX");

                        pdf_fd = g_mkstemp (pdf_file);

                        command = g_strdup_printf ("xsltproc -v %s %s"
                                                   " 2> /dev/null"
                                                   " | tee /tmp/openvasmd_html"
                                                   " | htmldoc -t pdf --webpage -f %s -"
                                                   " 2> /dev/null",
                                                   xsl_file,
                                                   xml_file,
                                                   pdf_file);
                        g_free (xsl_file);
                        g_free (xml_file);

                        g_message ("   command: %s\n", command);

                        if (pdf_fd == -1)
                          {
                            g_warning ("%s: g_mkstemp failed\n",
                                       __FUNCTION__);
                            g_free (pdf_file);
                            SEND_TO_CLIENT_OR_FAIL
                             (XML_INTERNAL_ERROR ("get_report"));
                          }
                        else if (ret = system (command),
                                 // FIX ret is always -1
                                 0 && ((ret) == -1
                                       || WEXITSTATUS (ret)))
                          {
                            g_warning ("%s: system failed with ret %i, %i, %s\n",
                                       __FUNCTION__,
                                       ret,
                                       WEXITSTATUS (ret),
                                       command);
                            close (pdf_fd);
                            g_free (command);
                            g_free (pdf_file);
                            SEND_TO_CLIENT_OR_FAIL
                             (XML_INTERNAL_ERROR ("get_report"));
                          }
                        else
                          {
                            GError *get_error;
                            gchar *pdf;
                            gsize pdf_len;

                            close (pdf_fd);
                            g_free (command);

                            /* Send the PDF to the client. */

                            get_error = NULL;
                            g_file_get_contents (pdf_file,
                                                 &pdf,
                                                 &pdf_len,
                                                 &get_error);
                            g_free (pdf_file);
                            if (get_error)
                              {
                                g_warning ("%s: Failed to get PDF: %s\n",
                                           __FUNCTION__,
                                           get_error->message);
                                g_error_free (get_error);
                                SEND_TO_CLIENT_OR_FAIL
                                 (XML_INTERNAL_ERROR ("get_report"));
                              }
                            else
                              {
                                gchar *base64;

                                /* Encode and send the HTML. */

                                SEND_TO_CLIENT_OR_FAIL ("<get_report_response"
                                                        " status=\"" STATUS_OK "\">"
                                                        "<report format=\"pdf\">");
                                base64 = g_base64_encode ((guchar*) pdf,
                                                          pdf_len);
                                g_free (pdf);
                                if (send_to_client (base64))
                                  {
                                    g_free (base64);
                                    error_send_to_client (error);
                                    return;
                                  }
                                g_free (base64);
                                SEND_TO_CLIENT_OR_FAIL ("</report>"
                                                        "</get_report_response>");
                              }
                          }
                      }
                  }
              }
            else if (strcasecmp (current_format, "pdf") == 0)
              {
                gchar *latex_file;
                gint latex_fd;

                latex_file = g_strdup ("/tmp/openvasmd_XXXXXX.tex");

                latex_fd = g_mkstemp (latex_file);

                if (latex_fd == -1)
                  {
                    g_warning ("%s: g_mkstemp failed\n",
                               __FUNCTION__);
                    g_free (latex_file);
                    SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_report"));
                  }
                else if (print_report_latex (report, latex_file))
                  {
                    g_free (latex_file);
                    close (latex_fd);
                    SEND_TO_CLIENT_OR_FAIL (XML_ERROR_MISSING ("get_report"));
                  }
                else
                  {
                    // TODO: Remove latex_file.

                    close (latex_fd);

                    gchar *pdf_file, *command;
                    gint pdf_fd;
                    int ret;

                    // TODO: Remove pdf_file.

                    pdf_file = g_strdup (latex_file);
                    pdf_file[strlen (pdf_file) - 1] = 'f';
                    pdf_file[strlen (pdf_file) - 2] = 'd';
                    pdf_file[strlen (pdf_file) - 3] = 'p';

                    pdf_fd = open (pdf_file,
                                   O_RDWR | O_CREAT,
                                   S_IRUSR | S_IWUSR);

                    command = g_strdup_printf
                               ("pdflatex -output-directory /tmp/ %s"
                                " > /tmp/openvasmd_pdflatex_out 2>&1"
                                " && pdflatex -output-directory /tmp/ %s"
                                " > /tmp/openvasmd_pdflatex_out 2>&1",
                                latex_file,
                                latex_file);
                    g_free (latex_file);

                    g_message ("   command: %s\n", command);

                    if (pdf_fd == -1)
                      {
                        g_warning ("%s: open of %s failed\n",
                                   __FUNCTION__,
                                   pdf_file);
                        g_free (pdf_file);
                        SEND_TO_CLIENT_OR_FAIL
                         (XML_INTERNAL_ERROR ("get_report"));
                      }
                    else if (ret = system (command),
                             // FIX ret is always -1
                             0 && ((ret) == -1
                                   || WEXITSTATUS (ret)))
                      {
                        g_warning ("%s: system failed with ret %i, %i, %s\n",
                                   __FUNCTION__,
                                   ret,
                                   WEXITSTATUS (ret),
                                   command);
                        close (pdf_fd);
                        g_free (command);
                        g_free (pdf_file);
                        SEND_TO_CLIENT_OR_FAIL
                         (XML_INTERNAL_ERROR ("get_report"));
                      }
                    else
                      {
                        GError *get_error;
                        gchar *pdf;
                        gsize pdf_len;

                        close (pdf_fd);
                        g_free (command);

                        /* Send the PDF to the client. */

                        get_error = NULL;
                        g_file_get_contents (pdf_file,
                                             &pdf,
                                             &pdf_len,
                                             &get_error);
                        g_free (pdf_file);
                        if (get_error)
                          {
                            g_warning ("%s: Failed to get PDF: %s\n",
                                       __FUNCTION__,
                                       get_error->message);
                            g_error_free (get_error);
                            SEND_TO_CLIENT_OR_FAIL
                             (XML_INTERNAL_ERROR ("get_report"));
                          }
                        else
                          {
                            gchar *base64;

                            /* Encode and send the PDF. */

                            SEND_TO_CLIENT_OR_FAIL ("<get_report_response"
                                                    " status=\"" STATUS_OK "\">"
                                                    "<report format=\"pdf\">");
                            base64 = g_base64_encode ((guchar*) pdf,
                                                      pdf_len);
                            g_free (pdf);
                            if (send_to_client (base64))
                              {
                                g_free (base64);
                                error_send_to_client (error);
                                return;
                              }
                            g_free (base64);
                            SEND_TO_CLIENT_OR_FAIL ("</report>"
                                                    "</get_report_response>");
                          }
                      }
                  }
              }
            else
              SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("get_report"));
          }
        free_string_var (&current_uuid);
        free_string_var (&current_format);
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_GET_RULES:
        // FIX XML_SERVICE_DOWN?
        if (server.rules)
          {
            int index;
            SEND_TO_CLIENT_OR_FAIL ("<get_rules_response"
                                    " status=\"" STATUS_OK "\">");
            for (index = 0; index < server.rules_size; index++)
              if (send_rule (g_ptr_array_index (server.rules, index)))
                {
                  error_send_to_client (error);
                  return;
                }
            SEND_TO_CLIENT_OR_FAIL ("</get_rules_response>");
          }
        else
          SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_rules"));
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_VERSION:
        SEND_TO_CLIENT_OR_FAIL ("<get_version_response"
                                " status=\"" STATUS_OK "\">"
                                "<version preferred=\"yes\">1.0</version>"
                                "</get_version_response>");
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_DELETE_CONFIG:
        {
          assert (strncasecmp ("DELETE_CONFIG", element_name, 13) == 0);
          assert (modify_task_name != NULL);

          if (strlen (modify_task_name) == 0)
            {
              free_string_var (&modify_task_name);
              SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("delete_config"));
            }
          else if (delete_config (modify_task_name))
            {
              free_string_var (&modify_task_name);
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("delete_config"));
            }
          else
            {
              free_string_var (&modify_task_name);
              SEND_TO_CLIENT_OR_FAIL (XML_OK ("delete_config"));
            }
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      case CLIENT_DELETE_CONFIG_NAME:
        assert (strncasecmp ("NAME", element_name, 4) == 0);
        set_client_state (CLIENT_DELETE_CONFIG);
        break;

      case CLIENT_DELETE_TARGET:
        {
          assert (strncasecmp ("DELETE_TARGET", element_name, 13) == 0);
          assert (modify_task_name != NULL);

          if (strlen (modify_task_name) == 0)
            {
              free_string_var (&modify_task_name);
              SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("delete_target"));
            }
          else if (delete_target (modify_task_name))
            {
              free_string_var (&modify_task_name);
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("delete_target"));
            }
          else
            {
              free_string_var (&modify_task_name);
              SEND_TO_CLIENT_OR_FAIL (XML_OK ("delete_target"));
            }
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      case CLIENT_DELETE_TARGET_NAME:
        assert (strncasecmp ("NAME", element_name, 4) == 0);
        set_client_state (CLIENT_DELETE_TARGET);
        break;

      case CLIENT_DELETE_TASK:
        if (current_uuid)
          {
            assert (current_client_task == (task_t) NULL);
            task_t task;
            if (find_task (current_uuid, &task))
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("delete_task"));
            else if (task == 0)
              SEND_TO_CLIENT_OR_FAIL (XML_ERROR_MISSING ("delete_task"));
            else switch (request_delete_task (&task))
              {
                case 0:    /* Deleted. */
                  SEND_TO_CLIENT_OR_FAIL (XML_OK ("delete_task"));
                  break;
                case 1:    /* Delete requested. */
                  SEND_TO_CLIENT_OR_FAIL (XML_OK_REQUESTED ("delete_task"));
                  break;
                default:   /* Programming error. */
                  assert (0);
                case -1:
                  /* to_server is full. */
                  // FIX or some other error
                  // FIX revert parsing for retry
                  // process_omp_client_input must return -2
                  tracef ("delete_task failed\n");
                  abort ();
                  break;
              }
            free_string_var (&current_uuid);
          }
        else
          SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("delete_task"));
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_HELP:
        SEND_TO_CLIENT_OR_FAIL ("<help_response status=\"" STATUS_OK "\">");
        SEND_TO_CLIENT_OR_FAIL (help_text);
        SEND_TO_CLIENT_OR_FAIL ("</help_response>");
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_MODIFY_REPORT:
        if (modify_task_parameter != NULL
            && modify_task_value != NULL)
          {
            report_t report;

            if (current_uuid == NULL)
              SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("modify_report"));
            else if (find_report (current_uuid, &report))
              {
                free_string_var (&current_uuid);
                free_string_var (&modify_task_parameter);
                free_string_var (&modify_task_value);
                SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("modify_report"));
              }
            else if (report == 0)
              {
                free_string_var (&current_uuid);
                free_string_var (&modify_task_parameter);
                free_string_var (&modify_task_value);
                SEND_TO_CLIENT_OR_FAIL (XML_ERROR_MISSING ("modify_report"));
              }
            else
              {
                int ret = set_report_parameter (report,
                                                modify_task_parameter,
                                                modify_task_value);
                free_string_var (&modify_task_parameter);
                free_string_var (&modify_task_value);
                switch (ret)
                  {
                    case 0:
                      SEND_TO_CLIENT_OR_FAIL (XML_OK ("modify_report"));
                      break;
                    case -2: /* Parameter name error. */
                      SEND_TO_CLIENT_OR_FAIL
                       (XML_ERROR_SYNTAX ("modify_report"));
                      break;
                    case -3: /* Failed to write to disk. */
                    default:
                      SEND_TO_CLIENT_OR_FAIL
                       (XML_INTERNAL_ERROR ("modify_report"));
                      break;
                  }
              }
          }
        else
          {
            free_string_var (&modify_task_parameter);
            free_string_var (&modify_task_value);
            free_string_var (&current_uuid);
            SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("modify_report"));
          }
        set_client_state (CLIENT_AUTHENTIC);
        break;
      case CLIENT_MODIFY_REPORT_PARAMETER:
        assert (strncasecmp ("PARAMETER", element_name, 9) == 0);
        set_client_state (CLIENT_MODIFY_REPORT);
        break;

      case CLIENT_MODIFY_TASK:
        if (current_uuid)
          {
            assert (current_client_task == (task_t) NULL);
            task_t task;
            if (find_task (current_uuid, &task))
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("modify_task"));
            else if (task == 0)
              SEND_TO_CLIENT_OR_FAIL (XML_ERROR_MISSING ("modify_task"));
            else
              {
                int fail = 0, first = 1;

                /* \todo TODO: It'd probably be better to allow only one
                 * modification at a time, that is, one parameter or one of
                 * file, name and comment.  Otherwise a syntax error in a
                 * later part of the command would result in an error being
                 * returning while some part of the command actually
                 * succeeded. */

                if (modify_task_rcfile)
                  {
                    fail = set_task_parameter (task,
                                               "RCFILE",
                                               modify_task_rcfile);
                    modify_task_rcfile = NULL;
                    if (fail)
                      {
                        free_string_var (&modify_task_name);
                        free_string_var (&modify_task_comment);
                        free_string_var (&modify_task_parameter);
                        free_string_var (&modify_task_value);
                        if (fail == -4)
                          SEND_TO_CLIENT_OR_FAIL
                           (XML_INTERNAL_ERROR ("modify_task"));
                        else
                          SEND_TO_CLIENT_OR_FAIL
                           (XML_ERROR_SYNTAX ("modify_task"));
                      }
                    else
                      first = 0;
                  }

                if (fail == 0 && modify_task_name)
                  {
                    fail = set_task_parameter (task,
                                               "NAME",
                                               modify_task_name);
                    modify_task_name = NULL;
                    if (fail)
                      {
                        free_string_var (&modify_task_comment);
                        free_string_var (&modify_task_parameter);
                        free_string_var (&modify_task_value);
                        if (fail == -4)
                          SEND_TO_CLIENT_OR_FAIL
                           (XML_INTERNAL_ERROR ("modify_task"));
                        else
                          SEND_TO_CLIENT_OR_FAIL
                           (XML_ERROR_SYNTAX ("modify_task"));
                      }
                    else
                      first = 0;
                  }

                if (fail == 0 && modify_task_comment)
                  {
                    fail = set_task_parameter (task,
                                               "COMMENT",
                                               modify_task_comment);
                    modify_task_comment = NULL;
                    if (fail)
                      {
                        free_string_var (&modify_task_parameter);
                        free_string_var (&modify_task_value);
                        if (fail == -4)
                          SEND_TO_CLIENT_OR_FAIL
                           (XML_INTERNAL_ERROR ("modify_task"));
                        else
                          SEND_TO_CLIENT_OR_FAIL
                           (XML_ERROR_SYNTAX ("modify_task"));
                      }
                    else
                      first = 0;
                  }

                if (fail == 0)
                  {
                    if (modify_task_parameter && modify_task_value)
                      {
                        fail = set_task_parameter (task,
                                                   modify_task_parameter,
                                                   modify_task_value);
                        free_string_var (&modify_task_parameter);
                        modify_task_value = NULL;
                        if (fail)
                          {
                            if (fail == -4)
                              SEND_TO_CLIENT_OR_FAIL
                               (XML_INTERNAL_ERROR ("modify_task"));
                            else
                              SEND_TO_CLIENT_OR_FAIL
                               (XML_ERROR_SYNTAX ("modify_task"));
                          }
                        else
                          SEND_TO_CLIENT_OR_FAIL
                           (XML_OK ("modify_task"));
                      }
                    else if (first)
                      {
                        if (modify_task_value)
                          {
                            free_string_var (&modify_task_value);
                            SEND_TO_CLIENT_OR_FAIL
                             (XML_ERROR_SYNTAX ("modify_task"));
                          }
                        else if (modify_task_parameter)
                          {
                            free_string_var (&modify_task_parameter);
                            SEND_TO_CLIENT_OR_FAIL
                             (XML_INTERNAL_ERROR ("modify_task"));
                          }
                        else
                          SEND_TO_CLIENT_OR_FAIL (XML_OK ("modify_task"));
                      }
                    else
                      {
                        free_string_var (&modify_task_parameter);
                        free_string_var (&modify_task_value);
                        SEND_TO_CLIENT_OR_FAIL (XML_OK ("modify_task"));
                      }
                  }
              }
            free_string_var (&current_uuid);
          }
        else
          SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("modify_task"));
        set_client_state (CLIENT_AUTHENTIC);
        break;
      case CLIENT_MODIFY_TASK_PARAMETER:
        assert (strncasecmp ("PARAMETER", element_name, 9) == 0);
        set_client_state (CLIENT_MODIFY_TASK);
        break;
      case CLIENT_MODIFY_TASK_RCFILE:
        assert (strncasecmp ("RCFILE", element_name, 6) == 0);
        set_client_state (CLIENT_MODIFY_TASK);
        break;

      case CLIENT_CREATE_CONFIG:
        {
          assert (strncasecmp ("CREATE_CONFIG", element_name, 13) == 0);
          assert (modify_task_name != NULL);
          assert (modify_task_value != NULL);

          if (strlen (modify_task_name) == 0
              || strlen (modify_task_value) == 0)
            {
              free_string_var (&modify_task_name);
              free_string_var (&modify_task_value);
              SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("create_config"));
            }
          else
            {
              int ret;
              gsize base64_len;
              guchar *base64;

              base64 = g_base64_decode (modify_task_value, &base64_len);
              free_string_var (&modify_task_value);
              /* g_base64_decode can return NULL (Glib 2.12.4-2), at least
               * when modify_task_value is zero length. */
              if (base64 == NULL)
                {
                  base64 = (guchar*) g_strdup ("");
                  base64_len = 0;
                }

              ret = create_config (modify_task_name, (char*) base64);
              free_string_var (&modify_task_name);
              g_free (base64);
              if (ret)
                SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("create_config"));
              else
                SEND_TO_CLIENT_OR_FAIL (XML_OK_CREATED ("create_config"));
            }
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      case CLIENT_CREATE_CONFIG_NAME:
        assert (strncasecmp ("NAME", element_name, 4) == 0);
        set_client_state (CLIENT_CREATE_CONFIG);
        break;
      case CLIENT_CREATE_CONFIG_RCFILE:
        assert (strncasecmp ("RCFILE", element_name, 6) == 0);
        set_client_state (CLIENT_CREATE_CONFIG);
        break;

      case CLIENT_CREATE_TARGET:
        {
          assert (strncasecmp ("CREATE_TARGET", element_name, 13) == 0);
          assert (modify_task_name != NULL);
          assert (modify_task_value != NULL);

          if (strlen (modify_task_name) == 0
              || strlen (modify_task_value) == 0)
            {
              free_string_var (&modify_task_name);
              free_string_var (&modify_task_value);
              SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("create_target"));
            }
          else if (create_target (modify_task_name, modify_task_value))
            {
              free_string_var (&modify_task_name);
              free_string_var (&modify_task_value);
              SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("create_target"));
            }
          else
            {
              free_string_var (&modify_task_name);
              free_string_var (&modify_task_value);
              SEND_TO_CLIENT_OR_FAIL (XML_OK_CREATED ("create_target"));
            }
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
      case CLIENT_CREATE_TARGET_HOSTS:
        assert (strncasecmp ("HOSTS", element_name, 5) == 0);
        set_client_state (CLIENT_CREATE_TARGET);
        break;
      case CLIENT_CREATE_TARGET_NAME:
        assert (strncasecmp ("NAME", element_name, 4) == 0);
        set_client_state (CLIENT_CREATE_TARGET);
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
            SEND_TO_CLIENT_OR_FAIL (XML_ERROR_MISSING ("create_task"));
          else
            {
              gchar* msg;
              msg = g_strdup_printf ("<create_task_response"
                                     " status=\"" STATUS_OK_CREATED "\">"
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
      case CLIENT_CREATE_TASK_NAME:
        assert (strncasecmp ("NAME", element_name, 4) == 0);
        set_client_state (CLIENT_CREATE_TASK);
        break;
      case CLIENT_CREATE_TASK_RCFILE:
        assert (strncasecmp ("RCFILE", element_name, 6) == 0);
        if (current_client_task)
          {
            gsize out_len;
            guchar* out;
            char* description = task_description (current_client_task);
            if (description)
              {
                out = g_base64_decode (description, &out_len);
                /* g_base64_decode can return NULL (Glib 2.12.4-2), at least
                 * when description is zero length. */
                if (out == NULL)
                  {
                    out = (guchar*) g_strdup ("");
                    out_len = 0;
                  }
              }
            else
              {
                out = (guchar*) g_strdup ("");
                out_len = 0;
              }
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
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("start_task"));
            else if (task == 0)
              SEND_TO_CLIENT_OR_FAIL (XML_ERROR_MISSING ("start_task"));
            else
              switch (start_task (task))
                {
                  case -1:
                    /* to_server is full. */
                    // FIX or other error
                    // FIX revert parsing for retry
                    // process_omp_client_input must return -2
                    abort ();
                    break;
                  case -2:
                    /* Task definition missing or lacks targets. */
                    SEND_TO_CLIENT_OR_FAIL (XML_ERROR_MISSING ("start_task"));
                    break;
                  default:
                    SEND_TO_CLIENT_OR_FAIL (XML_OK_REQUESTED ("start_task"));
                    break;
                }
            free_string_var (&current_uuid);
          }
        else
          SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("start_task"));
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_GET_STATUS:
        assert (strncasecmp ("GET_STATUS", element_name, 10) == 0);
        if (current_uuid && strlen (current_uuid))
          {
            task_t task;
            if (find_task (current_uuid, &task))
              SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_status"));
            else if (task == 0)
              SEND_TO_CLIENT_OR_FAIL (XML_ERROR_MISSING ("get_status"));
            else
              {
                char* tsk_uuid;

                if (task_uuid (task, &tsk_uuid))
                  SEND_TO_CLIENT_OR_FAIL (XML_INTERNAL_ERROR ("get_status"));
                else
                  {
                    int ret;
                    gchar *response, *progress_xml;
                    char* name;
                    gchar *last_report_id, *last_report;
                    gchar *second_last_report_id, *second_last_report;
                    report_t running_report;

                    last_report_id = task_last_report_id (task);
                    if (last_report_id)
                      {
                        int debugs, holes, infos, logs, warnings;
                        gchar *timestamp;

                        if (report_counts (last_report_id,
                                           &debugs, &holes, &infos, &logs,
                                           &warnings))
                          abort (); // FIX fail better

                        if (report_timestamp (last_report_id, &timestamp))
                          abort (); // FIX fail better

                        last_report = g_strdup_printf ("<last_report>"
                                                       "<report id=\"%s\">"
                                                       "<timestamp>"
                                                       "%s"
                                                       "</timestamp>"
                                                       "<messages>"
                                                       "<debug>%i</debug>"
                                                       "<hole>%i</hole>"
                                                       "<info>%i</info>"
                                                       "<log>%i</log>"
                                                       "<warning>%i</warning>"
                                                       "</messages>"
                                                       "</report>"
                                                       "</last_report>",
                                                       last_report_id,
                                                       timestamp,
                                                       debugs,
                                                       holes,
                                                       infos,
                                                       logs,
                                                       warnings);
                        g_free (timestamp);
                        g_free (last_report_id);
                      }
                    else
                      last_report = g_strdup ("");

                    second_last_report_id = task_second_last_report_id (task);
                    if (second_last_report_id)
                      {
                        int debugs, holes, infos, logs, warnings;
                        gchar *timestamp;

                        if (report_counts (second_last_report_id,
                                           &debugs, &holes, &infos, &logs,
                                           &warnings))
                          abort (); // FIX fail better

                        if (report_timestamp (second_last_report_id,
                                              &timestamp))
                          abort (); // FIX fail better

                        second_last_report = g_strdup_printf
                                              ("<second_last_report>"
                                               "<report id=\"%s\">"
                                               "<timestamp>"
                                               "%s"
                                               "</timestamp>"
                                               "<messages>"
                                               "<debug>%i</debug>"
                                               "<hole>%i</hole>"
                                               "<info>%i</info>"
                                               "<log>%i</log>"
                                               "<warning>%i</warning>"
                                               "</messages>"
                                               "</report>"
                                               "</second_last_report>",
                                               second_last_report_id,
                                               timestamp,
                                               debugs,
                                               holes,
                                               infos,
                                               logs,
                                               warnings);
                        g_free (timestamp);
                        g_free (second_last_report_id);
                      }
                    else
                      second_last_report = g_strdup ("");

                    running_report = task_running_report (task);
                    if (running_report)
                      {
                        long total = 0;
                        int num_hosts = 0;
                        iterator_t hosts;
                        GString *string = g_string_new ("");

                        init_host_iterator (&hosts, running_report);
                        while (next (&hosts))
                          {
                            unsigned int max_port, current_port;
                            long progress;

                            max_port = host_iterator_max_port (&hosts);
                            current_port = host_iterator_current_port (&hosts);
                            if (max_port)
                              {
                                progress = (current_port * 100) / max_port;
                                if (progress < 0) progress = 0;
                                else if (progress > 100) progress = 100;
                              }
                            else
                              progress = current_port ? 100 : 0;
                            total += progress;
                            num_hosts++;

                            g_string_append_printf (string,
                                                    "<progress>"
                                                    "<host>%s</host>"
                                                    "%li"
                                                    "</progress>",
                                                    host_iterator_host (&hosts),
                                                    progress);
                          }
                        cleanup_iterator (&hosts);

                        g_string_append_printf (string,
                                                "%li",
                                                num_hosts ? (total / num_hosts)
                                                          : 0);
                        progress_xml = g_string_free (string, FALSE);
                      }
                    else
                      progress_xml = g_strdup ("-1");

                    name = task_name (task);
                    response = g_strdup_printf ("<get_status_response"
                                                " status=\"" STATUS_OK "\">"
                                                "<task id=\"%s\">"
                                                "<name>%s</name>"
                                                "<status>%s</status>"
                                                "<progress>%s</progress>"
                                                "<messages>"
                                                "<debug>%i</debug>"
                                                "<hole>%i</hole>"
                                                "<info>%i</info>"
                                                "<log>%i</log>"
                                                "<warning>%i</warning>"
                                                "</messages>"
                                                "<report_count>%u</report_count>"
                                                "%s%s",
                                                tsk_uuid,
                                                name,
                                                task_run_status_name (task),
                                                progress_xml,
                                                task_debugs_size (task),
                                                task_holes_size (task),
                                                task_infos_size (task),
                                                task_logs_size (task),
                                                task_notes_size (task),
                                                task_report_count (task),
                                                last_report,
                                                second_last_report);
                    g_free (progress_xml);
                    g_free (last_report);
                    g_free (second_last_report);
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
                    SEND_TO_CLIENT_OR_FAIL ("</task>"
                                            "</get_status_response>");
                  }
              }
            free_string_var (&current_uuid);
          }
        else if (current_uuid)
          SEND_TO_CLIENT_OR_FAIL (XML_ERROR_SYNTAX ("get_status"));
        else
          {
            gchar* response;
            task_iterator_t iterator;
            task_t index;

            // TODO: A lot of this block is the same as the one above.

            free_string_var (&current_uuid);

            SEND_TO_CLIENT_OR_FAIL ("<get_status_response"
                                    " status=\"" STATUS_OK "\">");
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
                gchar *line, *progress_xml;
                char* name = task_name (index);
                char* tsk_uuid;
                gchar *last_report_id, *last_report;
                gchar *second_last_report_id, *second_last_report;
                report_t running_report;

                // FIX buffer entire response so this can respond on err
                if (task_uuid (index, &tsk_uuid)) abort ();

                last_report_id = task_last_report_id (index);
                if (last_report_id)
                  {
                    int debugs, holes, infos, logs, warnings;
                    gchar *timestamp;

                    if (report_counts (last_report_id,
                                       &debugs, &holes, &infos, &logs,
                                       &warnings))
                      abort (); // FIX fail better

                    if (report_timestamp (last_report_id, &timestamp))
                      abort ();

                    last_report = g_strdup_printf ("<last_report>"
                                                   "<report id=\"%s\">"
                                                   "<timestamp>%s</timestamp>"
                                                   "<messages>"
                                                   "<debug>%i</debug>"
                                                   "<hole>%i</hole>"
                                                   "<info>%i</info>"
                                                   "<log>%i</log>"
                                                   "<warning>%i</warning>"
                                                   "</messages>"
                                                   "</report>"
                                                   "</last_report>",
                                                   last_report_id,
                                                   timestamp,
                                                   debugs,
                                                   holes,
                                                   infos,
                                                   logs,
                                                   warnings);
                    g_free (timestamp);
                    g_free (last_report_id);
                  }
                else
                  last_report = g_strdup ("");

                second_last_report_id = task_second_last_report_id (index);
                if (second_last_report_id)
                  {
                    int debugs, holes, infos, logs, warnings;
                    gchar *timestamp;

                    if (report_counts (second_last_report_id,
                                       &debugs, &holes, &infos, &logs,
                                       &warnings))
                      abort (); // FIX fail better

                    if (report_timestamp (second_last_report_id, &timestamp))
                      abort ();

                    second_last_report = g_strdup_printf
                                          ("<second_last_report>"
                                           "<report id=\"%s\">"
                                           "<timestamp>%s</timestamp>"
                                           "<messages>"
                                           "<debug>%i</debug>"
                                           "<hole>%i</hole>"
                                           "<info>%i</info>"
                                           "<log>%i</log>"
                                           "<warning>%i</warning>"
                                           "</messages>"
                                           "</report>"
                                           "</second_last_report>",
                                           second_last_report_id,
                                           timestamp,
                                           debugs,
                                           holes,
                                           infos,
                                           logs,
                                           warnings);
                    g_free (timestamp);
                    g_free (second_last_report_id);
                  }
                else
                  second_last_report = g_strdup ("");

                running_report = task_running_report (index);
                if (running_report)
                  {
                    long total = 0;
                    int num_hosts = 0;
                    iterator_t hosts;
                    GString *string = g_string_new ("");

                    init_host_iterator (&hosts, running_report);
                    while (next (&hosts))
                      {
                        unsigned int max_port, current_port;
                        long progress;

                        max_port = host_iterator_max_port (&hosts);
                        current_port = host_iterator_current_port (&hosts);
                        if (max_port)
                          {
                            progress = (current_port * 100) / max_port;
                            if (progress < 0) progress = 0;
                            else if (progress > 100) progress = 100;
                          }
                        else
                          progress = current_port ? 100 : 0;
                        total += progress;
                        num_hosts++;

                        g_string_append_printf (string,
                                                "<progress>"
                                                "<host>%s</host>"
                                                "%li"
                                                "</progress>",
                                                host_iterator_host (&hosts),
                                                progress);
                      }
                    cleanup_iterator (&hosts);

                    g_string_append_printf (string,
                                            "%li",
                                            num_hosts ? (total / num_hosts)
                                                      : 0);
                    progress_xml = g_string_free (string, FALSE);
                  }
                else
                  progress_xml = g_strdup ("-1");

                line = g_strdup_printf ("<task"
                                        " id=\"%s\">"
                                        "<name>%s</name>"
                                        "<status>%s</status>"
                                        "<progress>%s</progress>"
                                        "<messages>"
                                        "<debug>%i</debug>"
                                        "<hole>%i</hole>"
                                        "<info>%i</info>"
                                        "<log>%i</log>"
                                        "<warning>%i</warning>"
                                        "</messages>"
                                        "<report_count>%u</report_count>"
                                        "%s%s"
                                        "</task>",
                                        tsk_uuid,
                                        name,
                                        task_run_status_name (index),
                                        progress_xml,
                                        task_debugs_size (index),
                                        task_holes_size (index),
                                        task_infos_size (index),
                                        task_logs_size (index),
                                        task_notes_size (index),
                                        task_report_count (index),
                                        last_report,
                                        second_last_report);
                g_free (progress_xml);
                g_free (last_report);
                g_free (second_last_report);
                free (name);
                free (tsk_uuid);
                if (send_to_client (line))
                  {
                    g_free (line);
                    error_send_to_client (error);
                    cleanup_task_iterator (&iterator);
                    return;
                  }
                g_free (line);
              }
            cleanup_task_iterator (&iterator);
            SEND_TO_CLIENT_OR_FAIL ("</get_status_response>");
          }
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_GET_CONFIGS:
        {
          iterator_t configs;
          assert (strncasecmp ("GET_CONFIGS", element_name, 11) == 0);

          SEND_TO_CLIENT_OR_FAIL ("<get_configs_response>");
          init_config_iterator (&configs);
          while (next (&configs))
            {
              const char *selector;
              selector = config_iterator_nvt_selector (&configs);
              SENDF_TO_CLIENT_OR_FAIL ("<config>"
                                       "<name>%s</name>"
                                       "<family_count>"
                                       "-1<growing>%i</growing>"
                                       "</family_count>"
                                       "<nvt_count>"
                                       "-1<growing>%i</growing>"
                                       "</nvt_count>"
                                       "</config>",
                                       config_iterator_name (&configs),
                                       nvt_selector_families_growing (selector),
                                       nvt_selector_nvts_growing (selector));
            }
          cleanup_iterator (&configs);
          SEND_TO_CLIENT_OR_FAIL ("</get_configs_response>");
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }

      case CLIENT_GET_TARGETS:
        {
          iterator_t targets;
          assert (strncasecmp ("GET_TARGETS", element_name, 11) == 0);

          SEND_TO_CLIENT_OR_FAIL ("<get_targets_response>");
          init_target_iterator (&targets);
          while (next (&targets))
            SENDF_TO_CLIENT_OR_FAIL ("<target>"
                                     "<name>%s</name><hosts>%s</hosts>"
                                     "</target>",
                                     target_iterator_name (&targets),
                                     target_iterator_hosts (&targets));
          cleanup_iterator (&targets);
          SEND_TO_CLIENT_OR_FAIL ("</get_targets_response>");
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }

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
        append_text (&modify_task_value, text, text_len);
        break;

      case CLIENT_MODIFY_TASK_COMMENT:
        append_text (&modify_task_comment, text, text_len);
        break;
      case CLIENT_MODIFY_TASK_NAME:
        append_text (&modify_task_name, text, text_len);
        break;
      case CLIENT_MODIFY_TASK_PARAMETER:
        append_text (&modify_task_value, text, text_len);
        break;
      case CLIENT_MODIFY_TASK_RCFILE:
        append_text (&modify_task_rcfile, text, text_len);
        break;

      case CLIENT_CREDENTIALS_USERNAME:
        append_to_credentials_username (&current_credentials, text, text_len);
        break;
      case CLIENT_CREDENTIALS_PASSWORD:
        append_to_credentials_password (&current_credentials, text, text_len);
        break;

      case CLIENT_CREATE_CONFIG_NAME:
        append_text (&modify_task_name, text, text_len);
        break;
      case CLIENT_CREATE_CONFIG_RCFILE:
        append_text (&modify_task_value, text, text_len);
        break;

      case CLIENT_CREATE_TARGET_HOSTS:
        append_text (&modify_task_value, text, text_len);
        break;
      case CLIENT_CREATE_TARGET_NAME:
        append_text (&modify_task_name, text, text_len);
        break;

      case CLIENT_CREATE_TASK_COMMENT:
        append_to_task_comment (current_client_task, text, text_len);
        break;
      case CLIENT_CREATE_TASK_NAME:
        append_to_task_name (current_client_task, text, text_len);
        break;
      case CLIENT_CREATE_TASK_RCFILE:
        /* Append the text to the task description. */
        if (add_task_description_line (current_client_task,
                                       text,
                                       text_len))
          abort (); // FIX out of mem
        break;

      case CLIENT_DELETE_CONFIG_NAME:
      case CLIENT_DELETE_TARGET_NAME:
        append_text (&modify_task_name, text, text_len);
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
init_omp (GSList *log_config)
{
  g_log_set_handler (G_LOG_DOMAIN,
                     ALL_LOG_LEVELS,
                     (GLogFunc) openvas_log_func,
                     log_config);
  return init_manage (log_config);
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
 *         or \ref to_server (respectively), -4 XML syntax error.
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
      int err;
      if (error)
        {
          err = -4;
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
          else
            err = -1;
          g_message ("   Failed to parse client XML: %s\n", error->message);
          g_error_free (error);
        }
      else
        err = -1;
      /* In all error cases the caller must cease to call this function as it
       * would be too hard, if possible at all, to figure out the position of
       * start of the next command. */
      return err;
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
