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

#ifdef S_SPLINT_S
#include "splint.h"
#endif

/**
 * @brief Installation prefix.
 */
#ifndef PREFIX
#define PREFIX ""
#endif

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
 * @brief Current client task during OMP commands like NEW_TASK and MODIFY_TASK.
 */
/*@null@*/ /*@dependent@*/
static task_t current_client_task = NULL;

/**
 * @brief Task ID during OMP MODIFY_TASK and START_TASK.
 */
static /*@null@*/ /*@only@*/ char*
current_task_task_id = NULL;

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
  CLIENT_GET_NVT_FEED_ALL,
  CLIENT_GET_NVT_FEED_CHECKSUM,
  CLIENT_GET_NVT_FEED_DETAILS,
  CLIENT_GET_PREFERENCES,
  CLIENT_GET_REPORT,
  CLIENT_GET_REPORT_ID,
  CLIENT_GET_RULES,
  CLIENT_MODIFY_REPORT,
  CLIENT_MODIFY_REPORT_REPORT_ID,
  CLIENT_MODIFY_REPORT_PARAMETER,
  CLIENT_MODIFY_REPORT_VALUE,
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
  tracef ("   XML  start: %s\n", element_name);

  switch (client_state)
    {
      case CLIENT_TOP:
        if (strncasecmp ("AUTHENTICATE", element_name, 10) == 0)
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
            if (send_to_client ("<omp_response>"
                                "<status>401</status>"
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
        if (strncasecmp ("AUTHENTICATE", element_name, 10) == 0)
          {
            // FIX Could check if reauthenticating current credentials, to
            // save the loading of the tasks.
            if (save_tasks ()) abort ();
            free_tasks ();
            free_credentials (&current_credentials);
            set_client_state (CLIENT_AUTHENTICATE);
          }
        else if (strncasecmp ("ABORT_TASK", element_name, 10) == 0)
          set_client_state (CLIENT_ABORT_TASK);
        else if (strncasecmp ("DELETE_REPORT", element_name, 13) == 0)
          set_client_state (CLIENT_DELETE_REPORT);
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
        else if (strncasecmp ("GET_REPORT", element_name, 10) == 0)
          set_client_state (CLIENT_GET_REPORT);
        else if (strncasecmp ("GET_RULES", element_name, 9) == 0)
          set_client_state (CLIENT_GET_RULES);
        else if (strncasecmp ("MODIFY_REPORT", element_name, 13) == 0)
          set_client_state (CLIENT_MODIFY_REPORT);
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
          set_client_state (CLIENT_STATUS);
        else
          {
            if (send_to_client ("<omp_response>"
                                "<status>402</status>"
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
                                "<status>402</status>"
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
                                "<status>402</status>"
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
                                "<status>402</status>"
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
                                "<status>402</status>"
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
                                "<status>402</status>"
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

      case CLIENT_GET_NVT_FEED_ALL:
          {
            if (send_to_client ("<get_nvt_feed_all>"
                                "<status>402</status>"
                                "</get_nvt_feed_all>"))
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
                                "<status>402</status>"
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

      case CLIENT_GET_NVT_FEED_DETAILS:
          {
            if (send_to_client ("<get_nvt_feed_details>"
                                "<status>402</status>"
                                "</get_nvt_feed_details>"))
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
                                "<status>402</status>"
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
                                "<status>402</status>"
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
                                "<status>402</status>"
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
                                "<status>402</status>"
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
                                "<status>402</status>"
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
                                "<status>402</status>"
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

      case CLIENT_NEW_TASK:
        if (strncasecmp ("TASK_FILE", element_name, 9) == 0)
          set_client_state (CLIENT_NEW_TASK_TASK_FILE);
        else if (strncasecmp ("IDENTIFIER", element_name, 10) == 0)
          set_client_state (CLIENT_NEW_TASK_IDENTIFIER);
        else if (strncasecmp ("COMMENT", element_name, 7) == 0)
          set_client_state (CLIENT_NEW_TASK_COMMENT);
        else
          {
            if (send_to_client ("<new_task_response>"
                                "<status>402</status>"
                                "</new_task_response>"))
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
                                "<status>402</status>"
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
                                "<status>402</status>"
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
 * @return 0 success, -1 task name error, -2 credentials missing,
 *         failed to open task dir, -4 out of space in to_client.
 */
static int
send_reports (task_t task)
{
  // FIX Abstract report iterator and move it to manage.c.

  gchar* dir_name;
  const char* id;
  struct dirent ** names;
  int count, index;
  gchar* msg;

  // FIX return error code?
  if (task_id_string (task, &id)) return -1;

  // FIX return error code
  if (current_credentials.username == NULL) return -2;

  dir_name = g_build_filename (PREFIX
                               "/var/lib/openvas/mgr/users/",
                               current_credentials.username,
                               "tasks",
                               id,
                               "reports",
                               NULL);

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
        if (current_task_task_id)
          {
            assert (current_client_task == NULL);
            task_t task;
            if (find_task (current_task_task_id, &task))
              SEND_TO_CLIENT_OR_FAIL ("<abort_task_response>"
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
              SEND_TO_CLIENT_OR_FAIL ("<abort_task_response>"
                                      "<status>201</status>"
                                      "</abort_task_response>");
            free_string_var (&current_task_task_id);
          }
        else
          SEND_TO_CLIENT_OR_FAIL ("<status>50x</status>");
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
            SEND_TO_CLIENT_OR_FAIL ("<authenticate_response>"
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
            SEND_TO_CLIENT_OR_FAIL ("<get_preferences_response>"
                                    "<status>200</status>");
            if (g_hash_table_find (server.preferences, send_preference, NULL))
              {
                error_send_to_client (error);
                return;
              }
            SEND_TO_CLIENT_OR_FAIL ("</get_preferences_response>");
          }
        else
          SEND_TO_CLIENT_OR_FAIL ("<get_preferences_response>"
                                  "<status>500</status>"
                                  "</get_preferences_response>");
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_GET_DEPENDENCIES:
        if (server.plugins_dependencies)
          {
            SEND_TO_CLIENT_OR_FAIL ("<get_dependencies_response>"
                                    "<status>200</status>");
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
                                  "<status>500</status>"
                                  "</get_dependencies_response>");
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_GET_NVT_FEED_ALL:
        SEND_TO_CLIENT_OR_FAIL ("<get_nvt_feed_all_response>"
                                "<status>200</status>");
        // FIX
        SEND_TO_CLIENT_OR_FAIL ("<nvt_count>2</nvt_count>");
        SEND_TO_CLIENT_OR_FAIL ("<feed_checksum>"
                                "<algorithm>md5</algorithm>"
                                "333"
                                "</feed_checksum>");
        SEND_TO_CLIENT_OR_FAIL ("<nvt>"
                                "<oid>1.3.6.1.4.1.25623.1.7.13005</oid>"
                                "<name>FooBar 1.5 installed</name>"
                                "<checksum>"
                                "<algorithm>md5</algorithm>"
                                "222"
                                "</checksum>"
                                "</nvt>");
        SEND_TO_CLIENT_OR_FAIL ("<nvt>"
                                "<oid>1.3.6.1.4.1.25623.1.7.13006</oid>"
                                "<name>FooBar 2.1 XSS vulnerability</name>"
                                "<checksum>"
                                "<algorithm>md5</algorithm>"
                                "223"
                                "</checksum>"
                                "</nvt>");
        SEND_TO_CLIENT_OR_FAIL ("</get_nvt_feed_all_response>");
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_GET_NVT_FEED_CHECKSUM:
// FIX
#if 0
        if (server.plugins_md5)
          {
            SEND_TO_CLIENT_OR_FAIL ("<get_nvt_feed_checksum_response>"
                                    "<status>200</status>"
                                    "<algorithm>md5</algorithm>");
            SEND_TO_CLIENT_OR_FAIL (server.plugins_md5);
            SEND_TO_CLIENT_OR_FAIL ("</get_nvt_feed_checksum_response>");
          }
        else
          SEND_TO_CLIENT_OR_FAIL ("<get_nvt_feed_checksum_response>"
                                  "<status>500</status>"
                                  "</get_nvt_feed_checksum_response>");
#else
        SEND_TO_CLIENT_OR_FAIL ("<get_nvt_feed_checksum_response>"
                                "<status>200</status>"
                                "<algorithm>md5</algorithm>");
        SEND_TO_CLIENT_OR_FAIL ("111");
        SEND_TO_CLIENT_OR_FAIL ("</get_nvt_feed_checksum_response>");
#endif
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_GET_NVT_FEED_DETAILS:
        SEND_TO_CLIENT_OR_FAIL ("<get_nvt_feed_details_response><status>200</status>");
        // FIX
        SEND_TO_CLIENT_OR_FAIL ("<nvt>"
                                "<oid>1.3.6.1.4.1.25623.1.7.13005</oid>"
                                "<cve>CVE-2008-4877</cve>"
                                "<cve>CVE-2008-4881</cve>"
                                "<bugtraq_id>12345</bugtraq_id>"
                                "<filename>foobar_15_detect.nasl</filename>"
                                "<description>This script detects whether FooBar 1.5 is installed.</description>"
                                "</nvt>");
        SEND_TO_CLIENT_OR_FAIL ("<nvt>"
                                "<oid>1.3.6.1.4.1.25623.1.7.13006</oid>"
                                "<cve>CVE-2008-5142</cve>"
                                "<bugtraq_id>12478</bugtraq_id>"
                                "<filename>foobar_21_xss.nasl</filename>"
                                "<description>This script detects whether the FooBar 2.1 XSS vulnerability is present.</description>"
                                "</nvt>");
        SEND_TO_CLIENT_OR_FAIL ("</get_nvt_feed_details_response>");
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_DELETE_REPORT:
        assert (strncasecmp ("DELETE_REPORT", element_name, 13) == 0);
        SEND_TO_CLIENT_OR_FAIL ("<delete_report_response>");
        if (current_task_task_id)
          {
            int ret = delete_report (current_task_task_id);
            free_string_var (&current_task_task_id);
            switch (ret)
              {
                case 0:
                  SEND_TO_CLIENT_OR_FAIL ("<status>200</status>");
                  break;
                case -1: /* Failed to find associated task. */
                case -2: /* Report file missing. */
                  SEND_TO_CLIENT_OR_FAIL ("<status>40x</status>");
                  break;
                case -3: /* Failed to read link. */
                case -4: /* Failed to remove report. */
                default:
                  free_string_var (&current_task_task_id);
                  SEND_TO_CLIENT_OR_FAIL ("<status>500</status>");
                  break;
              }
          }
        else
          // FIX could be a client error
          //        init to "" at ele start, then always server err
          SEND_TO_CLIENT_OR_FAIL ("<status>50x</status>");
        SEND_TO_CLIENT_OR_FAIL ("</delete_report_response>");
        set_client_state (CLIENT_AUTHENTIC);
        break;
      case CLIENT_DELETE_REPORT_ID:
        assert (strncasecmp ("REPORT_ID", element_name, 9) == 0);
        set_client_state (CLIENT_DELETE_REPORT);
        break;

      case CLIENT_GET_REPORT:
        assert (strncasecmp ("GET_REPORT", element_name, 10) == 0);
        if (current_task_task_id != NULL
            && current_credentials.username != NULL)
          {
            gchar* name = g_build_filename (PREFIX
                                            "/var/lib/openvas/mgr/users/",
                                            current_credentials.username,
                                            "reports",
                                            current_task_task_id,
                                            "report.nbe",
                                            NULL);
            free_string_var (&current_task_task_id);
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
                                            "<status>50x</status>");
                  }
                else
                  {
                    gchar* base64_content;
                    SEND_TO_CLIENT_OR_FAIL ("<get_report_response>"
                                            "<status>200</status>"
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
                                        "<status>40x</status>");
              }
          }
        else
          {
            free_string_var (&current_task_task_id);
            SEND_TO_CLIENT_OR_FAIL ("<get_report_response>"
                                    "<status>500</status>");
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
            SEND_TO_CLIENT_OR_FAIL ("<get_rules_response><status>200</status>");
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
                                  "<status>500</status>"
                                  "</get_rules_response>");
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_VERSION:
        SEND_TO_CLIENT_OR_FAIL ("<omp_version_response>"
                                "<status>200</status>"
                                "<version><preferred/>1.0</version>"
                                "</omp_version_response>");
        set_client_state (CLIENT_AUTHENTIC);
        break;

      case CLIENT_DELETE_TASK:
        if (current_task_task_id)
          {
            assert (current_client_task == NULL);
            task_t task;
            if (find_task (current_task_task_id, &task))
              SEND_TO_CLIENT_OR_FAIL ("<delete_task_response>"
                                      "<status>407</status>"
                                      "</delete_task_response>");
            else if (delete_task (&task))
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
                                      "<status>201</status>"
                                      "</delete_task_response>");
            free_string_var (&current_task_task_id);
          }
        else
          SEND_TO_CLIENT_OR_FAIL ("<status>50x</status>");
        set_client_state (CLIENT_AUTHENTIC);
        break;
      case CLIENT_DELETE_TASK_TASK_ID:
        assert (strncasecmp ("TASK_ID", element_name, 7) == 0);
        set_client_state (CLIENT_DELETE_TASK);
        break;

      case CLIENT_MODIFY_REPORT:
        if (current_task_task_id != NULL
            && modify_task_parameter != NULL
            && modify_task_value != NULL)
          {
            int ret = set_report_parameter (current_task_task_id,
                                            modify_task_parameter,
                                            modify_task_value);
            free_string_var (&modify_task_parameter);
            free_string_var (&modify_task_value);
            free_string_var (&current_task_task_id);
            switch (ret)
              {
                case 0:
                  SEND_TO_CLIENT_OR_FAIL ("<modify_report_response>"
                                          "<status>200</status>");
                  break;
                case -2: /* Parameter name error. */
                  SEND_TO_CLIENT_OR_FAIL ("<modify_report_response>"
                                          "<status>40x</status>");
                  break;
                case -3: /* Failed to write to disk. */
                default:
                  SEND_TO_CLIENT_OR_FAIL ("<modify_report_response>"
                                          "<status>50x</status>");
                  break;
              }
          }
        else
          {
            free_string_var (&modify_task_parameter);
            free_string_var (&modify_task_value);
            free_string_var (&current_task_task_id);
            SEND_TO_CLIENT_OR_FAIL ("<modify_report_response>"
                                    "<status>500</status>");
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
        if (current_task_task_id)
          {
            assert (current_client_task == NULL);
            task_t task;
            if (find_task (current_task_task_id, &task))
              SEND_TO_CLIENT_OR_FAIL ("<modify_task_response>"
                                      "<status>407</status>"
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
                    SEND_TO_CLIENT_OR_FAIL ("<modify_task_response>"
                                            "<status>40x</status>"
                                            "</modify_task_response>");
                  }
                else
                  {
                    modify_task_value = NULL;
                    SEND_TO_CLIENT_OR_FAIL ("<modify_task_response>"
                                            "<status>201</status>"
                                            "</modify_task_response>");
                  }
              }
            free_string_var (&current_task_task_id);
          }
        else
          SEND_TO_CLIENT_OR_FAIL ("<status>50x</status>");
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

      case CLIENT_NEW_TASK:
        {
          gchar* msg;
          assert (strncasecmp ("NEW_TASK", element_name, 7) == 0);
          assert (current_client_task != NULL);
          // FIX if all rqrd fields given then ok, else respond fail
          // FIX only here should the task be added to tasks
          //       eg on err half task could be saved (or saved with base64 file)
          msg = g_strdup_printf ("<new_task_response>"
                                 "<status>201</status>"
                                 "<task_id>%u</task_id>"
                                 "</new_task_response>",
                                 task_id (current_client_task));
          if (send_to_client (msg))
            {
              g_free (msg);
              error_send_to_client (error);
              return;
            }
          g_free (msg);
          current_client_task = NULL;
          set_client_state (CLIENT_AUTHENTIC);
          break;
        }
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
            out = g_base64_decode (task_description (current_client_task),
                                   &out_len);
            set_task_description (current_client_task, (char*) out, out_len);
            set_client_state (CLIENT_NEW_TASK);
          }
        break;

      case CLIENT_START_TASK:
        if (current_task_task_id)
          {
            assert (current_client_task == NULL);
            task_t task;
            if (find_task (current_task_task_id, &task))
              SEND_TO_CLIENT_OR_FAIL ("<start_task_response>"
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
              SEND_TO_CLIENT_OR_FAIL ("<start_task_response>"
                                      "<status>201</status>"
                                      "</start_task_response>");
            free_string_var (&current_task_task_id);
          }
        else
          SEND_TO_CLIENT_OR_FAIL ("<status>50x</status>");
        set_client_state (CLIENT_AUTHENTIC);
        break;
      case CLIENT_START_TASK_TASK_ID:
        assert (strncasecmp ("TASK_ID", element_name, 7) == 0);
        set_client_state (CLIENT_START_TASK);
        break;

      case CLIENT_STATUS:
        assert (strncasecmp ("STATUS", element_name, 6) == 0);
        if (current_task_task_id)
          {
            task_t task;
            if (find_task (current_task_task_id, &task))
              SEND_TO_CLIENT_OR_FAIL ("<status_response>"
                                      "<status>407</status>");
            else
              {
                gchar* response;
                SEND_TO_CLIENT_OR_FAIL ("<status_response><status>200</status>");
                response = g_strdup_printf ("<report_count>%u</report_count>",
                                            task_report_count (task));
                if (send_to_client (response))
                  {
                    g_free (response);
                    error_send_to_client (error);
                    return;
                  }
                g_free (response);
                // FIX need to handle err cases before send status
                (void) send_reports (task);
              }
            free_string_var (&current_task_task_id);
          }
        else
          {
            gchar* response;
            task_iterator_t iterator;
            task_t index;

            SEND_TO_CLIENT_OR_FAIL ("<status_response><status>200</status>");
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
                line = g_strdup_printf ("<task>"
                                        "<task_id>%u</task_id>"
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
                                        task_id (index),
                                        task_name (index),
                                        task_run_status (index)
                                        == TASK_STATUS_NEW
                                        ? "New"
                                        : (task_run_status (index)
                                           == TASK_STATUS_REQUESTED
                                           ? "Requested"
                                           : (task_run_status (index)
                                              == TASK_STATUS_RUNNING
                                              ? "Running"
                                              : "Done")),
                                        task_debugs_size (index),
                                        task_holes_size (index),
                                        task_infos_size (index),
                                        task_logs_size (index),
                                        task_notes_size (index));
                // FIX free line if RESPOND fails
                if (send_to_client (line))
                  {
                    g_free (line);
                    error_send_to_client (error);
                    return;
                  }
                g_free (line);
              }
          }
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
      case CLIENT_DELETE_REPORT_ID:
      case CLIENT_DELETE_TASK_TASK_ID:
      case CLIENT_GET_REPORT_ID:
      case CLIENT_MODIFY_REPORT_REPORT_ID:
      case CLIENT_MODIFY_TASK_TASK_ID:
      case CLIENT_START_TASK_TASK_ID:
      case CLIENT_STATUS_TASK_ID:
        append_text (&current_task_task_id, text, text_len);
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
 * @brief Initialise OMP library data.
 *
 * This should run once, before the first call to \ref process_omp_client_input.
 */
void
init_omp_data ()
{
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
