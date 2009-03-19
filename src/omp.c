/* OpenVAS Manager
 * $Id$
 * Description: Module for OpenVAS Manager: the OMP library.
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

/**
 * @brief Buffer of output to the client.
 */
char to_client[TO_CLIENT_BUFFER_SIZE];

/**
 * @brief The start of the data in the \ref to_client buffer.
 */
int to_client_start = 0;
/**
 * @brief The end of the data in the \ref to_client buffer.
 */
int to_client_end = 0;

/**
 * @brief Current client task during OMP commands like NEW_TASK and MODIFY_TASK.
 */
task_t* current_client_task = NULL;

/**
 * @brief Task ID during OMP MODIFY_TASK and START_TASK.
 */
char* current_task_task_id = NULL;

/**
 * @brief Parameter name during OMP MODIFY_TASK.
 */
char* modify_task_parameter = NULL;

/**
 * @brief Parameter value during OMP MODIFY_TASK.
 */
char* modify_task_value = NULL;

/**
 * @brief Client input parsing context.
 */
GMarkupParseContext* xml_context;

/**
 * @brief Client input parser.
 */
GMarkupParser xml_parser;



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


/* Communication. */

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
      if (TO_CLIENT_BUFFER_SIZE - to_client_end < strlen (msg))   \
        goto send_to_client_fail;                                 \
      memcpy (to_client + to_client_end, msg, strlen (msg));      \
      tracef ("-> client: %s\n", msg);                            \
      to_client_end += strlen (msg);                              \
    }                                                             \
  while (0)


/* XML parser handlers. */

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

      case CLIENT_DELETE_REPORT:
        if (strncasecmp ("REPORT_ID", element_name, 9) == 0)
          set_client_state (CLIENT_DELETE_REPORT_ID);
        else
          {
            SEND_TO_CLIENT ("<delete_report_response>"
                            "<status>402</status>"
                            "</delete_report_response>");
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

      case CLIENT_GET_REPORT:
        if (strncasecmp ("REPORT_ID", element_name, 9) == 0)
          set_client_state (CLIENT_GET_REPORT_ID);
        else
          {
            SEND_TO_CLIENT ("<get_report_response>"
                            "<status>402</status>"
                            "</get_report_response>");
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

      case CLIENT_MODIFY_REPORT:
        if (strncasecmp ("REPORT_ID", element_name, 9) == 0)
          set_client_state (CLIENT_MODIFY_REPORT_REPORT_ID);
        else if (strncasecmp ("PARAMETER", element_name, 9) == 0)
          set_client_state (CLIENT_MODIFY_REPORT_PARAMETER);
        else if (strncasecmp ("VALUE", element_name, 5) == 0)
          set_client_state (CLIENT_MODIFY_REPORT_VALUE);
        else
          {
            SEND_TO_CLIENT ("<modify_report_response>"
                            "<status>402</status>"
                            "</modify_report_response>");
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
                            "</status_response>");
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

 send_to_client_fail:
  tracef ("   SEND_TO_CLIENT out of space in to_client\n");
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
 send_to_client_fail:
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
      g_free (msg);
      return TRUE;
    }

  SEND_TO_CLIENT ("</dependency>");
  return FALSE;

 send_to_client_fail:
  g_free (msg);
  return TRUE;
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
 send_to_client_fail:
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
 send_to_client_fail:
  g_free (msg);
  return TRUE;
}

/**
 * @brief Send XML for the reports of a task.
 *
 * @param[in]  task  The task.
 *
 * @return TRUE if out of space in to_client buffer, else FALSE.
 */
gboolean
send_reports (task_t* task)
{
  const char* id;

  if (task_id_string (task, &id)) return FALSE;

  gchar* dir_name = g_build_filename (PREFIX
                                      "/var/lib/openvas/mgr/users/",
                                      current_credentials.username,
                                      "tasks",
                                      id,
                                      "reports",
                                      NULL);

  struct dirent ** names;
  int count;

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
      return -1;
    }

  int index;
  gchar* msg = NULL;
  for (index = 0; index < count; index++)
    {
      const char* report_name = names[index]->d_name;

      if (report_name[0] == '.'
          || strlen (report_name) < 5
          || strcmp (report_name + strlen (report_name) - 4, ".nbe"))
        continue;

#if 0
      report_dir_name = g_build_filename (dir_name, report_name, NULL);
#endif

      tracef ("     %s\n", report_name);

      msg = g_strdup_printf ("<report>"
                             "<id>%.*s</id>"
                             "<timestamp>FIX</timestamp>"
                             "<messages>"
                             "<hole>0</hole>"
                             "<info>0</info>"
                             "<log>0</log>"
                             "<debug>0</debug>"
                             "</messages>"
                             "</report>",
                             strlen (report_name) - 4,
                             report_name);
      free (names[index]);
      SEND_TO_CLIENT (msg);
    }

#if 0
  g_free (dir_name);
#endif
  free (names);

  SEND_TO_CLIENT (msg);
  g_free (msg);
  return FALSE;
 send_to_client_fail:
  g_free (names);
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
          if (sscanf (current_task_task_id, "%u", &id) == 1)
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
          else
            SEND_TO_CLIENT ("<abort_task_response>"
                            "<status>40x</status>"
                            "</abort_task_response>");
          free_string_var (&current_task_task_id);
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
              goto send_to_client_fail;
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
              goto send_to_client_fail;
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

      case CLIENT_DELETE_REPORT:
        assert (strncasecmp ("DELETE_REPORT", element_name, 13) == 0);
        if (current_task_task_id)
          {
            int ret = delete_report (current_task_task_id);
            free_string_var (&current_task_task_id);
            switch (ret)
              {
                case 0:
                  SEND_TO_CLIENT ("<delete_report_response>"
                                  "<status>200</status>");
                  break;
                case -2: /* Report file missing. */
                  SEND_TO_CLIENT ("<delete_report_response>"
                                  "<status>40x</status>");
                  break;
                case -1: /* Failed to parse id. */
                case -3: /* Failed to read link. */
                case -4: /* Failed to remove report. */
                default:
                  free_string_var (&current_task_task_id);
                  SEND_TO_CLIENT ("<delete_report_response>"
                                  "<status>500</status>");
                  break;
              }
            SEND_TO_CLIENT ("</delete_report_response>");
            set_client_state (CLIENT_AUTHENTIC);
          }
        break;
      case CLIENT_DELETE_REPORT_ID:
        assert (strncasecmp ("REPORT_ID", element_name, 9) == 0);
        set_client_state (CLIENT_DELETE_REPORT);
        break;

      case CLIENT_GET_REPORT:
        assert (strncasecmp ("GET_REPORT", element_name, 10) == 0);
        unsigned int id;
        if (current_task_task_id
            && sscanf (current_task_task_id, "%u", &id) == 1)
          {
            static char buffer[11]; /* (expt 2 32) => 4294967296 */

            free_string_var (&current_task_task_id);

            sprintf (buffer, "%010u", id);
            gchar* name = g_build_filename (PREFIX
                                            "/var/lib/openvas/mgr/users/",
                                            current_credentials.username,
                                            "reports",
                                            buffer,
                                            "report.nbe",
                                            NULL);
            // FIX glib access setuid note
            if (g_file_test (name, G_FILE_TEST_EXISTS))
              {
                gchar* content;
                gsize content_length;
                GError* content_error = NULL;
                g_file_get_contents (name, &content, &content_length,
                                     &content_error);
                g_free (name);
                if (content_error)
                  {
                    g_error_free (content_error);
                    SEND_TO_CLIENT ("<get_report_response>"
                                    "<status>50x</status>");
                  }
                else
                  {
                    gchar* base64_content;
                    base64_content = g_base64_encode ((guchar*) content,
                                                      content_length);
                    g_free (content);
                    // FIX free base64_content if SEND_TO_CLIENT fail
                    SEND_TO_CLIENT ("<get_report_response>"
                                    "<status>200</status>"
                                    "<report>");
                    SEND_TO_CLIENT (base64_content);
                    g_free (base64_content);
                    SEND_TO_CLIENT ("</report>");
                  }
              }
            else
              {
                g_free (name);
                SEND_TO_CLIENT ("<get_report_response>"
                                "<status>40x</status>");
              }
          }
        else
          {
            free_string_var (&current_task_task_id);
            SEND_TO_CLIENT ("<get_report_reponse>"
                            "<status>500</status>");
          }
        SEND_TO_CLIENT ("</get_report_response>");
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
            SEND_TO_CLIENT ("<get_rules_response><status>200</status>");
            for (index = 0; index < server.rules_size; index++)
              if (send_rule (g_ptr_array_index (server.rules, index)))
                goto send_to_client_fail;
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
          if (sscanf (current_task_task_id, "%u", &id) == 1)
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
          else
            SEND_TO_CLIENT ("<delete_task_response>"
                            "<status>40x</status>"
                            "</delete_task_response>");
          free_string_var (&current_task_task_id);
          set_client_state (CLIENT_AUTHENTIC);
        }
        break;
      case CLIENT_DELETE_TASK_TASK_ID:
        assert (strncasecmp ("TASK_ID", element_name, 7) == 0);
        set_client_state (CLIENT_DELETE_TASK);
        break;

      case CLIENT_MODIFY_REPORT:
        if (current_task_task_id
            && modify_task_parameter
            && modify_task_value)
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
                  SEND_TO_CLIENT ("<modify_report_response>"
                                  "<status>200</status>");
                  break;
                case -1: /* Failed to scan ID. */
                case -2: /* Parameter name error. */
                  SEND_TO_CLIENT ("<modify_report_response>"
                                  "<status>40x</status>");
                  break;
                case -3: /* Failed to write to disk. */
                default:
                  SEND_TO_CLIENT ("<modify_report_response>"
                                  "<status>50x</status>");
                  break;
              }
          }
        else
          {
            free_string_var (&modify_task_parameter);
            free_string_var (&modify_task_value);
            free_string_var (&current_task_task_id);
            SEND_TO_CLIENT ("<modify_report_response>"
                            "<status>500</status>");
          }
        SEND_TO_CLIENT ("</modify_report_response>");
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
        {
          assert (current_client_task == NULL);
          unsigned int id;
          if (sscanf (current_task_task_id, "%u", &id) == 1)
            {
              task_t* task = find_task (id);
              if (task == NULL)
                SEND_TO_CLIENT ("<modify_task_response>"
                                "<status>407</status>"
                                "</modify_task_response>");
              else
                {
                  // FIX check if param,value else respond fail
                  int fail = set_task_parameter (task,
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
          else
            SEND_TO_CLIENT ("<modify_task_response>"
                            "<status>40x</status>"
                            "</modify_task_response>");
          free_string_var (&current_task_task_id);
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
          if (sscanf (current_task_task_id, "%u", &id) == 1)
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
          else
            SEND_TO_CLIENT ("<start_task_response>"
                            "<status>40x</status>"
                            "</start_task_response>");
          free_string_var (&current_task_task_id);
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
            if (sscanf (current_task_task_id, "%u", &id) == 1)
              {
                task_t* task = find_task (id);
                if (task == NULL)
                  SEND_TO_CLIENT ("<status_response>"
                                  "<status>407</status>");
                else
                  {
                    SEND_TO_CLIENT ("<status_response><status>200</status>");
                    gchar* response;
                    response = g_strdup_printf ("<report_count>%u</report_count>",
                                                task->report_count);
                    SEND_TO_CLIENT (response);
                    send_reports (task);
                  }
              }
            else
              SEND_TO_CLIENT ("<status_response>"
                              "<status>40x</status>");
            free_string_var (&current_task_task_id);
          }
        else
          {
            SEND_TO_CLIENT ("<status_response><status>200</status>");
            gchar* response = g_strdup_printf ("<task_count>%u</task_count>",
                                               num_tasks);
            SEND_TO_CLIENT (response);
            // FIX this is the only place that accesses "tasks"  foreach_task?
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
                                            "<status>%s</status>"
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
                                            index->running
                                            ? (index->running == 1
                                               ? "Requested"
                                               : (index->running == 2
                                                  ? "Running"
                                                  : "Done"))
                                            : "New",
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

 send_to_client_fail:
  tracef ("   SEND_TO_CLIENT out of space in to_client\n");
  g_set_error (error, G_MARKUP_ERROR, G_MARKUP_ERROR_PARSE,
               "Manager out of space for reply to client.\n");
}

/**
 * @brief Handle the addition of text to an OMP XML element.
 *
 * React to the addition of text to the value of an XML element.
 * React according to the current value of \ref client_state,
 * usually appending the text to some part of the current task
 * (\ref current_client_task) with functions like \ref append_string,
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
      case CLIENT_MODIFY_REPORT_PARAMETER:
        append_string (&modify_task_parameter, text);
        break;
      case CLIENT_MODIFY_REPORT_VALUE:
        append_string (&modify_task_value, text);
        break;

      case CLIENT_MODIFY_TASK_PARAMETER:
        append_string (&modify_task_parameter, text);
        break;
      case CLIENT_MODIFY_TASK_VALUE:
        append_string (&modify_task_value, text);
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
        append_string (&current_task_task_id, text);
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


/* OMP input processor. */

// FIX probably should pass to process_omp_client_input
extern char from_client[];
extern int from_client_start;
extern int from_client_end;

/**
 * @brief Initialise OMP library data.
 *
 * This must run once, before the first call to \ref process_omp_client_input.
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
