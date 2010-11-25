/* OpenVAS Manager
 * $Id$
 * Description: Module for OpenVAS Manager: the Manage library.
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
 *
 * Copyright:
 * Copyright (C) 2009,2010 Greenbone Networks GmbH
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
 * @file  manage.c
 * @brief The OpenVAS Manager management library.
 *
 * This file defines a management library, for implementing OpenVAS
 * Managers such as the OpenVAS Manager daemon.
 *
 * This library provides facilities for storing and manipulating credential
 * and task information, and manipulating reports.  Task manipulation
 * includes sending task commands to the OTP server (the "scanner") that is
 * running the tasks.
 */

#include "manage.h"
#include "manage_sql.h"
#include "ovas-mngr-comm.h"
#include "tracef.h"

#include <assert.h>
#include <errno.h>
#include <dirent.h>
#include <glib.h>
#include <uuid/uuid.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/wait.h>
#include <unistd.h>

#include <openvas/base/openvas_string.h>
#include <openvas/omp/omp.h>
#include <openvas/misc/openvas_server.h>
#include <openvas/misc/openvas_uuid.h>

#ifdef S_SPLINT_S
#include "splint.h"
#endif

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Information about the scanner.
 */
scanner_t scanner = { NULL, NULL, NULL, NULL, 0 };


/* Threats. */

/**
 * @brief Get the message type of a threat.
 *
 * @param  threat  Threat.
 *
 * @return Static message type name if threat names a threat, else NULL.
 */
const char *
threat_message_type (const char *threat)
{
  if (strcasecmp (threat, "High") == 0)
    return "Security Hole";
  if (strcasecmp (threat, "Medium") == 0)
    return "Security Warning";
  if (strcasecmp (threat, "Low") == 0)
    return "Security Note";
  if (strcasecmp (threat, "Log") == 0)
    return "Log Message";
  if (strcasecmp (threat, "Debug") == 0)
    return "Debug Message";
  if (strcasecmp (threat, "False Positive") == 0)
    return "False Positive";
  return NULL;
}

/**
 * @brief Get the threat of a message type.
 *
 * @param  type  Message type.
 *
 * @return Static threat name if type names a message type, else NULL.
 */
const char *
message_type_threat (const char *type)
{
  if (strcasecmp (type, "Security Hole") == 0)
    return "High";
  if (strcasecmp (type, "Security Warning") == 0)
    return "Medium";
  if (strcasecmp (type, "Security Note") == 0)
    return "Low";
  if (strcasecmp (type, "Log Message") == 0)
    return "Log";
  if (strcasecmp (type, "Debug Message") == 0)
    return "Debug";
  if (strcasecmp (type, "False Positive") == 0)
    return "False Positive";
  return NULL;
}


/* Credentials. */

/**
 * @brief Current credentials during any OMP command.
 */
credentials_t current_credentials;


/* Reports. */

/**
 * @brief Delete all the reports for a task.
 *
 * It's up to the caller to ensure that this runs in a contention safe
 * context (for example within an SQL transaction).
 *
 * @param[in]  task  A task descriptor.
 *
 * @return 0 on success, -1 on error.
 */
int
delete_reports (task_t task)
{
  report_t report;
  iterator_t iterator;
  init_report_iterator (&iterator, task, 0);
  while (next_report (&iterator, &report))
    if (delete_report (report))
      {
        cleanup_iterator (&iterator);
        return -1;
      }
  cleanup_iterator (&iterator);
  return 0;
}

/**
 * @brief Return the threat associated with a result type.
 *
 * @param[in]  type  Result type.
 *
 * @return Threat name.
 */
const char*
manage_result_type_threat (const char* type)
{
  if (strcasecmp (type, "Security Hole") == 0)
    return "High";
  if (strcasecmp (type, "Security Warning") == 0)
    return "Medium";
  if (strcasecmp (type, "Security Note") == 0)
    return "Low";
  if (strcasecmp (type, "False Positive") == 0)
    return "False Positive";
  return "Log";
}


/* Task globals. */

/**
 * @brief Scanner active flag.
 *
 * This indicates whether the scanner is doing something that the manager
 * must wait for.  Set, for example, by \ref start_task.  If this variable
 * is true then the manager keeps the management process alive until the
 * scanner closes its connection, even if the client closes its connection.
 */
short scanner_active = 0;

/**
 * @brief The task currently running on the scanner.
 */
/*@null@*/ task_t current_scanner_task = (task_t) 0;

/**
 * @brief The report of the current task.
 */
report_t current_report = (report_t) 0;


/* Escalators. */

/**
 * @brief Get the name of an escalator condition.
 *
 * @param[in]  condition  Condition.
 *
 * @return The name of the condition (for example, "Always").
 */
const char*
escalator_condition_name (escalator_condition_t condition)
{
  switch (condition)
    {
      case ESCALATOR_CONDITION_ALWAYS:
        return "Always";
      case ESCALATOR_CONDITION_THREAT_LEVEL_AT_LEAST:
        return "Threat level at least";
      case ESCALATOR_CONDITION_THREAT_LEVEL_CHANGED:
        return "Threat level changed";
      default:
        return "Internal Error";
    }
}

/**
 * @brief Get the name of an escalator event.
 *
 * @param[in]  event  Event.
 *
 * @return The name of the event (for example, "Run status changed").
 */
const char*
event_name (event_t event)
{
  switch (event)
    {
      case EVENT_TASK_RUN_STATUS_CHANGED: return "Task run status changed";
      default:                            return "Internal Error";
    }
}

/**
 * @brief Get a description of an escalator condition.
 *
 * @param[in]  condition  Condition.
 * @param[in]  escalator  Escalator.
 *
 * @return Freshly allocated description of condition.
 */
gchar*
escalator_condition_description (escalator_condition_t condition,
                                 escalator_t escalator)
{
  switch (condition)
    {
      case ESCALATOR_CONDITION_ALWAYS:
        return g_strdup ("Always");
      case ESCALATOR_CONDITION_THREAT_LEVEL_AT_LEAST:
        {
          char *level = escalator_data (escalator, "condition", "level");
          gchar *ret = g_strdup_printf ("Task threat level is at least '%s'",
                                        level);
          free (level);
          return ret;
          break;
        }
      case ESCALATOR_CONDITION_THREAT_LEVEL_CHANGED:
        {
          char *direction;
          direction = escalator_data (escalator, "condition", "direction");
          gchar *ret = g_strdup_printf ("Task threat level %s", direction);
          free (direction);
          return ret;
          break;
        }
      default:
        return g_strdup ("Internal Error");
    }
}

/**
 * @brief Get a description of an escalator event.
 *
 * @param[in]  event       Event.
 * @param[in]  event_data  Event data.
 * @param[in]  task_name   Name of task if required in description, else NULL.
 *
 * @return Freshly allocated description of event.
 */
gchar*
event_description (event_t event, const void *event_data, const char *task_name)
{
  switch (event)
    {
      case EVENT_TASK_RUN_STATUS_CHANGED:
        if (task_name)
          return g_strdup_printf
                  ("The security scan task '%s' changed status to '%s'",
                   task_name,
                   run_status_name ((task_status_t) event_data));
        return g_strdup_printf ("Task status changed to '%s'",
                                run_status_name ((task_status_t) event_data));
        break;
      default:
        return g_strdup ("Internal Error");
    }
}

/**
 * @brief Get the name of an escalator method.
 *
 * @param[in]  method  Method.
 *
 * @return The name of the method (for example, "Email" or "SNMP").
 */
const char*
escalator_method_name (escalator_method_t method)
{
  switch (method)
    {
      case ESCALATOR_METHOD_EMAIL:    return "Email";
      case ESCALATOR_METHOD_HTTP_GET: return "HTTP Get";
      case ESCALATOR_METHOD_SYSLOG:   return "Syslog";
      default:                        return "Internal Error";
    }
}

/**
 * @brief Get an escalator condition from a name.
 *
 * @param[in]  name  Condition name.
 *
 * @return The condition.
 */
escalator_condition_t
escalator_condition_from_name (const char* name)
{
  if (strcasecmp (name, "Always") == 0)
    return ESCALATOR_CONDITION_ALWAYS;
  if (strcasecmp (name, "Threat level at least") == 0)
    return ESCALATOR_CONDITION_THREAT_LEVEL_AT_LEAST;
  if (strcasecmp (name, "Threat level changed") == 0)
    return ESCALATOR_CONDITION_THREAT_LEVEL_CHANGED;
  return ESCALATOR_CONDITION_ERROR;
}

/**
 * @brief Get an event from a name.
 *
 * @param[in]  name  Event name.
 *
 * @return The event.
 */
event_t
event_from_name (const char* name)
{
  if (strcasecmp (name, "Task run status changed") == 0)
    return EVENT_TASK_RUN_STATUS_CHANGED;
  return EVENT_ERROR;
}

/**
 * @brief Get an escalator method from a name.
 *
 * @param[in]  name  Method name.
 *
 * @return The method.
 */
escalator_method_t
escalator_method_from_name (const char* name)
{
  if (strcasecmp (name, "Email") == 0)
    return ESCALATOR_METHOD_EMAIL;
  if (strcasecmp (name, "HTTP Get") == 0)
    return ESCALATOR_METHOD_HTTP_GET;
  if (strcasecmp (name, "Syslog") == 0)
    return ESCALATOR_METHOD_SYSLOG;
  return ESCALATOR_METHOD_ERROR;
}


/* General task facilities. */

/**
 * @brief Get the name of a run status.
 *
 * @param[in]  status  Run status.
 *
 * @return The name of the status (for example, "Done" or "Running").
 */
const char*
run_status_name (task_status_t status)
{
  switch (status)
    {
      case TASK_STATUS_DELETE_REQUESTED: return "Delete Requested";
      case TASK_STATUS_DONE:             return "Done";
      case TASK_STATUS_NEW:              return "New";

      case TASK_STATUS_PAUSE_REQUESTED:
      case TASK_STATUS_PAUSE_WAITING:
        return "Pause Requested";

      case TASK_STATUS_PAUSED:           return "Paused";
      case TASK_STATUS_REQUESTED:        return "Requested";

      case TASK_STATUS_RESUME_REQUESTED:
      case TASK_STATUS_RESUME_WAITING:
        return "Resume Requested";

      case TASK_STATUS_RUNNING:          return "Running";

      case TASK_STATUS_STOP_REQUESTED:
      case TASK_STATUS_STOP_WAITING:
        return "Stop Requested";

      case TASK_STATUS_STOPPED:          return "Stopped";
      default:                           return "Internal Error";
    }
}

/**
 * @brief Get the name of the status of a task.
 *
 * @param[in]  task  The task.
 *
 * @return The name of the status of the given task (for example, "Done" or
 *         "Running").
 */
const char*
task_run_status_name (task_t task)
{
  return run_status_name (task_run_status (task));
}

/** @todo Test these RC parsing functions. */

/**
 * @brief Return a preference from an RC.
 *
 * @param[in]  desc  The RC.
 * @param[in]  name  The name of the preference.
 *
 * @return The preference on success, else NULL.
 */
char*
rc_preference (const char* desc, const char* name)
{
  char* seek;

  if (desc == NULL)
    {
      tracef ("   desc NULL\n");
      return NULL;
    }

  while ((seek = strchr (desc, '\n')))
    {
      char* eq = seek
                 ? memchr (desc, '=', seek - desc)
                 : strchr (desc, '=');
      if (eq)
        {
#if 0
          tracef ("   1 found: %.*s\n",
                  seek ? seek - desc : strlen (seek),
                  desc);
#endif
          if (strncmp (desc, name, eq - desc - 1) == 0)
            {
              gchar* ret;
              if (seek > eq + 1)
                ret = g_strndup (eq + 2,
                                 seek ? seek - (eq + 2) : strlen (seek));
              else
                ret = g_strdup ("");
              return ret;
            }
        }
      else if ((seek ? seek - desc > 7 : 1)
               && strncmp (desc, "begin(", 6) == 0)
        {
          /* Read over the section. */
          desc = seek + 1;
          while ((seek = strchr (desc, '\n')))
            {
              if ((seek ? seek - desc > 5 : 1)
                  && strncmp (desc, "end(", 4) == 0)
                {
                  break;
                }
#if 0
              tracef ("   1 skip: %.*s\n",
                      seek ? seek - desc : strlen (seek),
                      desc);
#endif
              desc = seek + 1;
            }
        }
      if (seek == NULL) break;
      desc = seek + 1;
    }
  return NULL;
}

/**
 * @brief Get files to send.
 *
 * @param  task  Task of interest.
 *
 * @return List of files to send, (NULL if none), data has to be freed with
 *         g_free.
 */
static GSList*
get_files_to_send (task_t task)
{
  iterator_t files;
  GSList* filelist = NULL;

  init_task_file_iterator (&files, task, NULL);
  while (next (&files))
    {
      const gchar* file_path = task_file_iterator_name (&files);
      filelist = g_slist_append (filelist, g_strdup (file_path));
    }
  cleanup_iterator (&files);

  return filelist;
}

/**
 * @brief Return the plugins of a config, as a semicolon separated string.
 *
 * @param[in]  config  Config.
 *
 * @return A string of semi-colon separated plugin IDS.
 */
static gchar*
nvt_selector_plugins (config_t config)
{
  GString* plugins = g_string_new ("");
  iterator_t families;
  gboolean first = TRUE;

  init_family_iterator (&families, 0, NULL, 1);
  while (next (&families))
    {
      const char *family = family_iterator_name (&families);
      if (family)
        {
          iterator_t nvts;
          init_nvt_iterator (&nvts, 0, config, family, 1, NULL);
          while (next (&nvts))
            {
              if (first)
                first = FALSE;
              else
                g_string_append_c (plugins, ';');
              g_string_append (plugins, nvt_iterator_oid (&nvts));
            }
          cleanup_iterator (&nvts);
        }
    }
  cleanup_iterator (&families);

  return g_string_free (plugins, FALSE);
}

/**
 * @brief Return the real value of a preference.
 *
 * Take care of radio button options.
 *
 * @param[in]  name        Name of preference.
 * @param[in]  full_value  Entire value of preference.
 *
 * @return Real value of the preference.
 */
static gchar*
preference_value (const char* name, const char* full_value)
{
  char *bracket = strchr (name, '[');
  if (bracket)
    {
      if (strncmp (bracket, "[radio]:", strlen ("[radio]:")) == 0)
        {
          char *semicolon = strchr (full_value, ';');
          if (semicolon)
            return g_strndup (full_value, semicolon - full_value);
        }
    }
  return g_strdup (full_value);
}

/**
 * @brief Send the preferences from a config to the scanner.
 *
 * @param[in]  config        Config.
 * @param[in]  section_name  Name of preference section to send.
 * @param[in]  task_files    Files associated with the task.
 * @param[out] pref_files    Files associated with config (UUID, contents, ...).
 *
 * @return 0 on success, -1 on failure.
 */
static int
send_config_preferences (config_t config, const char* section_name,
                         GSList *task_files, GPtrArray *pref_files)
{
  iterator_t prefs;

  init_otp_pref_iterator (&prefs, config, section_name);
  while (next (&prefs))
    {
      const char *pref_name = otp_pref_iterator_name (&prefs);
      char *value;

      if (send_to_server (pref_name))
        {
          cleanup_iterator (&prefs);
          return -1;
        }

      if (sendn_to_server (" <|> ", 5))
        {
          cleanup_iterator (&prefs);
          return -1;
        }

      value = preference_value (pref_name,
                                otp_pref_iterator_value (&prefs));

      if (pref_files)
        {
          int type_start = -1, type_end = -1, count;

          /* LDAPsearch[entry]:Timeout value */
          count = sscanf (pref_name, "%*[^[][%n%*[^]]%n]:", &type_start,
                          &type_end);
          if (count == 0
              && type_start > 0
              && type_end > 0
              && (strncmp (pref_name + type_start,
                           "file",
                           type_end - type_start)
                  == 0))
            {
              GSList *head;
              char *uuid;

              /* A "file" preference.
               *
               * If the value of the preference is empty, then send an empty
               * value.
               *
               * If the value of the preference is the name of a task file,
               * then just send the preference value, otherwise send a UUID and
               * add the value to the list of preference files (pref_files). */

              if (strcmp (value, "") == 0)
                {
                  g_free (value);
                  if (sendn_to_server ("\n", 1))
                    {
                      cleanup_iterator (&prefs);
                      return -1;
                    }
                  continue;
                }

              head = task_files;
              while (head)
                {
                  if (strcmp (head->data, value) == 0)
                    break;
                  head = g_slist_next (head);
                }

              if (head == NULL)
                {
                  uuid = openvas_uuid_make ();
                  if (uuid == NULL)
                    {
                      g_free (value);
                      cleanup_iterator (&prefs);
                      return -1;
                    }

                  g_ptr_array_add (pref_files, (gpointer) uuid);
                  g_ptr_array_add (pref_files, (gpointer) value);

                  if (send_to_server (uuid))
                    {
                      free (uuid);
                      g_free (value);
                      cleanup_iterator (&prefs);
                      return -1;
                    }

                  if (sendn_to_server ("\n", 1))
                    {
                      free (uuid);
                      g_free (value);
                      cleanup_iterator (&prefs);
                      return -1;
                    }

                  continue;
                }
            }
        }

      if (send_to_server (value))
        {
          g_free (value);
          cleanup_iterator (&prefs);
          return -1;
        }
      g_free (value);

      if (sendn_to_server ("\n", 1))
        {
          cleanup_iterator (&prefs);
          return -1;
        }
    }
  cleanup_iterator (&prefs);
  return 0;
}

#if 0
/**
 * @brief Send the rules (CLIENTSIDE_USERRULES) from a config to the scanner.
 *
 * @param[in]  config  Config.
 *
 * @return 0 on success, -1 on failure.
 */
static int
send_config_rules (const char* config)
{
  iterator_t prefs;

  init_preference_iterator (&prefs, config, "CLIENTSIDE_USERRULES");
  while (next (&prefs))
    {
      if (send_to_server (preference_iterator_name (&prefs)))
        {
          cleanup_iterator (&prefs);
          return -1;
        }
      if (sendn_to_server ("\n", 1))
        {
          cleanup_iterator (&prefs);
          return -1;
        }
    }
  cleanup_iterator (&prefs);
  return 0;
}
#endif

/**
 * @brief Send the rules listed in the users directory.
 *
 * @param[in]  stopped_report  Report whose finished hosts to deny.
 *
 * @return 0 on success, -1 on failure.
 */
static int
send_user_rules (report_t stopped_report)
{
  gchar *rules;
  gchar **rule, **split;

  assert (current_credentials.username);

  if (openvas_auth_user_uuid_rules (current_credentials.username,
                                    current_credentials.uuid,
                                    &rules)
      == 0)
    {
      tracef ("   failed to get rules.");
      return -1;
    }

  split = rule = g_strsplit (rules, "\n", 0);
  g_free (rules);

  if (stopped_report && (*rule == NULL))
    {
      iterator_t hosts;

      /* Empty rules file.  Send rules to deny all finished hosts. */

      init_host_iterator (&hosts, stopped_report, NULL);
      while (next (&hosts))
        if (host_iterator_end_time (&hosts)
            && strlen (host_iterator_end_time (&hosts))
            && sendf_to_server ("deny %s\n",
                                host_iterator_host (&hosts)))
          {
            cleanup_iterator (&hosts);
            g_strfreev (split);
            return -1;
          }
      cleanup_iterator (&hosts);

      g_strfreev (split);

      return send_to_server ("default accept\n") ? -1 : 0;
    }

  /** @todo Code to access the rules also occurs in openvas-administrator and
   *        should be consolidated into openvas-libraries. */
  while (*rule)
    {
      *rule = g_strstrip (*rule);
      if (**rule == '#')
        {
          rule++;
          continue;
        }

      /* Presume the rule is correctly formatted. */

      if (stopped_report)
        {
          gboolean send_rule = TRUE;
          iterator_t hosts;

          /* Send deny rules for finished hosts before "allow all" rule. */

          if (strncmp (*rule, "default accept", strlen ("default accept")) == 0)
            {
              init_host_iterator (&hosts, stopped_report, NULL);
              while (next (&hosts))
                if (host_iterator_end_time (&hosts)
                    && strlen (host_iterator_end_time (&hosts))
                    && sendf_to_server ("deny %s\n",
                                        host_iterator_host (&hosts)))
                  {
                    cleanup_iterator (&hosts);
                    g_strfreev (split);
                    return -1;
                  }
              cleanup_iterator (&hosts);
            }
          else
            {
              /* Prevent allow rules for finished hosts. */

              init_host_iterator (&hosts, stopped_report, NULL);
              while (next (&hosts))
                if (host_iterator_end_time (&hosts)
                    && strlen (host_iterator_end_time (&hosts)))
                  {
                    if ((strncmp (*rule, "allow ", strlen ("allow "))
                         == 0)
                        && (strncmp (*rule + strlen ("allow "),
                                     host_iterator_host (&hosts),
                                     strlen (host_iterator_host (&hosts)))
                            == 0))
                      {
                        send_rule = FALSE;
                        break;
                      }
                  }
              cleanup_iterator (&hosts);
            }

          /* Send the rule. */

          if (send_rule && send_to_server (*rule))
            {
              g_strfreev (split);
              return -1;
            }
        }
      else if (send_to_server (*rule))
        {
          g_strfreev (split);
          return -1;
        }

      if (sendn_to_server ("\n", 1))
        {
          g_strfreev (split);
          return -1;
        }
      rule++;
    }
  g_strfreev (split);

  return 0;
}

/**
 * @brief Send a file to the scanner.
 *
 * @param[in]  name     File name.
 * @param[in]  content  File contents.
 *
 * @return 0 on success, -1 on failure.
 */
static int
send_file (const char* name, const char* content)
{
  size_t content_len = strlen (content);

  if (sendf_to_server ("CLIENT <|> ATTACHED_FILE\n"
                       "name: %s\n"
                       "content: octet/stream\n"
                       "bytes: %i\n",
                       name,
                       content_len))
    return -1;

  if (sendn_to_server (content, content_len))
    return -1;

  return 0;
}

/**
 * @brief Send a file from a task to the scanner.
 *
 * @param[in]  task  The task.
 * @param[in]  file  File name.
 *
 * @return 0 on success, -1 on failure.
 */
static int
send_task_file (task_t task, const char* file)
{
  iterator_t files;

  init_task_file_iterator (&files, task, file);
  while (next (&files))
    {
      gsize content_len;
      guchar *content;
      const char *content_64 = task_file_iterator_content (&files);

      content = g_base64_decode (content_64, &content_len);

      if (sendf_to_server ("CLIENT <|> ATTACHED_FILE\n"
                           "name: %s\n"
                           "content: octet/stream\n"
                           "bytes: %i\n",
                           file,
                           content_len))
        {
          g_free (content);
          cleanup_iterator (&files);
          return -1;
        }

      if (sendn_to_server (content, content_len))
        {
          g_free (content);
          cleanup_iterator (&files);
          return -1;
        }
      g_free (content);
    }
  cleanup_iterator (&files);
  return 0;
}

/** @todo g_convert back to ISO-8559-1 for scanner? */

/**
 * @brief Free an slist of pointers, including the pointers.
 *
 * @param[in]  list  The list.
 */
/** @todo Duplicate in openvas_string module (openvas_string_list_free) .
  *       Find proper module to place this function. */
void
slist_free (GSList* list)
{
  GSList *head = list;
  while (list)
    {
      g_free (list->data);
      list = g_slist_next (list);
    }
  g_slist_free (head);
}

/**
 * @brief Update the locally cached task progress from the slave.
 *
 * @param[in]  get_tasks  Slave GET_TASKS response.
 *
 * @return 0 success, -1 error.
 */
int
update_slave_progress (entity_t get_tasks)
{
  entity_t entity;

  entity = entity_child (get_tasks, "task");
  if (entity == NULL)
    return -1;
  entity = entity_child (entity, "progress");
  if (entity == NULL)
    return -1;

  if (current_report == 0)
    return -1;

  set_report_slave_progress (current_report,
                             atoi (entity_text (entity)));

  return 0;
}

/**
 * @brief Update the local task from the slave task.
 *
 * @param[in]   task         The local task.
 * @param[in]   get_report   Slave GET_REPORT response.
 * @param[out]  report       Report from get_report.
 * @param[out]  next_result  Next result counter.
 *
 * @return 0 success, -1 error.
 */
int
update_from_slave (task_t task, entity_t get_report, entity_t *report,
                   int *next_result)
{
  entity_t entity, host_start, start;
  entities_t results, hosts, entities;

  entity = entity_child (get_report, "report");
  if (entity == NULL)
    return -1;

  *report = entity_child (entity, "report");
  if (*report == NULL)
    return -1;

  /* Set the scan start time. */

  entities = (*report)->entities;
  while ((start = first_entity (entities)))
    {
      if (strcmp (entity_name (start), "scan_start") == 0)
        {
          set_task_start_time (current_scanner_task,
                               g_strdup (entity_text (start)));
          set_scan_start_time (current_report, entity_text (start));
          break;
        }
      entities = next_entities (entities);
    }

  /* Get any new results and hosts from the slave. */

  hosts = (*report)->entities;
  while ((host_start = first_entity (hosts)))
    {
      if (strcmp (entity_name (host_start), "host_start") == 0)
        {
          entity_t host;

          host = entity_child (host_start, "host");
          if (host == NULL)
            return -1;

          set_scan_host_start_time (current_report,
                                    entity_text (host),
                                    entity_text (host_start));
        }
      hosts = next_entities (hosts);
    }

  entity = entity_child (*report, "results");
  if (entity == NULL)
    return -1;

  assert (current_report);

  results = entity->entities;
  while ((entity = first_entity (results)))
    {
      if (strcmp (entity_name (entity), "result") == 0)
        {
          entity_t subnet, host, port, nvt, threat, description;
          const char *oid;

          subnet = entity_child (entity, "subnet");
          if (subnet == NULL)
            return -1;

          host = entity_child (entity, "host");
          if (host == NULL)
            return -1;

          port = entity_child (entity, "port");
          if (port == NULL)
            return -1;

          nvt = entity_child (entity, "nvt");
          if (nvt == NULL)
            return -1;
          oid = entity_attribute (nvt, "oid");
          if ((oid == NULL) || (strlen (oid) == 0))
            return -1;

          threat = entity_child (entity, "threat");
          if (threat == NULL)
            return -1;

          description = entity_child (entity, "description");
          if (description == NULL)
            return -1;

          {
            result_t result;

            result = make_result (task,
                                  entity_text (subnet),
                                  entity_text (host),
                                  entity_text (port),
                                  oid,
                                  threat_message_type (entity_text (threat)),
                                  entity_text (description));
            if (current_report) report_add_result (current_report, result);
          }

          (*next_result)++;
        }
      results = next_entities (results);
    }
  return 0;
}

/**
 * @brief Authenticate with a slave.
 *
 * @param[in]  session  GNUTLS session.
 * @param[in]  slave    Slave.
 *
 * @return 0 success, -1 error.
 */
int
slave_authenticate (gnutls_session_t *session, slave_t slave)
{
  int ret;
  gchar *login, *password;

  login = slave_login (slave);
  if (login == NULL)
    return -1;

  password = slave_password (slave);
  if (password == NULL)
    {
      g_free (login);
      return -1;
    }

  ret = omp_authenticate (session, login, password);
  g_free (login);
  g_free (password);
  if (ret)
    return -1;
  return 0;
}

/* Defined in omp.c. */
void buffer_config_preference_xml (GString *, iterator_t *, config_t);

/**
 * @brief Start a task on a slave.
 *
 * @param[in]   task        The task.
 * @param[out]  report_id   The report ID.
 * @param[in]   from        0 start from beginning, 1 continue from stopped, 2
 *                          continue if stopped else start from beginning.
 * @param[out]  target      Task target.
 * @param[out]  target_credential    Target credential.
 * @param[out]  last_stopped_report  Last stopped report if any, else 0.
 *
 * @return 0 success, -1 error.
 */
static int
run_slave_task (task_t task, char **report_id, int from, target_t target,
                lsc_credential_t target_credential,
                report_t last_stopped_report)
{
  slave_t slave;
  char *host, *name;
  int port, socket, ret, next_result;
  gnutls_session_t session;
  iterator_t credentials, targets;
  gchar *slave_credential_uuid = NULL, *slave_target_uuid, *slave_config_uuid;
  gchar *slave_task_uuid, *slave_report_uuid;

  /* Some of the cases in here must write to the session outside an open
   * statement.  For example, the omp_create_lsc_credential must come after
   * cleaning up the credential iterator.  This is because the slave may be
   * the master, and the open statement would prevent the slave from getting
   * a lock on the database and fulfilling the request. */

  tracef ("   Running slave task %llu\n", task);

  slave = task_slave (task);
  tracef ("   %s: slave: %llu\n", __FUNCTION__, slave);
  assert (slave);
  if (slave == 0) return -1;

  host = slave_host (slave);
  if (host == NULL) return -1;

  tracef ("   %s: host: %s\n", __FUNCTION__, host);

  port = slave_port (slave);
  if (port == -1)
    {
      free (host);
      return -1;
    }

  socket = openvas_server_open (&session, host, port);
  free (host);
  if (socket == -1) return -1;

  tracef ("   %s: connected\n", __FUNCTION__);

  name = openvas_uuid_make ();
  if (name == NULL)
    {
      openvas_server_close (socket, session);
      return -1;
    }

  /* Authenticate using the slave login. */

  if (slave_authenticate (&session, slave))
    goto fail;

  tracef ("   %s: authenticated\n", __FUNCTION__);

  if (last_stopped_report)
    {
      /* Resume the task on the slave. */

      slave_task_uuid = report_slave_task_uuid (last_stopped_report);
      if (slave_task_uuid == NULL)
        {
          /* This may happen if someone sets a slave on a local task.  Clear
           * all the report results and start the task from the beginning.  */
          trim_report (last_stopped_report);
          last_stopped_report = 0;
        }
      else switch (omp_resume_stopped_task_report (&session, slave_task_uuid,
                                                   &slave_report_uuid))
        {
          case 0:
            if (slave_report_uuid == NULL)
              goto fail;
            set_task_run_status (task, TASK_STATUS_REQUESTED);
            break;
          case 1:
            /* The resume may have failed because the task slave changed or
             * because someone removed the task on the slave.  Clear all the
             * report results and start the task from the beginning.
             *
             * This and the if above both "leak" the resources on the slave,
             * because on the report these resources are replaced with the new
             * resources. */
            trim_report (last_stopped_report);
            last_stopped_report = 0;
            break;
          default:
            free (slave_task_uuid);
            goto fail;
        }
    }

  if (last_stopped_report == 0)
    {
      /* Create the target credential on the slave. */

      init_lsc_credential_iterator (&credentials, target_credential, 1, NULL);
      if (next (&credentials))
        {
          const char *user, *password;
          gchar *user_copy, *password_copy;

          user = lsc_credential_iterator_login (&credentials);
          password = lsc_credential_iterator_password (&credentials);
#if 0
          /** @todo Need more OMP support for this. */
          public_key = lsc_credential_iterator_public_key (&credentials);
          private_key = lsc_credential_iterator_private_key (&credentials);
#endif

          if (user == NULL || password == NULL)
            {
              cleanup_iterator (&credentials);
              goto fail;
            }

          user_copy = g_strdup (user);
          password_copy = g_strdup (password);
          cleanup_iterator (&credentials);

          ret = omp_create_lsc_credential (&session, name, user_copy, password_copy,
                                           "Slave credential created by Master",
                                           &slave_credential_uuid);
          g_free (user_copy);
          g_free (password_copy);
          if (ret)
            goto fail;
        }

      tracef ("   %s: slave credential uuid: %s\n", __FUNCTION__,
              slave_credential_uuid);

      /* Create the target on the slave. */

      init_target_iterator (&targets, target, 1, NULL);
      if (next (&targets))
        {
          const char *hosts;
          gchar *hosts_copy;

          hosts = target_iterator_hosts (&targets);
          if (hosts == NULL)
            {
              cleanup_iterator (&targets);
              goto fail_credential;
            }

          hosts_copy = g_strdup (hosts);
          cleanup_iterator (&targets);

          ret = omp_create_target (&session, name, hosts_copy,
                                   "Slave target created by Master",
                                   slave_credential_uuid, &slave_target_uuid);
          g_free (hosts_copy);
          if (ret)
            goto fail_credential;
        }
      else
        {
          cleanup_iterator (&targets);
          goto fail_credential;
        }

      tracef ("   %s: slave target uuid: %s\n", __FUNCTION__, slave_target_uuid);

      /* Create the config on the slave. */

      {
        config_t config;
        iterator_t prefs, selectors;

        /* This must follow the GET_CONFIGS_RESPONSE export case. */

        config = task_config (task);
        if (config == 0)
          goto fail_target;

        if (openvas_server_sendf (&session,
                                  "<create_config>"
                                  "<get_configs_response"
                                  " status=\"200\""
                                  " status_text=\"OK\">"
                                  "<config id=\"XXX\">"
                                  "<name>%s</name>"
                                  "<comment>"
                                  "Slave config created by Master"
                                  "</comment>"
                                  "<preferences>",
                                  name))
          goto fail_target;

        init_nvt_preference_iterator (&prefs, NULL);
        while (next (&prefs))
          {
            GString *buffer = g_string_new ("");
            buffer_config_preference_xml (buffer, &prefs, config);
            if (openvas_server_send (&session, buffer->str))
              {
                cleanup_iterator (&prefs);
                goto fail_target;
              }
            g_string_free (buffer, TRUE);
          }
        cleanup_iterator (&prefs);

        if (openvas_server_send (&session,
                                 "</preferences>"
                                 "<nvt_selectors>"))
          {
            cleanup_iterator (&prefs);
            goto fail_target;
          }

        init_nvt_selector_iterator (&selectors,
                                    NULL,
                                    config,
                                    NVT_SELECTOR_TYPE_ANY);
        while (next (&selectors))
          {
            int type = nvt_selector_iterator_type (&selectors);
            if (openvas_server_sendf
                 (&session,
                  "<nvt_selector>"
                  "<name>%s</name>"
                  "<include>%i</include>"
                  "<type>%i</type>"
                  "<family_or_nvt>%s</family_or_nvt>"
                  "</nvt_selector>",
                  nvt_selector_iterator_name (&selectors),
                  nvt_selector_iterator_include (&selectors),
                  type,
                  (type == NVT_SELECTOR_TYPE_ALL
                    ? ""
                    : nvt_selector_iterator_nvt (&selectors))))
              goto fail_target;
          }
        cleanup_iterator (&selectors);

        if (openvas_server_send (&session,
                                 "</nvt_selectors>"
                                 "</config>"
                                 "</get_configs_response>"
                                 "</create_config>")
            || (omp_read_create_response (&session, &slave_config_uuid) != 201))
          goto fail_target;
      }

      tracef ("   %s: slave config uuid: %s\n", __FUNCTION__, slave_config_uuid);

      /* Create the task on the slave. */

      if (omp_create_task (&session, name, slave_config_uuid, slave_target_uuid,
                           "Slave task created by Master", &slave_task_uuid))
        goto fail_config;

      /* Start the task on the slave. */

      if (omp_start_task_report (&session, slave_task_uuid, &slave_report_uuid))
        goto fail_task;
      if (slave_report_uuid == NULL)
        goto fail_stop_task;

      set_report_slave_task_uuid (current_report, slave_task_uuid);
    }

  /* Setup the current task for functions like set_task_run_status. */

  current_scanner_task = task;

  /* Poll the slave until the task is finished. */

  next_result = 1;
  while (1)
    {
      entity_t get_tasks, report, get_report;
      const char *status;
      task_status_t run_status;

      /* Check if some other process changed the task status. */

      run_status = task_run_status (task);
      switch (run_status)
        {
          case TASK_STATUS_PAUSE_REQUESTED:
            if (omp_pause_task (&session, slave_task_uuid))
              goto fail_stop_task;
            set_task_run_status (current_scanner_task,
                                 TASK_STATUS_PAUSE_WAITING);
            break;
          case TASK_STATUS_RESUME_REQUESTED:
            if (omp_resume_paused_task (&session, slave_task_uuid))
              goto fail_stop_task;
            set_task_run_status (current_scanner_task,
                                 TASK_STATUS_RESUME_WAITING);
            break;
          case TASK_STATUS_STOP_REQUESTED:
            if (omp_stop_task (&session, slave_task_uuid))
              goto fail_stop_task;
            set_task_run_status (current_scanner_task,
                                 TASK_STATUS_STOP_WAITING);
            break;
          case TASK_STATUS_PAUSED:
            /* Keep doing the status checks even though the task is paused, in
             * case someone resumes the task on the slave. */
            break;
          case TASK_STATUS_STOPPED:
            assert (0);
            goto fail_stop_task;
            break;
          case TASK_STATUS_PAUSE_WAITING:
          case TASK_STATUS_RESUME_WAITING:
          case TASK_STATUS_DELETE_REQUESTED:
          case TASK_STATUS_DONE:
          case TASK_STATUS_NEW:
          case TASK_STATUS_REQUESTED:
          case TASK_STATUS_RUNNING:
          case TASK_STATUS_STOP_WAITING:
          case TASK_STATUS_INTERNAL_ERROR:
            break;
        }

      if (omp_get_tasks (&session, slave_task_uuid, 0, 0, &get_tasks))
        goto fail_task;

      status = omp_task_status (get_tasks);
      if ((strcmp (status, "Running") == 0)
          || (strcmp (status, "Done") == 0))
        {
          if ((run_status == TASK_STATUS_REQUESTED)
              || (run_status == TASK_STATUS_RESUME_WAITING)
              /* In case someone resumes the task on the slave. */
              || (run_status == TASK_STATUS_PAUSED))
            set_task_run_status (task, TASK_STATUS_RUNNING);

          if (update_slave_progress (get_tasks))
            {
              free_entity (get_tasks);
              goto fail_stop_task;
            }

          if (omp_get_report (&session, slave_report_uuid,
                              "d5da9f67-8551-4e51-807b-b6a873d70e34",
                              next_result,
                              &get_report))
            {
              free_entity (get_tasks);
              goto fail_stop_task;
            }

          if (update_from_slave (task, get_report, &report, &next_result))
            {
              free_entity (get_tasks);
              free_entity (get_report);
              goto fail_stop_task;
            }

          if (strcmp (status, "Running") == 0)
            free_entity (get_report);
        }
      else if (strcmp (status, "Paused") == 0)
        set_task_run_status (task, TASK_STATUS_PAUSED);
      else if (strcmp (status, "Pause Requested") == 0)
        set_task_run_status (task, TASK_STATUS_PAUSE_WAITING);
      else if (strcmp (status, "Stopped") == 0)
        {
          set_task_run_status (task, TASK_STATUS_STOPPED);
          goto succeed_stopped;
        }
      else if (strcmp (status, "Stop Requested") == 0)
        set_task_run_status (task, TASK_STATUS_STOP_WAITING);
      else if (strcmp (status, "Resume Requested") == 0)
        set_task_run_status (task, TASK_STATUS_RESUME_WAITING);
      else if ((strcmp (status, "Internal Error") == 0)
               || (strcmp (status, "Delete Requested") == 0))
        {
          free_entity (get_tasks);
          goto fail_stop_task;
        }

      if (strcmp (status, "Done") == 0)
        {
          entity_t end;
          entities_t entities;

          /* Set the host end times. */

          entities = report->entities;
          while ((end = first_entity (entities)))
            {
              if (strcmp (entity_name (end), "host_end") == 0)
                {
                  entity_t host;

                  host = entity_child (end, "host");
                  if (host == NULL)
                    {
                      free_entity (get_tasks);
                      free_entity (get_report);
                      goto fail_stop_task;
                    }

                  set_scan_host_end_time (current_report,
                                          entity_text (host),
                                          entity_text (end));
                }
              entities = next_entities (entities);
            }

          /* Set the scan end time. */

          entities = report->entities;
          while ((end = first_entity (entities)))
            {
              if (strcmp (entity_name (end), "scan_end") == 0)
                {
                  set_task_end_time (current_scanner_task,
                                     g_strdup (entity_text (end)));
                  set_scan_end_time (current_report, entity_text (end));
                  break;
                }
              entities = next_entities (entities);
            }

          free_entity (get_report);
          set_task_run_status (task, TASK_STATUS_DONE);
          break;
        }

      free_entity (get_tasks);

      sleep (25);
    }

  /* Cleanup. */

  current_scanner_task = (task_t) 0;

  omp_delete_task (&session, slave_task_uuid);
  set_report_slave_task_uuid (current_report, "");
  omp_delete_config (&session, slave_config_uuid);
  omp_delete_target (&session, slave_target_uuid);
  omp_delete_lsc_credential (&session, slave_credential_uuid);
 succeed_stopped:
  free (slave_task_uuid);
  free (slave_report_uuid);
  free (slave_config_uuid);
  free (slave_target_uuid);
  free (slave_credential_uuid);
  free (name);
  openvas_server_close (socket, session);
  return 0;

 fail_stop_task:
  omp_stop_task (&session, slave_task_uuid);
  free (slave_report_uuid);
 fail_task:
  omp_delete_task (&session, slave_task_uuid);
  set_report_slave_task_uuid (current_report, "");
  free (slave_task_uuid);
 fail_config:
  omp_delete_config (&session, slave_config_uuid);
  free (slave_config_uuid);
 fail_target:
  omp_delete_target (&session, slave_target_uuid);
  free (slave_target_uuid);
 fail_credential:
  omp_delete_lsc_credential (&session, slave_credential_uuid);
  free (slave_credential_uuid);
 fail:
  current_scanner_task = (task_t) 0;
  free (name);
  openvas_server_close (socket, session);
  return -1;
}

/**
 * @brief Start a task.
 *
 * Use \ref send_to_server to queue the task start sequence in the scanner
 * output buffer.
 *
 * Only one task can run at a time in a process.
 *
 * @param[in]   task       The task.
 * @param[out]  report_id  The report ID.
 * @param[in]   from       0 start from beginning, 1 continue from stopped, 2
 *                         continue if stopped else start from beginning.
 *
 * @return Before forking: 1 task is active already, -1 error,
 *         -2 task is missing a target, -3 creating the report failed,
 *         -4 target missing hosts, -6 already a task running in this process,
 *         -9 fork failed.
 *         After forking: 0 success (parent), 2 success (child),
 *         -10 error (child).
 */
static int
run_task (task_t task, char **report_id, int from)
{
  target_t target;
  char *hosts;
  gchar *plugins;
  int fail, pid;
  GSList *files = NULL;
  GPtrArray *preference_files;
  task_status_t run_status;
  config_t config;
  lsc_credential_t credential;
  report_t last_stopped_report;

  tracef ("   start task %u\n", task_id (task));

  if (set_task_requested (task, &run_status))
    return 1;

  /* Every fail exit from here must reset the run status. */

  if (current_scanner_task)
    {
      set_task_run_status (task, run_status);
      return -6;
    }

  target = task_target (task);
  if (target == 0)
    {
      tracef ("   task target is 0.\n");
      set_task_run_status (task, run_status);
      return -2;
    }

  hosts = target_hosts (target);
  if (hosts == NULL)
    {
      tracef ("   target hosts is NULL.\n");
      set_task_run_status (task, run_status);
      return -4;
    }

  credential = target_lsc_credential (target);

  if ((from == 1)
      || ((from == 2)
          && (run_status == TASK_STATUS_STOPPED)))
    {
      if (task_last_stopped_report (task, &last_stopped_report))
        {
          tracef ("   error getting last stopped report.\n");
          set_task_run_status (task, run_status);
          return -1;
        }

      /* Clear slave record, in case slave changed. */
      set_report_slave_task_uuid (last_stopped_report, "");

      current_report = last_stopped_report;
      if (report_id) *report_id = report_uuid (last_stopped_report);

      /* Remove partial host information from the report. */

      trim_partial_report (last_stopped_report);

      /* Ensure the report is marked as requested. */

      set_report_scan_run_status (current_report, TASK_STATUS_REQUESTED);

      /* Clear the end times of the task and partial report. */

      set_task_end_time (task, NULL);
      set_scan_end_time (last_stopped_report, NULL);
    }
  else if ((from == 0) || (from == 2))
    {
      last_stopped_report = 0;

      /* Create the report. */

      if (create_report (task, report_id, TASK_STATUS_REQUESTED))
        {
          free (hosts);
          set_task_run_status (task, run_status);
          return -3;
        }
    }
  else
    {
      /* "from" must be 0, 1 or 2. */
      assert (0);
      return -1;
    }

  /* Fork a child to start and handle the task while the parent responds to
   * the client. */

  pid = fork ();
  switch (pid)
    {
      case 0:
        /* Child.  Carry on starting the task, reopen the database (required
         * after fork). */
        reinit_manage_process ();
        break;
      case -1:
        /* Parent when error. */
        g_warning ("%s: failed to fork task child: %s\n",
                   __FUNCTION__,
                   strerror (errno));
        set_task_run_status (task, run_status);
        current_report = (report_t) 0;
        return -9;
        break;
      default:
        /* Parent.  Return, in order to respond to client. */
        current_report = (report_t) 0;
        return 0;
        break;
    }

  /* Every fail exit from here must reset to this run status, and must
   * clear current_report. */

  /** @todo On fail exits only, may need to honour request states that one of
   *        the other processes has set on the task (stop_task,
   *        request_delete_task). */

  /** @todo Also reset status on report, as current_scanner_task is 0 here. */

  run_status = TASK_STATUS_INTERNAL_ERROR;

  /* Reset any running information. */

  reset_task (task);

  if (task_slave (task))
    {
      if (run_slave_task (task, report_id, from, target, credential,
                          last_stopped_report))
        {
          free (hosts);
          set_task_run_status (task, run_status);
          exit (EXIT_FAILURE);
        }
      exit (EXIT_SUCCESS);
    }

  /* Send the preferences header. */

  if (send_to_server ("CLIENT <|> PREFERENCES <|>\n"))
    {
      free (hosts);
      set_task_run_status (task, run_status);
      current_report = (report_t) 0;
      return -10;
    }

  /* Get the config and selector. */

  config = task_config (task);
  if (config == 0)
    {
      free (hosts);
      tracef ("   task config is 0.\n");
      set_task_run_status (task, run_status);
      current_report = (report_t) 0;
      return -10;
    }

  /* Send the plugin list. */

  plugins = nvt_selector_plugins (config);
  if (plugins)
    fail = sendf_to_server ("plugin_set <|> %s\n", plugins);
  else
    fail = send_to_server ("plugin_set <|> 0\n");
  free (plugins);
  if (fail)
    {
      free (hosts);
      set_task_run_status (task, run_status);
      current_report = (report_t) 0;
      return -10;
    }

  /* Send some fixed preferences. */

  if (send_to_server ("ntp_keep_communication_alive <|> yes\n"))
    {
      free (hosts);
      set_task_run_status (task, run_status);
      current_report = (report_t) 0;
      return -10;
    }
  if (send_to_server ("ntp_client_accepts_notes <|> yes\n"))
    {
      free (hosts);
      set_task_run_status (task, run_status);
      current_report = (report_t) 0;
      return -10;
    }
  /** @todo Confirm this really stops scanner from sending FINISHED messages. */
  if (send_to_server ("ntp_opt_show_end <|> no\n"))
    {
      free (hosts);
      set_task_run_status (task, run_status);
      current_report = (report_t) 0;
      return -10;
    }
  if (send_to_server ("ntp_short_status <|> no\n"))
    {
      free (hosts);
      set_task_run_status (task, run_status);
      current_report = (report_t) 0;
      return -10;
    }

  /* Send the scanner preferences. */

  if (send_config_preferences (config, "SERVER_PREFS", NULL, NULL))
    {
      free (hosts);
      set_task_run_status (task, run_status);
      current_report = (report_t) 0;
      return -10;
    }

  /* Collect task files to send. */

  files = get_files_to_send (task);

  /* Send the plugins preferences. */

  preference_files = g_ptr_array_new ();
  if (send_config_preferences (config, "PLUGINS_PREFS", files, preference_files))
    {
      g_ptr_array_free (preference_files, TRUE);
      slist_free (files);
      free (hosts);
      set_task_run_status (task, run_status);
      current_report = (report_t) 0;
      return -10;
    }

  /* Send credential preferences if there's a credential linked to target. */

  if (credential)
    {
      iterator_t credentials;

      init_lsc_credential_iterator (&credentials, credential, 1, NULL);
      if (next (&credentials))
        {
          const char *user = lsc_credential_iterator_login (&credentials);
          const char *password = lsc_credential_iterator_password (&credentials);

          if (sendf_to_server ("SMB Authorization[entry]:SMB login: <|> %s\n",
                               user)
              || sendf_to_server ("SMB Authorization[password]:SMB password:"
                                  " <|> %s\n",
                                  password)
              || sendf_to_server ("SSH Authorization[entry]:SSH login name:"
                                  " <|> %s\n",
                                  user)
              || (lsc_credential_iterator_public_key (&credentials)
                   ? sendf_to_server ("SSH Authorization[password]:"
                                      "SSH key passphrase:"
                                      " <|> %s\n",
                                      password)
                   : sendf_to_server ("SSH Authorization[password]:"
                                      "SSH password (unsafe!):"
                                      " <|> %s\n",
                                      password)))

            {
 fail:
              free (hosts);
              cleanup_iterator (&credentials);
              g_ptr_array_add (preference_files, NULL);
              array_free (preference_files);
              slist_free (files);
              set_task_run_status (task, run_status);
              current_report = (report_t) 0;
              return -10;
            }

          if (lsc_credential_iterator_public_key (&credentials)
              && (strlen (lsc_credential_iterator_public_key (&credentials))
                  > 7))
            {
              gchar *public_key, *space;
              char *uuid = openvas_uuid_make ();
              if (uuid == NULL)
                goto fail;

              public_key = g_strdup (lsc_credential_iterator_public_key
                                      (&credentials)
                                     + 8);
              space = memchr (public_key, ' ', strlen (public_key));
              if (space)
                *space = '\0';

              g_ptr_array_add (preference_files, (gpointer) uuid);
              g_ptr_array_add (preference_files, (gpointer) public_key);

              if (sendf_to_server ("SSH Authorization[file]:"
                                   "SSH public key:"
                                   " <|> %s\n",
                                   uuid))
                goto fail;
            }

          if (lsc_credential_iterator_private_key (&credentials))
            {
              char *uuid = openvas_uuid_make ();
              if (uuid == NULL)
                goto fail;

              g_ptr_array_add (preference_files, (gpointer) uuid);
              g_ptr_array_add
               (preference_files,
                (gpointer) g_strdup (lsc_credential_iterator_private_key
                                      (&credentials)));

              if (sendf_to_server ("SSH Authorization[file]:"
                                   "SSH private key:"
                                   " <|> %s\n",
                                   uuid))
                goto fail;
            }
        }
      cleanup_iterator (&credentials);
    }

  g_ptr_array_add (preference_files, NULL);

  if (send_to_server ("<|> CLIENT\n"))
    {
      free (hosts);
      array_free (preference_files);
      slist_free (files);
      set_task_run_status (task, run_status);
      current_report = (report_t) 0;
      return -10;
    }

  /* Send any files stored in the config preferences. */

  {
    gchar *file;
    int index = 0;
    while ((file = g_ptr_array_index (preference_files, index)))
      {
        GSList *head;
        gchar *value;

        index++;

        /* Skip the file if the value of the preference is the name of a
         * file associated with the task. */
        value = g_ptr_array_index (preference_files, index);
        head = files;
        while (head)
          {
            if (strcmp (head->data, value) == 0)
              break;
            head = g_slist_next (head);
          }

        if (head == NULL && send_file (file, value))
          {
            free (hosts);
            array_free (preference_files);
            slist_free (files);
            set_task_run_status (task, run_status);
            current_report = (report_t) 0;
            return -10;
          }
        index++;
      }

    array_free (preference_files);
  }

  /* Send any files. */

  while (files)
    {
      GSList *last = files;
      if (send_task_file (task, files->data))
        {
          free (hosts);
          slist_free (files);
          set_task_run_status (task, run_status);
          current_report = (report_t) 0;
          return -10;
        }
      files = g_slist_next (files);
      g_free (last->data);
      g_slist_free_1 (last);
    }

  /* Send the rules. */

  if (send_to_server ("CLIENT <|> RULES <|>\n"))
    {
      free (hosts);
      set_task_run_status (task, run_status);
      current_report = (report_t) 0;
      return -10;
    }

  if (send_user_rules (last_stopped_report))
    {
      free (hosts);
      set_task_run_status (task, run_status);
      current_report = (report_t) 0;
      return -10;
    }

  if (send_to_server ("<|> CLIENT\n"))
    {
      free (hosts);
      set_task_run_status (task, run_status);
      current_report = (report_t) 0;
      return -10;
    }

  /* Send the attack command. */

  /* Send all the hosts to the Scanner.  When resuming a stopped task,
   * the hosts that have been completely scanned are excluded by being
   * included in the RULES above. */
  fail = sendf_to_server ("CLIENT <|> LONG_ATTACK <|>\n%d\n%s\n",
                          strlen (hosts),
                          hosts);
  free (hosts);
  if (fail)
    {
      set_task_run_status (task, run_status);
      current_report = (report_t) 0;
      return -10;
    }
  scanner_active = 1;

  current_scanner_task = task;

#if 0
  /** @todo This is what the file based tasks did. */
  if (task->open_ports) (void) g_array_free (task->open_ports, TRUE);
  task->open_ports = g_array_new (FALSE, FALSE, (guint) sizeof (port_t));
  task->open_ports_size = 0;
#endif

  return 2;
}

/**
 * @brief Start a task.
 *
 * Use \ref send_to_server to queue the task start sequence in the scanner
 * output buffer.
 *
 * Only one task can run at a time in a process.
 *
 * @param[in]   task       The task.
 * @param[out]  report_id  The report ID.
 *
 * @return Before forking: 1 task is active already,
 *         -2 task is missing a target, -3 creating the report failed,
 *         -4 target missing hosts, -6 already a task running in this process,
 *         -9 fork failed.
 *         After forking: 0 success (parent), 2 success (child),
 *         -10 error (child).
 */
int
start_task (task_t task, char **report_id)
{
  return run_task (task, report_id, 0);
}

/**
 * @brief Initiate stopping a task.
 *
 * Use \ref send_to_server to queue the task stop sequence in the
 * scanner output buffer.
 *
 * @param[in]  task  A pointer to the task.
 *
 * @return 0 on success, 1 if stop requested, -1 if out of space in scanner
 *         output buffer.
 */
int
stop_task (task_t task)
{
  task_status_t run_status;
  tracef ("   request task stop %u\n", task_id (task));
  run_status = task_run_status (task);
  if (run_status == TASK_STATUS_PAUSE_REQUESTED
      || run_status == TASK_STATUS_PAUSE_WAITING
      || run_status == TASK_STATUS_PAUSED
      || run_status == TASK_STATUS_RESUME_REQUESTED
      || run_status == TASK_STATUS_RESUME_WAITING
      || run_status == TASK_STATUS_REQUESTED
      || run_status == TASK_STATUS_RUNNING)
    {
      if (current_scanner_task == task
          && send_to_server ("CLIENT <|> STOP_WHOLE_TEST <|> CLIENT\n"))
        return -1;
      set_task_run_status (task, TASK_STATUS_STOP_REQUESTED);
      return 1;
    }
  return 0;
}

/**
 * @brief Initiate pausing of a task.
 *
 * Use \ref send_to_server to queue the task pause sequence in the
 * scanner output buffer.
 *
 * @param[in]  task  A pointer to the task.
 *
 * @return 0 on success, 1 if pause requested, -1 if out of space in scanner
 *         output buffer.
 */
int
pause_task (task_t task)
{
  task_status_t run_status;
  tracef ("   request task pause %u\n", task_id (task));
  run_status = task_run_status (task);
  if (run_status == TASK_STATUS_REQUESTED
      || run_status == TASK_STATUS_RUNNING)
    {
      if (current_scanner_task == task
          && send_to_server ("CLIENT <|> PAUSE_WHOLE_TEST <|> CLIENT\n"))
        return -1;
      set_task_run_status (task, TASK_STATUS_PAUSE_REQUESTED);
      return 1;
    }
  return 0;
}

/**
 * @brief Initiate resuming of a task.
 *
 * Use \ref send_to_server to queue the task resume sequence in the
 * scanner output buffer.
 *
 * @param[in]  task  A pointer to the task.
 *
 * @return 0 on success, 1 if resume requested, -1 if out of space in scanner
 *         output buffer.
 */
int
resume_paused_task (task_t task)
{
  task_status_t run_status;
  tracef ("   request task resume %u\n", task_id (task));
  run_status = task_run_status (task);
  if (run_status == TASK_STATUS_PAUSE_REQUESTED
      || run_status == TASK_STATUS_PAUSED)
    {
      if (current_scanner_task == task
          && send_to_server ("CLIENT <|> RESUME_WHOLE_TEST <|> CLIENT\n"))
        return -1;
      set_task_run_status (task, TASK_STATUS_RESUME_REQUESTED);
      return 1;
    }
  return 0;
}

/**
 * @brief Resume a stopped task.
 *
 * @param[in]   task       A pointer to the task.
 * @param[out]  report_id  If successful, ID of the resultant report.
 *
 * @return 22 caller error (task must be in "stopped" state), -1 error or any
 *         start_task error.
 */
int
resume_stopped_task (task_t task, char **report_id)
{
  task_status_t run_status;
  run_status = task_run_status (task);
  if (run_status == TASK_STATUS_STOPPED)
    return run_task (task, report_id, 1);
  return 22;
}

/**
 * @brief Resume task if stopped, else start task.
 *
 * Only one task can run at a time in a process.
 *
 * @param[in]   task       The task.
 * @param[out]  report_id  The report ID.
 *
 * @return 23 caller error (task must be in "stopped" state), -1 error or any
 *         start_task error.
 */
int
resume_or_start_task (task_t task, char **report_id)
{
  return run_task (task, report_id, 2);
}


/* Scanner messaging. */

/**
 * @brief Request the list of certificates from the scanner.
 *
 * @return 0 on success, -1 if out of space in scanner output buffer.
 */
int
request_certificates ()
{
  if (send_to_server ("CLIENT <|> CERTIFICATES <|> CLIENT\n"))
    return -1;
  return 0;
}

/**
 * @brief Acknowledge a scanner BYE.
 *
 * @return 0 on success, -1 if out of space in scanner output buffer.
 */
int
acknowledge_bye ()
{
  if (send_to_server ("CLIENT <|> BYE <|> ACK\n"))
    return -1;
  return 0;
}

/**
 * @brief Acknowledge the scanner PLUGINS_MD5 message.
 *
 * @return 0 on success, -1 if out of space in scanner output buffer.
 */
int
acknowledge_md5sum ()
{
  if (send_to_server ("CLIENT <|> GO ON <|> CLIENT\n"))
    return -1;
  return 0;
}

/**
 * @brief Acknowledge scanner PLUGINS_MD5 message, requesting plugin md5sums.
 *
 * @return 0 on success, -1 if out of space in scanner output buffer.
 */
int
acknowledge_md5sum_sums ()
{
  if (send_to_server ("CLIENT <|> SEND_PLUGINS_MD5 <|> CLIENT\n"))
    return -1;
  return 0;
}

/**
 * @brief Acknowledge scanner PLUGINS_MD5 message, requesting all plugin info.
 *
 * @return 0 on success, -1 if out of space in scanner output buffer.
 */
int
acknowledge_md5sum_info ()
{
  if (send_to_server ("CLIENT <|> COMPLETE_LIST <|> CLIENT\n"))
    return -1;
  return 0;
}

/**
 * @brief Handle state changes to current task made by other processes.
 *
 * @return 0 on success, -1 if out of space in scanner output buffer, 1 if
 *         queued to scanner.
 */
int
manage_check_current_task ()
{
  if (current_scanner_task)
    {
      task_status_t run_status;

      /* Check if some other process changed the status. */

      run_status = task_run_status (current_scanner_task);
      switch (run_status)
        {
          case TASK_STATUS_PAUSE_REQUESTED:
            if (send_to_server ("CLIENT <|> PAUSE_WHOLE_TEST <|> CLIENT\n"))
              return -1;
            set_task_run_status (current_scanner_task,
                                 TASK_STATUS_PAUSE_WAITING);
            return 1;
            break;
          case TASK_STATUS_RESUME_REQUESTED:
            if (send_to_server ("CLIENT <|> RESUME_WHOLE_TEST <|> CLIENT\n"))
              return -1;
            set_task_run_status (current_scanner_task,
                                 TASK_STATUS_RESUME_WAITING);
            return 1;
            break;
          case TASK_STATUS_STOP_REQUESTED:
            if (send_to_server ("CLIENT <|> STOP_WHOLE_TEST <|> CLIENT\n"))
              return -1;
            set_task_run_status (current_scanner_task,
                                 TASK_STATUS_STOP_WAITING);
            return 1;
            break;
          case TASK_STATUS_DELETE_REQUESTED:
          case TASK_STATUS_DONE:
          case TASK_STATUS_NEW:
          case TASK_STATUS_REQUESTED:
          case TASK_STATUS_RESUME_WAITING:
          case TASK_STATUS_RUNNING:
          case TASK_STATUS_PAUSE_WAITING:
          case TASK_STATUS_PAUSED:
          case TASK_STATUS_STOP_WAITING:
          case TASK_STATUS_STOPPED:
          case TASK_STATUS_INTERNAL_ERROR:
            break;
        }
    }
  return 0;
}


/* System reports. */

/**
 * @brief Get system report types from a slave.
 *
 * @param[in]   required_type  Single type to limit types to.
 * @param[out]  types          Types on success.
 * @param[out]  start          Actual start of types, which caller must free.
 * @param[out]  slave_id       ID of slave.
 *
 * @return 0 if successful, 2 failed to find slave, -1 otherwise.
 */
static int
get_slave_system_report_types (const char *required_type, gchar ***start,
                               gchar ***types, const char *slave_id)
{
  slave_t slave = 0;
  char *host, **end;
  int port, socket;
  gnutls_session_t session;
  entity_t get, report;
  entities_t reports;

  if (find_slave (slave_id, &slave))
    return -1;
  if (slave == 0)
    return 2;

  host = slave_host (slave);
  if (host == NULL) return -1;

  tracef ("   %s: host: %s\n", __FUNCTION__, host);

  port = slave_port (slave);
  if (port == -1)
    {
      free (host);
      return -1;
    }

  socket = openvas_server_open (&session, host, port);
  free (host);
  if (socket == -1) return -1;

  tracef ("   %s: connected\n", __FUNCTION__);

  /* Authenticate using the slave login. */

  if (slave_authenticate (&session, slave))
    goto fail;

  tracef ("   %s: authenticated\n", __FUNCTION__);

  if (omp_get_system_reports (&session, required_type, 1, &get))
    goto fail;

  openvas_server_close (socket, session);

  reports = get->entities;
  end = *types = *start = g_malloc ((xml_count_entities (reports) + 1)
                                    * sizeof (gchar*));
  while ((report = first_entity (reports)))
    {
      if (strcmp (entity_name (report), "system_report") == 0)
        {
          entity_t name, title;
          gchar *pair;
          char *name_text, *title_text;
          name = entity_child (report, "name");
          title = entity_child (report, "title");
          if (name == NULL || title == NULL)
            {
              *end = NULL;
              g_strfreev (*start);
              free_entity (get);
              return -1;
            }
          name_text = entity_text (name);
          title_text = entity_text (title);
          *end = pair = g_malloc (strlen (name_text) + strlen (title_text) + 2);
          strcpy (pair, name_text);
          pair += strlen (name_text) + 1;
          strcpy (pair, title_text);
          end++;
        }
      reports = next_entities (reports);
    }
  *end = NULL;

  free_entity (get);

  return 0;

 fail:
  openvas_server_close (socket, session);
  return -1;
}

/**
 * @brief Command called by get_system_report_types.
 */
#define COMMAND "openvasmr 0 titles"

/**
 * @brief Get system report types.
 *
 * @param[in]   required_type  Single type to limit types to.
 * @param[out]  types          Types on success.
 * @param[out]  start          Actual start of types, which caller must free.
 * @param[out]  slave_id       ID of slave.
 *
 * @return 0 if successful, 1 failed to find report type, 2 failed to find
 *         slave, -1 otherwise.
 */
static int
get_system_report_types (const char *required_type, gchar ***start,
                         gchar ***types, const char *slave_id)
{
  gchar *astdout = NULL;
  gchar *astderr = NULL;
  GError *err = NULL;
  gint exit_status;

  if (slave_id && strcmp (slave_id, "0"))
    return get_slave_system_report_types (required_type, start, types,
                                          slave_id);

  tracef ("   command: " COMMAND);

  if ((g_spawn_command_line_sync (COMMAND,
                                  &astdout,
                                  &astderr,
                                  &exit_status,
                                  &err)
       == FALSE)
      || (WIFEXITED (exit_status) == 0)
      || WEXITSTATUS (exit_status))
    {
      tracef ("%s: openvasmr failed with %d", __FUNCTION__, exit_status);
      tracef ("%s: stdout: %s", __FUNCTION__, astdout);
      tracef ("%s: stderr: %s", __FUNCTION__, astderr);
      g_free (astdout);
      g_free (astderr);
      return -1;
    }
  if (astdout)
    {
      char **type;
      *start = *types = type = g_strsplit (g_strchomp (astdout), "\n", 0);
      while (*type)
        {
          char *space;
          space = strchr (*type, ' ');
          if (space == NULL)
            {
              g_strfreev (*types);
              *types = NULL;
              g_free (astdout);
              g_free (astderr);
              return -1;
            }
          *space = '\0';
          if (required_type && (strcmp (*type, required_type) == 0))
            {
              char **next;
              /* Found the single given type. */
              next = type + 1;
              while (*next)
                {
                  free (*next);
                  next++;
                }
              next = type + 1;
              *next = NULL;
              *types = type;
              g_free (astdout);
              g_free (astderr);
              return 0;
            }
          type++;
        }
      if (required_type)
        {
          /* Failed to find the single given type. */
          g_free (astdout);
          g_free (astderr);
          g_strfreev (*types);
          return 1;
        }
    }
  else
    *start = *types = g_malloc0 (sizeof (gchar*));

  g_free (astdout);
  g_free (astderr);
  return 0;
}

#undef COMMAND

/**
 * @brief Initialise a system report type iterator.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  type        Single report type to iterate over, NULL for all.
 * @param[in]  slave_id    ID of slave to get reports from.  0 for local.
 *
 * @return 0 on success, 1 failed to find report type, 2 failed to find slave,
 *         -1 on error.
 */
int
init_system_report_type_iterator (report_type_iterator_t* iterator,
                                  const char* type,
                                  const char* slave_id)
{
  int ret;
  ret = get_system_report_types (type, &iterator->start, &iterator->current,
                                 slave_id);
  if (ret)
    return ret;
  iterator->current--;
  return 0;
}

/**
 * @brief Cleanup a report type iterator.
 *
 * @param[in]  iterator  Iterator.
 */
void
cleanup_report_type_iterator (report_type_iterator_t* iterator)
{
  g_strfreev (iterator->start);
}

/**
 * @brief Increment a report type iterator.
 *
 * The caller must stop using this after it returns FALSE.
 *
 * @param[in]  iterator  Task iterator.
 *
 * @return TRUE if there was a next item, else FALSE.
 */
gboolean
next_report_type (report_type_iterator_t* iterator)
{
  iterator->current++;
  if (*iterator->current == NULL) return FALSE;
  return TRUE;
}

/**
 * @brief Return the name from a report type iterator.
 *
 * @param[in]  iterator  Iterator.
 */
const char*
report_type_iterator_name (report_type_iterator_t* iterator)
{
  return (const char*) *iterator->current;
}

/**
 * @brief Return the title from a report type iterator.
 *
 * @param[in]  iterator  Iterator.
 */
const char*
report_type_iterator_title (report_type_iterator_t* iterator)
{
  const char *name = *iterator->current;
  return name + strlen (name) + 1;
}

/**
 * @brief Get a system report from a slave.
 *
 * @param[in]   name      Name of report.
 * @param[in]   duration  Time range of report, in seconds.
 * @param[in]   slave_id  ID of slave to get report from.  0 for local.
 * @param[out]  report    On success, report in base64 if such a report exists
 *                        else NULL.  Arbitrary on error.
 *
 * @return 0 if successful, 2 failed to find slave, -1 otherwise.
 */
static int
slave_system_report (const char *name, const char *duration,
                     const char *slave_id, char **report)
{
  slave_t slave = 0;
  char *host;
  int port, socket;
  gnutls_session_t session;
  entity_t get, entity;
  entities_t reports;

  if (find_slave (slave_id, &slave))
    return -1;
  if (slave == 0)
    return 2;

  host = slave_host (slave);
  if (host == NULL) return -1;

  tracef ("   %s: host: %s\n", __FUNCTION__, host);

  port = slave_port (slave);
  if (port == -1)
    {
      free (host);
      return -1;
    }

  socket = openvas_server_open (&session, host, port);
  free (host);
  if (socket == -1) return -1;

  tracef ("   %s: connected\n", __FUNCTION__);

  /* Authenticate using the slave login. */

  if (slave_authenticate (&session, slave))
    goto fail;

  tracef ("   %s: authenticated\n", __FUNCTION__);

  if (omp_get_system_reports (&session, name, 0, &get))
    goto fail;

  openvas_server_close (socket, session);

  reports = get->entities;
  if ((entity = first_entity (reports))
      && (strcmp (entity_name (entity), "system_report") == 0))
    {
      entity = entity_child (entity, "report");
      if (entity)
        {
          *report = g_strdup (entity_text (entity));
          return 0;
        }
    }

  free_entity (get);
  return -1;

 fail:
  openvas_server_close (socket, session);
  return -1;
}

/**
 * @brief Get a system report.
 *
 * @param[in]   name      Name of report.
 * @param[in]   duration  Time range of report, in seconds.
 * @param[in]   slave_id  ID of slave to get report from.  0 for local.
 * @param[out]  report    On success, report in base64 if such a report exists
 *                        else NULL.  Arbitrary on error.
 *
 * @return 0 if successful (including failure to find report), -1 on error.
 */
int
manage_system_report (const char *name, const char *duration,
                      const char *slave_id, char **report)
{
  gchar *astdout = NULL;
  gchar *astderr = NULL;
  GError *err = NULL;
  gint exit_status;
  gchar *command;

  assert (name);

  if (duration == NULL)
    duration = "86400";

  if (slave_id && strcmp (slave_id, "0"))
    return slave_system_report (name, duration, slave_id, report);

  /* For simplicity, it's up to the command to do the base64 encoding. */
  command = g_strdup_printf ("openvasmr %s %s", duration, name);

  tracef ("   command: %s", command);

  if ((g_spawn_command_line_sync (command,
                                  &astdout,
                                  &astderr,
                                  &exit_status,
                                  &err)
       == FALSE)
      || (WIFEXITED (exit_status) == 0)
      || WEXITSTATUS (exit_status))
    {
      tracef ("%s: openvasmr failed with %d", __FUNCTION__, exit_status);
      tracef ("%s: stdout: %s", __FUNCTION__, astdout);
      tracef ("%s: stderr: %s", __FUNCTION__, astderr);
      g_free (astdout);
      g_free (astderr);
      g_free (command);
      return -1;
    }
  g_free (astderr);
  g_free (command);
  if (astdout == NULL || strlen (astdout) == 0)
    {
      g_free (astdout);
      if (strcmp (name, "blank") == 0)
        return -1;
      return manage_system_report ("blank", duration, NULL, report);
    }
  else
    *report = astdout;
  return 0;
}


/* Scheduling. */

/**
 * @brief Flag for manage_auth_allow_all.
 */
int authenticate_allow_all = 0;

/**
 * @brief UUID of user whose scheduled task is to be started (in connection
 *        with authenticate_allow_all).
 */
gchar* schedule_user_uuid = 0;

/**
 * @brief Ensure that any subsequent authentications succeed.
 */
void
manage_auth_allow_all ()
{
  authenticate_allow_all = 1;
}

/**
 * @brief Access UUID of user that scheduled the current task.
 *
 * @return UUID of user that scheduled the current task.
 */
gchar*
get_scheduled_user_uuid ()
{
  return schedule_user_uuid;
}

/**
 * @brief Set UUID of user that scheduled the current task.
 *
 * @param user_uuid UUID of user that scheduled the current task.
 */
void
set_scheduled_user_uuid (gchar* user_uuid)
{
  schedule_user_uuid = user_uuid;
}

/**
 * @brief Schedule any actions that are due.
 *
 * In openvasmd, periodically called from the main daemon loop.
 *
 * @param[in]  fork_connection  Function that forks a child which is connected
 *                              to the Manager.  Must return 0 in parent, PID
 *                              in child, or -1 on error.
 *
 * @return 0 success, -1 error.
 */
int
manage_schedule (int (*fork_connection) (int *,
                                         gnutls_session_t *,
                                         gnutls_certificate_credentials_t *,
                                         gchar*))
{
  iterator_t schedules;
  GSList *starts = NULL, *stops = NULL;

  manage_update_nvti_cache ();

  /* Assemble "starts" and "stops" list containing task uuid and owner name
   * for each (scheduled) task to start or stop. */

  init_task_schedule_iterator (&schedules);
  /* This iterator runs in an exclusive transaction, so this loop is atomic. */
  while (next (&schedules))
    if (task_schedule_iterator_start_due (&schedules))
      {
        time_t period, period_months;

        /* Update the task schedule info to prevent multiple schedules. */

        period = task_schedule_iterator_period (&schedules);
        period_months = task_schedule_iterator_period_months (&schedules);

        if (period)
          {
            time_t now = time (NULL);
            time_t first = task_schedule_iterator_first_time (&schedules);
            time_t duration = task_schedule_iterator_duration (&schedules);

            assert (first <= now);

            set_task_schedule_next_time
             (task_schedule_iterator_task (&schedules),
              first + ((((now - first) / period) + 1) * period));

            /* Ensure that the task starts within the duration if it has one. */
            if (duration && (((now - first) % period) > duration))
              continue;

            /* Ensure that the task is scheduled within a short interval after
             * the start of the period.
             *
             * A periodic task that becomes due while the previous instantiation
             * of the task is still running will be runnable as soon as the
             * previous instantiation completes.  This could be any time, so
             * skip the task and let is start again at the proper time. */
            if (((now - first) % period) > (3 * 60))
              continue;
          }
        else if (period_months)
          {
            time_t now = time (NULL);
            time_t first = task_schedule_iterator_first_time (&schedules);
            time_t duration = task_schedule_iterator_duration (&schedules);

            assert (first <= now);

            set_task_schedule_next_time
             (task_schedule_iterator_task (&schedules),
              add_months (first, months_between (first, now) + 1));

            /* Ensure that the task starts within the duration if it has one. */
            if (duration
                && ((now - add_months (first, months_between (first, now)))
                    > duration))
              continue;

            /* Ensure that the task is scheduled within a short interval after
             * the start of the period.
             *
             * A periodic task that becomes due while the previous instantiation
             * of the task is still running will be runnable as soon as the
             * previous instantiation completes.  This could be any time, so
             * skip the task and let is start again at the proper time. */
            if ((now - add_months (first, months_between (first, now)))
                > (3 * 60))
              continue;
          }
        else
          set_task_schedule_next_time
           (task_schedule_iterator_task (&schedules), 0);

        /* Add task UUID and owner name and UUID to the list. */

        starts = g_slist_prepend
                  (starts,
                   g_strdup (task_schedule_iterator_task_uuid (&schedules)));
        starts = g_slist_prepend
                  (starts,
                   g_strdup (task_schedule_iterator_owner_uuid (&schedules)));
        starts = g_slist_prepend
                  (starts,
                   g_strdup (task_schedule_iterator_owner_name (&schedules)));
      }
    else if (task_schedule_iterator_stop_due (&schedules))
      {
        /* Add task UUID and owner name and UUID to the list. */

        stops = g_slist_prepend
                 (stops,
                  g_strdup (task_schedule_iterator_task_uuid (&schedules)));
        stops = g_slist_prepend
                 (stops,
                  g_strdup (task_schedule_iterator_owner_uuid (&schedules)));
        stops = g_slist_prepend
                 (stops,
                  g_strdup (task_schedule_iterator_owner_name (&schedules)));
      }
  cleanup_task_schedule_iterator (&schedules);

  /* Start tasks in forked processes, now that the SQL statement is closed. */

  while (starts)
    {
      int socket;
      gnutls_session_t session;
      gnutls_certificate_credentials_t credentials;
      gchar *task_uuid, *owner, *owner_uuid;
      GSList *head;

      owner = starts->data;
      assert (starts->next);
      owner_uuid = starts->next->data;
      assert (starts->next->next);
      task_uuid = starts->next->next->data;

      head = starts;
      starts = starts->next->next->next;
      g_slist_free_1 (head->next->next);
      g_slist_free_1 (head->next);
      g_slist_free_1 (head);

      /* Run the callback to fork a child connected to the Manager. */

      switch (fork_connection (&socket, &session, &credentials, owner_uuid))
        {
          case 0:
            /* Parent.  Continue to next task. */
            g_free (task_uuid);
            g_free (owner);
            g_free (owner_uuid);
            continue;
            break;

          case -1:
            /* Parent on error. */
            g_free (task_uuid);
            g_free (owner);
            g_free (owner_uuid);
            while (starts)
              {
                g_free (starts->data);
                starts = g_slist_delete_link (starts, starts);
              }
            return -1;
            break;

          default:
            /* Child.  Break, start task, exit. */
            while (starts)
              {
                g_free (starts->data);
                starts = g_slist_delete_link (starts, starts);
              }
            break;
        }

      /* Start the task. */

      if (omp_authenticate (&session, owner, ""))
        {
          g_free (task_uuid);
          g_free (owner);
          g_free (owner_uuid);
          openvas_server_free (socket, session, credentials);
          exit (EXIT_FAILURE);
        }

      if (omp_resume_or_start_task (&session, task_uuid))
        {
          g_free (task_uuid);
          g_free (owner);
          g_free (owner_uuid);
          openvas_server_free (socket, session, credentials);
          exit (EXIT_FAILURE);
        }

      g_free (task_uuid);
      g_free (owner);
      g_free (owner_uuid);
      openvas_server_free (socket, session, credentials);
      exit (EXIT_SUCCESS);
   }

  /* Stop tasks in forked processes, now that the SQL statement is closed. */

  while (stops)
    {
      int socket;
      gnutls_session_t session;
      gnutls_certificate_credentials_t credentials;
      gchar *task_uuid, *owner, *owner_uuid;
      GSList *head;

      owner = stops->data;
      assert (stops->next);
      owner_uuid = stops->next->data;
      assert (stops->next->next);
      task_uuid = stops->next->next->data;

      head = stops;
      stops = stops->next->next->next;
      g_slist_free_1 (head->next->next);
      g_slist_free_1 (head->next);
      g_slist_free_1 (head);

      /* Run the callback to fork a child connected to the Manager. */

      switch (fork_connection (&socket, &session, &credentials, owner_uuid))
        {
          case 0:
            /* Parent.  Continue to next task. */
            g_free (task_uuid);
            g_free (owner);
            g_free (owner_uuid);
            continue;
            break;

          case -1:
            /* Parent on error. */
            g_free (task_uuid);
            g_free (owner);
            g_free (owner_uuid);
            while (stops)
              {
                g_free (stops->data);
                stops = g_slist_delete_link (stops, stops);
              }
            return -1;
            break;

          default:
            /* Child.  Break, stop task, exit. */
            while (stops)
              {
                g_free (stops->data);
                stops = g_slist_delete_link (stops, stops);
              }
            break;
        }

      /* Stop the task. */

      if (omp_authenticate (&session, owner, ""))
        {
          g_free (task_uuid);
          g_free (owner);
          g_free (owner_uuid);
          openvas_server_free (socket, session, credentials);
          exit (EXIT_FAILURE);
        }

      if (omp_stop_task (&session, task_uuid))
        {
          g_free (task_uuid);
          g_free (owner);
          g_free (owner_uuid);
          openvas_server_free (socket, session, credentials);
          exit (EXIT_FAILURE);
        }

      g_free (task_uuid);
      g_free (owner);
      g_free (owner_uuid);
      openvas_server_free (socket, session, credentials);
      exit (EXIT_SUCCESS);
   }

  return 0;
}


/* Report formats. */

/**
 * @brief Get the name of a report format param type.
 *
 * @param[in]  type  Param type.
 *
 * @return The name of the param type.
 */
const char *
report_format_param_type_name (report_format_param_type_t type)
{
  switch (type)
    {
      case REPORT_FORMAT_PARAM_TYPE_BOOLEAN:
        return "boolean";
      case REPORT_FORMAT_PARAM_TYPE_INTEGER:
        return "integer";
      case REPORT_FORMAT_PARAM_TYPE_SELECTION:
        return "selection";
      case REPORT_FORMAT_PARAM_TYPE_STRING:
        return "string";
      case REPORT_FORMAT_PARAM_TYPE_TEXT:
        return "text";
      default:
        assert (0);
      case REPORT_FORMAT_PARAM_TYPE_ERROR:
        return "ERROR";
    }
}

/**
 * @brief Get a report format param type from a name.
 *
 * @param[in]  name  Param type name.
 *
 * @return The param type.
 */
report_format_param_type_t
report_format_param_type_from_name (const char *name)
{
  if (strcmp (name, "boolean") == 0)
    return REPORT_FORMAT_PARAM_TYPE_BOOLEAN;
  if (strcmp (name, "integer") == 0)
    return REPORT_FORMAT_PARAM_TYPE_INTEGER;
  if (strcmp (name, "selection") == 0)
    return REPORT_FORMAT_PARAM_TYPE_SELECTION;
  if (strcmp (name, "string") == 0)
    return REPORT_FORMAT_PARAM_TYPE_STRING;
  if (strcmp (name, "text") == 0)
    return REPORT_FORMAT_PARAM_TYPE_TEXT;
  return REPORT_FORMAT_PARAM_TYPE_ERROR;
}

/**
 * @brief Return whether a name is a backup file name.
 *
 * @return 0 if normal file name, 1 if backup file name.
 */
static int
backup_file_name (const char *name)
{
  int length = strlen (name);

  if (length && (name[length - 1] == '~'))
    return 1;

  if ((length > 3)
      && (name[length - 4] == '.'))
    return ((name[length - 3] == 'b')
            && (name[length - 2] == 'a')
            && (name[length - 1] == 'k'))
           || ((name[length - 3] == 'B')
               && (name[length - 2] == 'A')
               && (name[length - 1] == 'K'))
           || ((name[length - 3] == 'C')
               && (name[length - 2] == 'K')
               && (name[length - 1] == 'P'));

  return 0;
}

/**
 * @brief Get files associated with a report format.
 *
 * @param[in]   dir_name  Location of files.
 * @param[out]  start     Files on success.
 *
 * @return 0 if successful, -1 otherwise.
 */
static int
get_report_format_files (const char *dir_name, GPtrArray **start)
{
  GPtrArray *files;
  struct dirent **names;
  int n, index;

  files = g_ptr_array_new ();

  n = scandir (dir_name, &names, NULL, alphasort);
  if (n < 0)
    {
      g_warning ("%s: failed to open dir %s: %s\n",
                 __FUNCTION__,
                 dir_name,
                 strerror (errno));
      return -1;
    }

  for (index = 0; index < n; index++)
    {
      if (strcmp (names[index]->d_name, ".")
          && strcmp (names[index]->d_name, "..")
          && (backup_file_name (names[index]->d_name) == 0))
        g_ptr_array_add (files, g_strdup (names[index]->d_name));
      free (names[index]);
    }
  free (names);

  g_ptr_array_add (files, NULL);

  *start = files;
  return 0;
}

/**
 * @brief Initialise a report format file iterator.
 *
 * @param[in]  iterator       Iterator.
 * @param[in]  report_format  Single report format to iterate over, NULL for
 *                            all.
 *
 * @return 0 on success, -1 on error.
 */
int
init_report_format_file_iterator (file_iterator_t* iterator,
                                  report_format_t report_format)
{
  gchar *dir_name, *uuid;

  uuid = report_format_uuid (report_format);
  if (uuid == NULL)
    return -1;

  if (report_format_global (report_format))
    dir_name = g_build_filename (OPENVAS_SYSCONF_DIR,
                                 "openvasmd",
                                 "global_report_formats",
                                 uuid,
                                 NULL);
  else
    {
      assert (current_credentials.uuid);
      dir_name = g_build_filename (OPENVAS_SYSCONF_DIR,
                                   "openvasmd",
                                   "report_formats",
                                   current_credentials.uuid,
                                   uuid,
                                   NULL);
    }

  g_free (uuid);

  if (get_report_format_files (dir_name, &iterator->start))
    {
      g_free (dir_name);
      return -1;
    }

  iterator->current = iterator->start->pdata;
  iterator->current--;
  iterator->dir_name = dir_name;
  return 0;
}

/**
 * @brief Cleanup a report type iterator.
 *
 * @param[in]  iterator  Iterator.
 */
void
cleanup_file_iterator (file_iterator_t* iterator)
{
  array_free (iterator->start);
  g_free (iterator->dir_name);
}

/**
 * @brief Increment a report type iterator.
 *
 * The caller must stop using this after it returns FALSE.
 *
 * @param[in]  iterator  Task iterator.
 *
 * @return TRUE if there was a next item, else FALSE.
 */
gboolean
next_file (file_iterator_t* iterator)
{
  iterator->current++;
  if (*iterator->current == NULL) return FALSE;
  return TRUE;
}

/**
 * @brief Return the name from a file iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return File name.
 */
const char*
file_iterator_name (file_iterator_t* iterator)
{
  return (const char*) *iterator->current;
}

/**
 * @brief Return the file contents from a file iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Freshly allocated file contents, in base64.
 */
gchar*
file_iterator_content_64 (file_iterator_t* iterator)
{
  gchar *path_name, *content;
  GError *error;
  gsize content_size;

  path_name = g_build_filename (iterator->dir_name,
                                (gchar*) *iterator->current,
                                NULL);

  /* Read in the contents. */

  error = NULL;
  if (g_file_get_contents (path_name,
                           &content,
                           &content_size,
                           &error)
      == FALSE)
    {
      if (error)
        {
          g_debug ("%s: failed to read %s: %s",
                   __FUNCTION__, path_name, error->message);
          g_error_free (error);
        }
      g_free (path_name);
      return NULL;
    }

  g_free (path_name);

  /* Base64 encode the contents. */

  if (content && (content_size > 0))
    {
      gchar *base64 = g_base64_encode ((guchar*) content, content_size);
      g_free (content);
      return base64;
    }

  return content;
}


/* Tags. */

/**
 * @brief Split up the tags received from the scanner.
 *
 * @param[in]  scanner_tags  The tags sent by the scanner.
 * @param[out] tags          Tags.
 * @param[out] cvss_base     CVSS base.
 * @param[out] risk_factor   Risk factor.
 */
void
parse_tags (const char *scanner_tags, gchar **tags, gchar **cvss_base,
            gchar **risk_factor)
{
  gchar **split, **point;
  GString *tags_buffer;
  gboolean first;

  tags_buffer = g_string_new ("");
  split = g_strsplit (scanner_tags, "|", 0);
  point = split;
  *cvss_base = NULL;
  *risk_factor = NULL;
  first = TRUE;

  while (*point)
    {
      if (strncmp (*point, "cvss_base=", strlen ("cvss_base=")) == 0)
        {
          if (*cvss_base == NULL)
            *cvss_base = g_strdup (*point + strlen ("cvss_base="));
        }
      else if (strncmp (*point, "risk_factor=", strlen ("risk_factor=")) == 0)
        {
          if (*risk_factor == NULL)
            *risk_factor = g_strdup (*point + strlen ("risk_factor="));
        }
      else
        {
          if (first)
            first = FALSE;
          else
            g_string_append_c (tags_buffer, '|');
          g_string_append (tags_buffer, *point);
        }
      point++;
    }

  if (tags_buffer->len == 0)
    {
      g_string_free (tags_buffer, TRUE);
      *tags = g_strdup ("NOTAG");
    }
  else
    *tags = g_string_free (tags_buffer, FALSE);
  g_strfreev (split);
}


/* Slaves. */

/**
 * @brief Delete a task on a slave.
 *
 * @param[in]   slave            The slave.
 * @param[in]   slave_task_uuid  UUID of task on slave.
 *
 * @return 0 success, -1 error.
 */
int
delete_slave_task (slave_t slave, const char *slave_task_uuid)
{
  int socket;
  gnutls_session_t session;
  char *host;
  int port;
  entity_t get_tasks, get_targets, entity, task;
  const char *slave_config_uuid, *slave_target_uuid, *slave_credential_uuid;

  assert (slave);

  /* Connect to the slave. */

  host = slave_host (slave);
  if (host == NULL) return -1;

  tracef ("   %s: host: %s\n", __FUNCTION__, host);

  port = slave_port (slave);
  if (port == -1)
    {
      free (host);
      return -1;
    }

  socket = openvas_server_open (&session, host, port);
  free (host);
  if (socket == -1) return -1;

  tracef ("   %s: connected\n", __FUNCTION__);

  /* Authenticate using the slave login. */

  if (slave_authenticate (&session, slave))
    goto fail;

  tracef ("   %s: authenticated\n", __FUNCTION__);

  /* Get the UUIDs of the slave resources. */

  if (omp_get_tasks (&session, slave_task_uuid, 0, 0, &get_tasks))
    goto fail;

  task = entity_child (get_tasks, "task");
  if (task == NULL)
    goto fail_free_task;

  entity = entity_child (task, "config");
  if (entity == NULL)
    goto fail_free_task;
  slave_config_uuid = entity_attribute (entity, "id");

  entity = entity_child (task, "target");
  if (entity == NULL)
    goto fail_free_task;
  slave_target_uuid = entity_attribute (entity, "id");

  if (omp_get_targets (&session, slave_target_uuid, 0, 0, &get_targets))
    goto fail_free_task;

  entity = entity_child (get_targets, "target");
  if (entity == NULL)
    goto fail_free;

  entity = entity_child (entity, "lsc_credential");
  if (entity == NULL)
    goto fail_free;
  slave_credential_uuid = entity_attribute (entity, "id");

  /* Remove the slave resources. */

  omp_stop_task (&session, slave_task_uuid);
  if (omp_delete_task (&session, slave_task_uuid))
    goto fail_config;
  if (omp_delete_config (&session, slave_config_uuid))
    goto fail_target;
  if (omp_delete_target (&session, slave_target_uuid))
    goto fail_credential;
  if (omp_delete_lsc_credential (&session, slave_credential_uuid))
    goto fail;

  /* Cleanup. */

  free_entity (get_targets);
  free_entity (get_tasks);
  openvas_server_close (socket, session);
  return 0;

 fail_config:
  omp_delete_config (&session, slave_config_uuid);
 fail_target:
  omp_delete_target (&session, slave_target_uuid);
 fail_credential:
  omp_delete_lsc_credential (&session, slave_credential_uuid);
 fail_free:
  free_entity (get_targets);
 fail_free_task:
  free_entity (get_tasks);
 fail:
  openvas_server_close (socket, session);
  return -1;
}
