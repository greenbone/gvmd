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

#include <openvas/base/openvas_string.h>
#include <openvas/omp/omp.h>
#include <openvas/openvas_server.h>
#include <openvas/openvas_uuid.h>

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
scanner_t scanner;


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
 * @param[in]  task  A task descriptor.
 *
 * @return 0 on success, -1 on error.
 */
int
delete_reports (task_t task)
{
  report_t report;
  iterator_t iterator;
  // FIX wrap in transaction?
  init_report_iterator (&iterator, task);
  while (next_report (&iterator, &report)) delete_report (report);
  cleanup_iterator (&iterator);
  return 0;
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
 *
 * @return Freshly allocated description of event.
 */
gchar*
event_description (event_t event, const void *event_data)
{
  switch (event)
    {
      case EVENT_TASK_RUN_STATUS_CHANGED:
        return g_strdup_printf ("Task run status changed to '%s'",
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
      case ESCALATOR_METHOD_EMAIL: return "Email";
      default:                     return "Internal Error";
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
  GString* plugins = g_string_new ("");;
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

      current_report = last_stopped_report;
      if (report_id) *report_id = report_uuid (last_stopped_report);

      /* Remove partial host information from the report. */

      trim_partial_report (last_stopped_report);

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

  // FIX On fail exits only, if another process has set a request state then
  //     honour that request.  (stop_task, request_delete_task)

  /** @todo Also reset status on report, as current_scanner_task is 0 here. */

  run_status = TASK_STATUS_INTERNAL_ERROR;

  /* Reset any running information. */

  reset_task (task);

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
  // FIX still getting FINISHED msgs
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
  // FIX This is what the file based tasks did.
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
  // FIX something should check safety credential before this
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
  // FIX something should check safety credential before this
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
  // FIX something should check safety credential before this
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
  // FIX something should check safety credential before this
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

      // FIX something should check safety credential before this
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
 * @brief Command called by get_system_report_types.
 */
#define COMMAND "openvasmr 0 titles"

/**
 * @brief Get system report types.
 *
 * @param[out]  types  Types on success.
 *
 * @return 0 if successful, -1 otherwise.
 */
static int
get_system_report_types (gchar ***types)
{
  gchar *astdout = NULL;
  gchar *astderr = NULL;
  GError *err = NULL;
  gint exit_status;

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
      *types = type = g_strsplit (g_strchomp (astdout), "\n", 0);
      while (*type)
        {
          char *space;
          space = strchr (*type, ' ');
          if (space == NULL)
            {
              g_strfreev (type);
              *types = NULL;
              g_free (astdout);
              g_free (astderr);
              return -1;
            }
          *space = '\0';
          type++;
        }
    }
  else
    *types = NULL;
  g_free (astdout);
  g_free (astderr);
  return 0;
}

#undef COMMAND

/**
 * @brief Initialise a system report type iterator.
 *
 * @param[in]  iterator    Iterator.
 *
 * @return 0 on success, -1 on error.
 */
int
init_system_report_type_iterator (report_type_iterator_t* iterator)
{
  if (get_system_report_types (&iterator->start)) return -1;
  iterator->current = iterator->start - 1;
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
 * @brief Get a system report.
 *
 * @param[in]   name      Name of report.
 * @param[in]   duration  Time range of report, in seconds.
 * @param[out]  report    On success, report in base64 if such a report exists
 *                        else NULL.  Arbitrary on error.
 *
 * @return 0 if successful (including failure to find report), -1 on error.
 */
int
manage_system_report (const char *name, const char *duration, char **report)
{
  gchar *astdout = NULL;
  gchar *astderr = NULL;
  GError *err = NULL;
  gint exit_status;
  gchar *command;

  assert (name);
  assert (duration);

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
      return manage_system_report ("blank", duration, report);
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
