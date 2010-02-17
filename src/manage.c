/* OpenVAS Manager
 * $Id$
 * Description: Module for OpenVAS Manager: the Manage library.
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
#include "ovas-mngr-comm.h"
#include "tracef.h"

#include <assert.h>
#include <errno.h>
#include <dirent.h>
#include <uuid/uuid.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <openvas/openvas_auth.h>
#include <openvas/base/openvas_string.h>

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


/* Functions defined in task_*.h and used before the include. */

/**
 * @brief Increment report count.
 *
 * @param[in]  task  Task.
 */
void
inc_task_report_count (task_t task);

/**
 * @brief Decrement report count.
 *
 * @param[in]  task  Task.
 */
void
dec_task_report_count (task_t task);

/**
 * @brief Return data associated with an escalator.
 *
 * @param[in]  escalator  Escalator.
 * @param[in]  type       Type of data: "condition", "event" or "method".
 * @param[in]  name       Name of the data.
 *
 * @return Freshly allocated data if it exists, else NULL.
 */
static char *
escalator_data (escalator_t, const char *, const char *);


/* Threats. */

/**
 * @brief Get the message type of a threat.
 *
 * @param  threat  Threat.
 *
 * @return Static message type name if threat names a threat, else NULL.
 */
static const char *
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
static const char *
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


/* Arrays. */

/**
 * @brief Make a global array.
 *
 * @return New array.
 */
GPtrArray *
make_array ()
{
  return g_ptr_array_new ();
}

/**
 * @brief Free global array value.
 *
 * Also g_free any elements.
 *
 * @param[in]  array  Pointer to array.
 */
void
free_array (GPtrArray *array)
{
  if (array)
    {
      int index = 0;
      gpointer item;
      while ((item = g_ptr_array_index (array, index++)))
        g_free (item);
      g_ptr_array_free (array, TRUE);
    }
}


/* Credentials. */

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
                                gsize length)
{
  openvas_append_text (&credentials->username, text, length);
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
                                gsize length)
{
  openvas_append_text (&credentials->password, text, length);
}


/* Reports. */

/**
 * @brief Make a new universal identifier for a report.
 *
 * @return A newly allocated string holding the identifier, which the
 *         caller must free, or NULL on failure.
 */
char*
make_report_uuid ()
{
  char* id;
  uuid_t uuid;

  /* Generate an UUID. */
  uuid_generate (uuid);
  if (uuid_is_null (uuid) == 1)
    {
      g_warning ("%s: failed to generate UUID", __FUNCTION__);
      return NULL;
    }

  /* Allocate mem for string to hold UUID. */
  id = malloc (sizeof (char) * 37);
  if (id == NULL)
    {
      g_warning ("%s: Cannot export UUID to text: out of memory", __FUNCTION__);
      return NULL;
    }

  /* Export the UUID to text. */
  uuid_unparse (uuid, id);

  return id;
}

/**
 * @brief Delete all the reports for a task.
 *
 * @param[in]  task  A task descriptor.
 *
 * @return 0 on success, -1 on error.
 */
static int
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


/* Task code specific to the representation of tasks. */

/* Headers of functions in the next page. */
static int
delete_reports (task_t);
#if 0
static void
print_tasks ();
#endif

#ifdef TASKS_SQL
#include "tasks_sql.h"
#endif


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
 * @brief Make a new universal identifier for a task.
 *
 * @return A newly allocated string holding the identifier on success, or NULL
 *         on failure.
 */
char*
make_task_uuid ()
{
  return make_report_uuid ();
}

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
      case TASK_STATUS_REQUESTED:        return "Requested";
      case TASK_STATUS_RUNNING:          return "Running";
      case TASK_STATUS_STOP_REQUESTED:   return "Stop Requested";
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

#if 0
#if TRACE
/**
 * @brief Print the scanner tasks.
 */
static void
print_tasks ()
{
  task_iterator_t iterator;
  task_t index;

  init_task_iterator (&iterator, 1, NULL);
  if (next_task (&iterator, &index))
    {
      do
        {
          char* comment = task_comment (index);
          char* description = task_description (index);
          char* name = task_name (index);
          tracef ("   Task %u: \"%s\" %s\n%s\n\n",
                  task_id (index),
                  name,
                  comment ? comment : "",
                  description ? description : "");
          free (name);
          free (description);
          free (comment);
        }
      while (next_task (&iterator, &index));
    }
  else
    tracef ("   Task array empty or still to be created\n\n");
}
#endif
#endif

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
 *
 * @return 0 on success, -1 on failure.
 */
static int
send_config_preferences (config_t config, const char* section_name)
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
 * @param[in]  config  Config.
 *
 * @return 0 on success, -1 on failure.
 */
static int
send_user_rules ()
{
  gchar *rules_file, *rules;
  GError *error = NULL;
  gchar **rule, **split;

  assert (current_credentials.username);

  rules_file = g_build_filename (OPENVAS_USERS_DIR,
                                 current_credentials.username,
                                 "auth",
                                 "rules",
                                 NULL);
  g_file_get_contents (rules_file, &rules, NULL, &error);
  if (error)
    {
      tracef ("   failed to get rules: %s", error->message);
      g_error_free (error);
      g_free (rules_file);
      return -1;
    }
  g_free (rules_file);

  split = rule = g_strsplit (rules, "\n", 0);
  g_free (rules);
  while (*rule)
    {
      *rule = g_strstrip (*rule);
      if (**rule == '#')
        {
          rule++;
          continue;
        }
      /* Presume the rule is correctly formatted. */
      if (send_to_server (*rule))
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
 * @brief Send a file from a config to the scanner.
 *
 * @param[in]  config  Config.
 * @param[in]  file    File name.
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
  target_t target;
  char *hosts;
  gchar *plugins;
  int fail, pid;
  GSList *files = NULL;
  task_status_t run_status;
  config_t config;
  lsc_credential_t credential;

  tracef ("   start task %u\n", task_id (task));

  sql ("BEGIN EXCLUSIVE;");

  run_status = task_run_status (task);
  if (run_status == TASK_STATUS_REQUESTED
      || run_status == TASK_STATUS_RUNNING
      || run_status == TASK_STATUS_STOP_REQUESTED
      || run_status == TASK_STATUS_DELETE_REQUESTED)
    {
      sql ("END;");
      return 1;
    }

  set_task_run_status (task, TASK_STATUS_REQUESTED);

  sql ("COMMIT;");

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

  /* Create the report. */

  if (create_report (task, report_id, TASK_STATUS_REQUESTED))
    {
      free (hosts);
      set_task_run_status (task, run_status);
      return -3;
    }

  /* Fork a child to start and handle the task while the parent responds to
   * the client. */

  pid = fork ();
  switch (pid)
    {
      case 0:
        /* Child.  Carry on starting the task. */
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

  /* Send the scanner and plugins preferences. */

  if (send_config_preferences (config, "SERVER_PREFS"))
    {
      free (hosts);
      set_task_run_status (task, run_status);
      current_report = (report_t) 0;
      return -10;
    }
  if (send_config_preferences (config, "PLUGINS_PREFS"))
    {
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
              || sendf_to_server ("SSH Authorization[password]:"
                                  "SSH password (unsafe!):"
                                  " <|> %s\n",
                                  password))
            {
              free (hosts);
              cleanup_iterator (&credentials);
              set_task_run_status (task, run_status);
              current_report = (report_t) 0;
              return -10;
            }
        }
      cleanup_iterator (&credentials);
    }

  if (send_to_server ("<|> CLIENT\n"))
    {
      free (hosts);
      set_task_run_status (task, run_status);
      current_report = (report_t) 0;
      return -10;
    }

  /* Collect files to send. */

  files = get_files_to_send (task);

  /* Send any files. */

  while (files)
    {
      GSList *last = files;
      if (send_task_file (task, files->data))
        {
          free (hosts);
          /* Free the data. */
          while (files)
            {
              g_free (files->data);
              files = g_slist_next (files);
            }
          /* Free the list. */
          g_slist_free (last);
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

  if (send_user_rules ())
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

#if TASKS_FS
  if (task->open_ports) (void) g_array_free (task->open_ports, TRUE);
  task->open_ports = g_array_new (FALSE, FALSE, (guint) sizeof (port_t));
  task->open_ports_size = 0;
#else
  // FIX
#endif

  return 2;
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
  if (run_status == TASK_STATUS_REQUESTED
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

#if 0
      // FIX should prevent this from repeating somehow
      if (current_scanner_task_stop_requested) return;
#endif

      // FIX something should check safety credential before this
      run_status = task_run_status (current_scanner_task);
      if (run_status == TASK_STATUS_STOP_REQUESTED)
        {
          /* Some other process changed to this status, so request the stop. */
          if (send_to_server ("CLIENT <|> STOP_WHOLE_TEST <|> CLIENT\n"))
            return -1;
          return 1;
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
