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
#include <ossp/uuid.h>
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
  uuid_rc_t ret;
  uuid_t* uuid = NULL;

  /* Create the UUID structure. */
  ret = uuid_create (&uuid);
  if (ret)
    {
      g_warning ("%s: failed to create UUID structure: %s\n",
                 __FUNCTION__,
                 uuid_error (ret));
      return NULL;
    }

  /* Create the UUID in the structure. */
  ret = uuid_make (uuid, UUID_MAKE_V1);
  if (ret)
    {
      g_warning ("%s: failed to make UUID: %s\n",
                 __FUNCTION__,
                 uuid_error (ret));
      return NULL;
    }

  /* Export the UUID to text. */
  id = NULL;
  ret = uuid_export (uuid, UUID_FMT_STR, (void**) &id, NULL);
  if (ret)
    {
      g_warning ("%s: failed to export UUID to text: %s\n",
                 __FUNCTION__,
                 uuid_error (ret));
      (void) uuid_destroy (uuid);
      return NULL;
    }

  /* Free the structure. */
  ret = uuid_destroy (uuid);
  if (ret)
    {
      g_warning ("%s: failed to free UUID structure: %s\n",
                 __FUNCTION__,
                 uuid_error (ret));
      if (id) free (id);
      return NULL;
    }

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

  init_task_iterator (&iterator);
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
 * @brief Return the plugins of a task, as a semicolon separated string.
 *
 * @param[in]  task  Task.
 *
 * @return A string of semi-colon separated plugin IDS if known, else NULL.
 */
static gchar*
nvt_selector_plugins (const char* selector)
{
  if (nvt_selector_nvts_growing (selector))
    {
      if ((sql_int (0, 0,
                    "SELECT COUNT(*) FROM nvt_selectors WHERE name = '%s';",
                    selector)
           == 1)
          && (sql_int (0, 0,
                       "SELECT COUNT(*) FROM nvt_selectors"
                       " WHERE name = '%s'"
                       " AND type = " G_STRINGIFY (NVT_SELECTOR_TYPE_ALL)
                       ";",
                       selector)
              == 1))
        {
          GString* plugins;
          iterator_t nvts;
          gboolean first = TRUE;

          plugins = g_string_new ("");
          init_nvt_iterator (&nvts, (nvt_t) 0, NULL, NULL);
          while (next (&nvts))
            {
              if (first)
                first = FALSE;
              else
                g_string_append_c (plugins, ';');
              g_string_append (plugins, nvt_iterator_oid (&nvts));
            }
          cleanup_iterator (&nvts);
          return g_string_free (plugins, FALSE);
        }
      // FIX finalise selector implementation
      return NULL;
    }
  else
    {
      GString* plugins;
      iterator_t nvts;
      gboolean first = TRUE;

      plugins = g_string_new ("");
      init_nvt_selector_iterator (&nvts, selector, 2);
      while (next (&nvts))
        if (nvt_selector_iterator_include (&nvts))
          {
            if (first)
              first = FALSE;
            else
              g_string_append_c (plugins, ';');
            g_string_append (plugins, nvt_selector_iterator_nvt (&nvts));
          }
      cleanup_iterator (&nvts);

      return g_string_free (plugins, FALSE);
    }
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
 * @param[in]  task  Task.
 * @param[in]  name  Name of preference section to send.
 *
 * @return 0 on success, -1 on failure.
 */
static int
send_config_preferences (const char* config,
                         const char* name)
{
  iterator_t prefs;

  init_preference_iterator (&prefs, config, name);
  while (next (&prefs))
    {
      const char *name = preference_iterator_name (&prefs);
      char *value;

      if (send_to_server (name))
        {
          cleanup_iterator (&prefs);
          return -1;
        }

      if (sendn_to_server (" <|> ", 5))
        {
          cleanup_iterator (&prefs);
          return -1;
        }

      value = preference_value (name,
                                preference_iterator_value (&prefs));
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
 * @return 0 on success, 1 task is active already,
 *         -1 if out of space in scanner output buffer, -2 if the
 *         task is missing a target, -3 if creating the report fails, -4 target
 *         missing hosts, -5 task missing config, -6 if there's already a task
 *         running in this process.
 */
int
start_task (task_t task, char **report_id)
{
  char *hosts, *target, *config, *selector;
  gchar *plugins;
  int fail;
  GSList *files = NULL;
  task_status_t run_status;

  tracef ("   start task %u\n", task_id (task));

  // FIX atomic

  run_status = task_run_status (task);
  if (run_status == TASK_STATUS_REQUESTED
      || run_status == TASK_STATUS_RUNNING
      || run_status == TASK_STATUS_STOP_REQUESTED
      || run_status == TASK_STATUS_DELETE_REQUESTED)
    return 1;

  if (current_scanner_task) return -6;

  target = task_target (task);
  if (target == NULL)
    {
      tracef ("   task target is NULL.\n");
      return -2;
    }

  hosts = target_hosts (target);
  free (target);
  if (hosts == NULL)
    {
      tracef ("   target hosts is NULL.\n");
      return -4;
    }

  /* Create the report. */

  if (create_report (task, report_id))
    {
      free (hosts);
      return -3;
    }

  /* Reset any running information. */

  reset_task (task);

  /* Send the preferences header. */

  if (send_to_server ("CLIENT <|> PREFERENCES <|>\n"))
    {
      free (hosts);
      return -1;
    }

  /* Get the config and selector. */

  config = task_config (task);
  if (config == NULL)
    {
      free (hosts);
      tracef ("   task config is NULL.\n");
      return -5;
    }

  selector = config_nvt_selector (config);
  if (selector == NULL)
    {
      free (hosts);
      free (config);
      tracef ("   task config is NULL.\n");
      return -5;
    }

  /* Send the plugin list. */

  plugins = nvt_selector_plugins (selector);
  free (selector);
  if (plugins)
    fail = sendf_to_server ("plugin_set <|> %s\n", plugins);
  else
    fail = send_to_server ("plugin_set <|> 0\n");
  free (plugins);
  if (fail) return -1;

  /* Send some fixed preferences. */

  if (send_to_server ("ntp_keep_communication_alive <|> yes\n"))
    {
      free (hosts);
      free (config);
      return -1;
    }
  if (send_to_server ("ntp_client_accepts_notes <|> yes\n"))
    {
      free (hosts);
      free (config);
      return -1;
    }
  // FIX still getting FINISHED msgs
  if (send_to_server ("ntp_opt_show_end <|> no\n"))
    {
      free (hosts);
      free (config);
      return -1;
    }
  if (send_to_server ("ntp_short_status <|> no\n"))
    {
      free (hosts);
      free (config);
      return -1;
    }

  /* Send the scanner and plugins preferences. */

  if (send_config_preferences (config, "SERVER_PREFS"))
    {
      free (hosts);
      free (config);
      return -1;
    }
  if (send_config_preferences (config, "PLUGINS_PREFS"))
    {
      free (hosts);
      free (config);
      return -1;
    }

  if (send_to_server ("<|> CLIENT\n"))
    {
      free (hosts);
      free (config);
      return -1;
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
          free (config);
          /* Free the data. */
          while (files)
            {
              g_free (files->data);
              files = g_slist_next (files);
            }
          /* Free the list. */
          g_slist_free (last);
          return -1;
        }
      files = g_slist_next (files);
      g_free (last->data);
      g_slist_free_1 (last);
    }

  /* Send the rules. */

  if (send_to_server ("CLIENT <|> RULES <|>\n"))
    {
      free (hosts);
      free (config);
      return -1;
    }

  if (send_config_rules (config))
    {
      free (hosts);
      free (config);
      return -1;
    }

  free (config);
  if (send_to_server ("<|> CLIENT\n"))
    {
      free (hosts);
      return -1;
    }

  /* Send the attack command. */

  fail = sendf_to_server ("CLIENT <|> LONG_ATTACK <|>\n%d\n%s\n",
                          strlen (hosts),
                          hosts);
  free (hosts);
  if (fail) return -1;
  scanner_active = 1;

  current_scanner_task = task;

  set_task_run_status (task, TASK_STATUS_REQUESTED);

#if TASKS_FS
  if (task->open_ports) (void) g_array_free (task->open_ports, TRUE);
  task->open_ports = g_array_new (FALSE, FALSE, (guint) sizeof (port_t));
  task->open_ports_size = 0;
#else
  // FIX
#endif

  return 0;
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
