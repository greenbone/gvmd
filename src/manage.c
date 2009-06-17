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
 * includes sending task commands to the OTP server that is running the
 * tasks.
 */

#include "manage.h"
#include "file.h"
#include "ovas-mngr-comm.h"
#include "string.h"
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

#ifdef S_SPLINT_S
#include "splint.h"
#endif


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
  append_text (&credentials->username, text, length);
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
  append_text (&credentials->password, text, length);
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
      fprintf (stderr,
               "Failed to create UUID structure: %s.\n",
               uuid_error (ret));
      return NULL;
    }

  /* Create the UUID in the structure. */
  ret = uuid_make (uuid, UUID_MAKE_V1);
  if (ret)
    {
      fprintf (stderr,
               "Failed to make UUID: %s.\n",
               uuid_error (ret));
      return NULL;
    }

  /* Export the UUID to text. */
  id = NULL;
  ret = uuid_export (uuid, UUID_FMT_STR, (void**) &id, NULL);
  if (ret)
    {
      fprintf (stderr,
               "Failed to export UUID to text: %s.\n",
               uuid_error (ret));
      (void) uuid_destroy (uuid);
      return NULL;
    }

  /* Free the structure. */
  ret = uuid_destroy (uuid);
  if (ret)
    {
      fprintf (stderr,
               "Failed to free UUID structure: %s.\n",
               uuid_error (ret));
      if (id) free (id);
      return NULL;
    }

  return id;
}

/**
 * @brief Get the name of the task from the pathname of a report.
 *
 * @param[in]  path  Absolute path of report in task directory.
 *
 * @return The UUID of the task as a newly allocated string.
 */
gchar*
report_path_task_uuid (gchar* path)
{
#if 0
  gchar* task_dir = g_build_filename (path, "..", "..", NULL);
  // FIX how to do this (expand .. (and resolve links))?
  gchar* task_actual_dir = g_truename (task_dir);
  gchar* basename = g_path_get_basename (task_actual_dir);
  g_free (task_dir);
  g_free (task_actual_dir);
  return basename;
#else
  gchar* basename;
  gchar* path2 = g_strdup (path);
  /* mgr/users/user/tasks/ID/reports/report_id */
  gchar* last = g_path_get_basename (path2);
  size_t path2_length = strlen (path2);

  path2_length -= strlen (last);
  path2_length--; /* In case trailing slash. */
  path2[path2_length] = '\0';
  g_free (last);
  /* mgr/users/user/tasks/ID/reports/ */
  last = g_path_get_basename (path2);
  path2_length -= strlen (last);
  path2_length--; /* Trailing slash. */
  path2[path2_length] = '\0';
  g_free (last);
  /* mgr/users/user/tasks/ID/ */
  basename = g_path_get_basename (path2);
  g_free (path2);

  return basename;
#endif
}

/**
 * @brief Get the task associated with a report.
 *
 * @param[in]   report_id    ID of report.
 * @param[out]  task_return  The task return.
 *
 * @return TRUE on error, else FALSE.
 */
gboolean
report_task (const char* report_id, task_t* task_return)
{
  if (current_credentials.username)
    {
      gchar* link_name;
      link_name = g_build_filename (OPENVAS_STATE_DIR
                                    "/mgr/users/",
                                    current_credentials.username,
                                    "reports",
                                    report_id,
                                    NULL);
      // FIX glib access setuid note
      if (g_file_test (link_name, G_FILE_TEST_IS_SYMLINK)
          && g_file_test (link_name, G_FILE_TEST_IS_DIR))
        {
          GError* error = NULL;
          gchar* report_path = g_file_read_link (link_name, &error);
          g_free (link_name);
          if (error)
            {
              fprintf (stderr,
                       "Failed to read report symlink: %s.\n",
                       error->message);
              g_error_free (error);
              g_free (report_path);
              return TRUE;
            }
          {
            gchar* task_uuid = report_path_task_uuid (report_path);
            task_t task;
            int err = find_task (task_uuid, &task);
            g_free (report_path);
            if (err && task == 0)
              {
                fprintf (stderr, "Failed to find task %s.\n", task_uuid);
                g_free (task_uuid);
                return TRUE;
              }
            g_free (task_uuid);
            *task_return = task;
            return FALSE;
          }
        }
      else
        {
          fprintf (stderr, "Failed to access %s.\n", link_name);
          g_free (link_name);
        }
    }
  return TRUE;
}

/**
 * @brief Delete a report.
 *
 * @param[in]  report_id  ID of report.
 *
 * @return 0 success, -1 failed to find task, -2 report file missing,
 *         -3 failed to read link, -4 failed to remove report, -5 username
 *         missing from current_credentials.
 */
int
delete_report (const char* report_id)
{
  gchar* link_name;
  task_t task;

  if (report_task (report_id, &task)) return -1;

  if (current_credentials.username == NULL) return -5;

  link_name = g_build_filename (OPENVAS_STATE_DIR
                                "/mgr/users/",
                                current_credentials.username,
                                "reports",
                                report_id,
                                NULL);
  // FIX glib access setuid note
  if (g_file_test (link_name, G_FILE_TEST_IS_SYMLINK)
      && g_file_test (link_name, G_FILE_TEST_IS_DIR))
    {
      GError* error = NULL;
      gchar* name = g_file_read_link (link_name, &error);
      if (error)
        {
          fprintf (stderr,
                   "Failed to read report symlink: %s.\n",
                   error->message);
          g_error_free (error);
          g_free (name);
          g_free (link_name);
          return -3;
        }
      else if (rmdir_recursively (name, &error) == FALSE)
        {
          if (error)
            {
              fprintf (stderr,
                       "Failed to remove %s: %s.\n",
                       name,
                       error->message);
              g_error_free (error);
            }
          g_free (name);
          g_free (link_name);
          return -4;
        }
      else
        {
          if (unlink (link_name))
            /* Just log the error. */
            fprintf (stderr,
                     "Failed to remove report symlink %s: %s.\n",
                     link_name,
                     strerror (errno));
          g_free (name);
          g_free (link_name);
          dec_task_report_count (task);
          return 0;
        }
    }
  else
    {
      fprintf (stderr, "Failed to access %s.\n", link_name);
      g_free (link_name);
      return -2;
    }
}

/**
 * @brief Set a report parameter.
 *
 * @param[in]  report_id  The ID of the report.
 * @param[in]  parameter  The name of the parameter (in any case): COMMENT.
 * @param[in]  value      The value of the parameter.
 *
 * @return 0 success, -2 parameter name error,
 *         -3 failed to write parameter to disk,
 *         -4 username missing from current_credentials.
 */
int
set_report_parameter (char* report_id, const char* parameter, char* value)
{
  tracef ("   set_report_parameter %s %s\n", report_id, parameter);
  if (strncasecmp ("COMMENT", parameter, 7) == 0)
    {
      gboolean success;
      GError* error;
      gchar* name;

      if (current_credentials.username == NULL) return -4;

      name = g_build_filename (OPENVAS_STATE_DIR
                               "/mgr/users/",
                               current_credentials.username,
                               "reports",
                               report_id,
                               "comment",
                               NULL);
      error = NULL;
      success = g_file_set_contents (name, value, -1, &error);
      if (success == FALSE)
        {
          if (error)
            fprintf (stderr,
                     "Failed to save comment to %s: %s.\n",
                     name,
                     error->message);
          g_free (name);
          return -3;
        }
      g_free (name);
    }
  else
    return -2;
  return 0;
}


/* Task globals. */

/**
 * @brief Server active flag.
 *
 * This indicates whether the server is doing something that the manager
 * must wait for.  Set, for example, by \ref start_task.  If this variable
 * is true then the manager keeps the management process alive until the
 * server closes its connection, even if the client closes its connection.
 */
short server_active = 0;

/**
 * @brief The task currently running on the server.
 */
/*@null@*/ task_t current_server_task = (task_t) NULL;

/**
 * @brief Report stream of the current task.
 */
FILE* current_report = NULL;


/* Task code specific to the representation of tasks. */

/* Headers of functions in the next page. */
static int
delete_reports (task_t);
#if 0
static void
print_tasks ();
#endif

#ifdef TASKS_FS
#include "tasks_fs.h"
#else
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
  switch (task_run_status (task))
    {
      case TASK_STATUS_DELETE_REQUESTED: return "Delete requested";
      case TASK_STATUS_DONE:             return "Done";
      case TASK_STATUS_NEW:              return "New";
      case TASK_STATUS_REQUESTED:        return "Requested";
      case TASK_STATUS_RUNNING:          return "Running";
      case TASK_STATUS_STOP_REQUESTED:   return "Stop requested";
      default:                           return "Internal Error";
    }
}

#if 0
#if TRACE
/**
 * @brief Print the server tasks.
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
    tracef ("   Task array empty or still to be created.\n\n");
}
#endif
#endif

/**
 * @brief Create the current report file for a task.
 *
 * @param[in]  task   The task.
 *
 * @return 0 success, -1 failed to open file, -2 ID or credentials error,
 *         -3 failed to symlink file to task dir, -4 failed to create dir,
 *         -5 failed to generate ID, -6 report file already exists.
 */
static int
create_report_file (task_t task)
{
  char* tsk_uuid;
  char* report_id;
  gchar* user_dir_name;
  gchar* dir_name;
  gchar* name;
  gchar* symlink_name;
  FILE* file;

  if (current_credentials.username == NULL) return -2;

  assert (current_report == NULL);
  if (current_report) return -6;

#if TRACE
  {
    char* start_time = task_start_time (task);
    tracef ("   Saving report (%s) on task %u\n",
            start_time, task_id (task));
    free (start_time);
  }
#endif

  if (task_uuid (task, &tsk_uuid)) return -2;

  user_dir_name = g_build_filename (OPENVAS_STATE_DIR
                                    "/mgr/users/",
                                    current_credentials.username,
                                    "reports",
                                    NULL);

  /* Ensure user reports directory exists. */

  if (g_mkdir_with_parents (user_dir_name, 33216 /* -rwx------ */) == -1)
    {
      fprintf (stderr, "Failed to create report dir %s: %s\n",
               user_dir_name,
               strerror (errno));
      g_free (user_dir_name);
      return -4;
    }

  /* Generate report directory name. */

  report_id = make_report_uuid ();
  if (report_id == NULL)
    {
      g_free (user_dir_name);
      return -5;
    }

  dir_name = g_build_filename (OPENVAS_STATE_DIR
                               "/mgr/users/",
                               current_credentials.username,
                               "tasks",
                               tsk_uuid,
                               "reports",
                               report_id,
                               NULL);
  free (tsk_uuid);

  symlink_name = g_build_filename (user_dir_name, report_id, NULL);
  free (report_id);
  g_free (user_dir_name);

  /* Ensure task report directory exists. */

  if (g_mkdir_with_parents (dir_name, 33216 /* -rwx------ */) == -1)
    {
      fprintf (stderr, "Failed to create report dir %s: %s\n",
               dir_name,
               strerror (errno));
      g_free (dir_name);
      g_free (symlink_name);
      return -4;
    }

  /* Link report directory into task directory. */

  if (symlink (dir_name, symlink_name))
    {
      (void) rmdir (dir_name);
      fprintf (stderr, "Failed to symlink %s to %s\n",
               dir_name,
               symlink_name);
      g_free (dir_name);
      g_free (symlink_name);
      return -3;
    }

  /* Save report stream. */

  name = g_build_filename (dir_name, "report.nbe", NULL);

  file = fopen (name, "w");
  if (file == NULL)
    {
      (void) rmdir (dir_name);
      fprintf (stderr, "Failed to open report file %s: %s\n",
               name,
               strerror (errno));
      g_free (dir_name);
      g_free (name);
      g_free (symlink_name);
      return -1;
    }

  current_report = file;
  inc_task_report_count (task);

  g_free (dir_name);
  g_free (name);
  g_free (symlink_name);
  return 0;
}

/**
 * @brief Return a task preference.
 *
 * @param[in]  task  The task.
 * @param[in]  name  The name of the preference.
 *
 * @return The preference on success, else NULL.
 */
static char*
task_preference (task_t task, const char* name)
{
  char* desc = task_description (task);
  char* orig_desc = desc;
  char* seek;
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
              ret = g_strndup (eq + 2,
                               seek ? seek - (eq + 2) : strlen (seek));
              free (orig_desc);
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
  free (orig_desc);
  return NULL;
}

/**
 * @brief Return the plugins of a task, as a semicolon separated string.
 *
 * @param[in]  task  Task.
 *
 * @return A string of semi-colon separated plugin IDS, or the empty string
 *         if the task is to invoke all plugins.
 */
static char*
task_plugins (task_t task)
{
  char* desc = task_description (task);
  char* orig_desc = desc;
  char* seek;
  GString* plugins = g_string_new ("");
  gboolean first = TRUE;

  while ((seek = strchr (desc, '\n')))
    {
      char* eq = seek
                 ? memchr (desc, '=', seek - desc)
                 : strchr (desc, '=');
      if (eq)
        {
#if 0
          tracef ("   skip: %.*s\n",
                  seek ? seek - desc : strlen (seek),
                  desc);
#endif
        }
      else if ((seek ? seek - desc >= 17 : 1)
               && (strncmp (desc, "begin(PLUGIN_SET)", 17) == 0
                   || strncmp (desc, "begin(SCANNER_SET)", 18) == 0))
        {
          /* Read in the plugins. */
          desc = seek + 1;
          while ((seek = strchr (desc, '\n')))
            {
              char* eq2;

              if ((seek ? seek - desc > 5 : 1)
                  && strncmp (desc, "end(", 4) == 0)
                {
                  break;
                }

              eq2 = memchr (desc, '=', seek - desc);
              if (eq2)
                {
                  if (strncasecmp (eq2 + 2, "yes", 3) == 0)
                    {
                      if (first)
                        first = FALSE;
                      else
                        g_string_append_c (plugins, ';');
                      /* FIX Rather skip all whitespace before and after
                             name. */
                      g_string_append_len (plugins, desc + 1, eq2 - desc - 2);
#if 0
                      tracef ("   plugin: %.*s\n",
                              eq2 - desc - 1,
                              desc);
#endif
                    }
                }

              desc = seek + 1;
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
              tracef ("skip s: %.*s\n",
                      seek ? seek - desc : strlen (seek),
                      desc);
#endif
              desc = seek + 1;
            }
        }
      if (seek == NULL) break;
      desc = seek + 1;
    }
  free (orig_desc);
  return g_string_free (plugins, FALSE);
}

/**
 * @brief Send the task preferences (SERVER_PREFS) to the server.
 *
 * @param[in]  task  Task.
 *
 * @return 0 on success, -1 on failure.
 */
static int
send_task_preferences (task_t task, char* name)
{
  char* desc = task_description (task);
  char* orig_desc = desc;
  char* seek;

  while (1)
    {
      char* eq;
      seek = strchr (desc, '\n');
      eq = seek
           ? memchr (desc, '=', seek - desc)
           : strchr (desc, '=');
      if (eq)
        {
#if 0
          tracef ("   skip: %.*s\n",
                  seek ? seek - desc : strlen (seek),
                  desc);
#endif
        }
      else if ((seek ? seek - desc >= 7 + strlen (name) : 1)
               && (strncmp (desc, "begin(", 6) == 0)
               && (strncmp (desc + 6, name, strlen (name)) == 0)
               && (desc[6 + strlen (name)] == ')'))
        {
          /* Send the preferences. */
          desc = seek + 1;
          while ((seek = strchr (desc, '\n')))
            {
              char* eq2;

              if ((seek ? seek - desc > 5 : 1)
                  && strncmp (desc, "end(", 4) == 0)
                {
                  break;
                }

              eq2 = memchr (desc, '=', seek - desc);
              if (eq2)
                {
                  if (sendn_to_server (desc, eq2 - desc))
                    {
                      free (orig_desc);
                      return -1;
                    }
                  if (sendn_to_server (" <|> ", 5))
                    {
                      free (orig_desc);
                      return -1;
                    }
                  if (sendn_to_server (eq2 + 2,
                                       seek ? seek - (eq2 + 2)
                                            : strlen (eq2 + 2)))
                    {
                      free (orig_desc);
                      return -1;
                    }
                  if (sendn_to_server ("\n", 1))
                    {
                      free (orig_desc);
                      return -1;
                    }
                }

              desc = seek + 1;
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
              tracef ("skip s: %.*s\n",
                      seek ? seek - desc : strlen (seek),
                      desc);
#endif
              desc = seek + 1;
            }
        }
      if (seek == NULL) break;
      desc = seek + 1;
    }
  free (orig_desc);
  return 0;
}

/**
 * @brief Send the task rules (CLIENTSIDE_USERRULES) to the server.
 *
 * @param[in]  task  Task.
 *
 * @return 0 on success, -1 on failure.
 */
static int
send_task_rules (task_t task)
{
  char* desc = task_description (task);
  char* orig_desc = desc;
  char* seek;

  while (1)
    {
      char* eq;
      seek = strchr (desc, '\n');
      eq = seek
           ? memchr (desc, '=', seek - desc)
           : strchr (desc, '=');
      if (eq)
        {
#if 0
          tracef ("   skip: %.*s\n",
                  seek ? seek - desc : strlen (seek),
                  desc);
#endif
        }
      else if ((seek ? seek - desc >= 27 : 1)
               && (strncmp (desc, "begin(CLIENTSIDE_USERRULES)", 27) == 0))
        {
          /* Send the preferences. */
          desc = seek + 1;
          while ((seek = strchr (desc, '\n')))
            {
              if ((seek ? seek - desc > 5 : 1)
                  && strncmp (desc, "end(", 4) == 0)
                {
                  break;
                }

              if (sendn_to_server (desc, seek ? seek - desc : strlen (desc)))
                return -1;
              if (sendn_to_server ("\n", 1))
                return -1;

              desc = seek + 1;
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
              tracef ("skip s: %.*s\n",
                      seek ? seek - desc : strlen (seek),
                      desc);
#endif
              desc = seek + 1;
            }
        }
      if (seek == NULL) break;
      desc = seek + 1;
    }
  free (orig_desc);
  return 0;
}

/**
 * @brief Start a task.
 *
 * Use \ref send_to_server to queue the task start sequence in \ref to_server.
 *
 * @param[in]  task  A pointer to the task.
 *
 * @return 0 on success, -1 if out of space in \ref to_server buffer.
 */
int
start_task (task_t task)
{
  char* targets;
  char* plugins;
  int fail;

  tracef ("   start task %u\n", task_id (task));

  // FIX atomic

  task_status_t run_status = task_run_status (task);
  if (run_status == TASK_STATUS_REQUESTED
      || run_status == TASK_STATUS_RUNNING)
    return 0;

  /* Create the report file. */

  if (create_report_file (task)) return -2;

  /* Start the task. */

  if (send_to_server ("CLIENT <|> PREFERENCES <|>\n")) return -1;

  plugins = task_plugins (task);
  if (strlen (plugins))
    fail = sendf_to_server ("plugin_set <|> %s\n", plugins);
  else
    fail = sendf_to_server ("plugin_set <|> 0\n");
  free (plugins);
  if (fail) return -1;

  if (send_to_server ("ntp_keep_communication_alive <|> yes\n")) return -1;
  if (send_to_server ("ntp_client_accepts_notes <|> yes\n")) return -1;
  // FIX still getting FINISHED msgs
  if (send_to_server ("ntp_opt_show_end <|> no\n")) return -1;
  if (send_to_server ("ntp_short_status <|> no\n")) return -1;

  if (send_task_preferences (task, "SERVER_PREFS")) return -1;
  if (send_task_preferences (task, "PLUGINS_PREFS")) return -1;

  if (send_to_server ("<|> CLIENT\n")) return -1;

  if (send_to_server ("CLIENT <|> RULES <|>\n")) return -1;

  if (send_task_rules (task)) return -1;
  if (send_to_server ("<|> CLIENT\n")) return -1;

  targets = task_preference (task, "targets");
  fail = sendf_to_server ("CLIENT <|> LONG_ATTACK <|>\n%d\n%s\n",
                          strlen (targets),
                          targets);
  free (targets);
  if (fail) return -1;
  server_active = 1;

  set_task_run_status (task, TASK_STATUS_REQUESTED);

#if TASKS_FS
  if (task->open_ports) (void) g_array_free (task->open_ports, TRUE);
  task->open_ports = g_array_new (FALSE, FALSE, (guint) sizeof (port_t));
  task->open_ports_size = 0;
#else
  // FIX
#endif

  current_server_task = task;

  return 0;
}

/**
 * @brief Initiate stopping a task.
 *
 * Use \ref send_to_server to queue the task stop sequence in
 * \ref to_server.
 *
 * @param[in]  task  A pointer to the task.
 *
 * @return 0 on success, 1 if stop requested, -1 if out of space in \ref
 *         to_server buffer.
 */
int
stop_task (task_t task)
{
  tracef ("   request task stop %u\n", task_id (task));
  // FIX something should check safety credential before this
  task_status_t run_status = task_run_status (task);
  if (run_status == TASK_STATUS_REQUESTED
      || run_status == TASK_STATUS_RUNNING)
    {
      if (send_to_server ("CLIENT <|> STOP_WHOLE_TEST <|> CLIENT\n"))
        return -1;
      set_task_run_status (task, TASK_STATUS_STOP_REQUESTED);
      return 1;
    }
  return 0;
}

/**
 * @brief Delete all the reports for a task.
 *
 * @param[in]  task  A pointer to the task.
 *
 * @return 0 on success, -1 on error.
 */
static int
delete_reports (task_t task)
{
  char* tsk_uuid;
  gchar* dir_name;
  struct dirent ** names = NULL;
  int count, index;

  if (task_uuid (task, &tsk_uuid)) return -1;

  if (current_credentials.username == NULL) return -1;

  dir_name = g_build_filename (OPENVAS_STATE_DIR
                               "/mgr/users/",
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
          g_free (dir_name);
          return 0;
        }
      fprintf (stderr, "Failed to open dir %s: %s\n",
               dir_name,
               strerror (errno));
      g_free (dir_name);
      return -1;
    }
  g_free (dir_name);

  for (index = 0; index < count; index++)
    {
      int ret;
      /*@dependent@*/ const char* report_name = names[index]->d_name;

      if (report_name[0] == '.')
        {
          free (names[index]);
          continue;
        }

      ret = delete_report (report_name);
      free (names[index]);
      switch (ret)
        {
          case 0: break;
          default: free (names); return -1;
        }
    }
  free (names);
  return 0;
}


/* Server messaging. */

/**
 * @brief Request the list of plugins from the server.
 *
 * @return 0 on success, -1 if out of space in \ref to_server buffer.
 */
int
request_plugin_list ()
{
  if (send_to_server ("CLIENT <|> COMPLETE_LIST <|> CLIENT\n"))
    return -1;
  return 0;
}

/**
 * @brief Request the list of certificates from the server.
 *
 * @return 0 on success, -1 if out of space in \ref to_server buffer.
 */
int
request_certificates ()
{
  if (send_to_server ("CLIENT <|> CERTIFICATES <|> CLIENT\n"))
    return -1;
  return 0;
}

/**
 * @brief Acknowledge a server BYE.
 *
 * @return 0 on success, -1 if out of space in \ref to_server buffer.
 */
int
acknowledge_bye ()
{
  if (send_to_server ("CLIENT <|> BYE <|> ACK\n"))
    return -1;
  return 0;
}
