/* OpenVAS Manager
 * $Id$
 * Description: Module for OpenVAS Manager: the Manage library.
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

// FIX might be cleaner to separate server funcs like start_task
//     from storage and manip funcs like make_task and
//     add_task_description_line

#include "manage.h"
#include "file.h"
#include "ovas-mngr-comm.h"
#include "tracef.h"

#include <assert.h>
#include <errno.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


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
                                int length)
{
  credentials->username = credentials->username
                          ? g_strconcat (credentials->username, text, NULL)
                          : g_strndup (text, length);
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
                                int length)
{
  credentials->password = credentials->password
                          ? g_strconcat (credentials->password, text, NULL)
                          : g_strndup (text, length);
}

/**
 * @brief Authenticate credentials.
 *
 * @param[in]  credentials  Credentials.
 *
 * @return 1 if credentials are authentic, else 0.
 */
int
authenticate (credentials_t credentials)
{
  if (credentials.username) return 1;
  return 0;
}


/* Reports. */

/**
 * @brief Delete a report.
 *
 * @param[in]  report_id  ID of report.
 *
 * @return 0 success, -1 failed to parse ID, -2 report file missing,
 *         -3 failed to read link, -4 failed to remove report.
 */
int
delete_report (const char* report_id)
{
  unsigned int id;
  if (sscanf (report_id, "%u", &id) == 1)
    {
      static char buffer[11]; /* (expt 2 32) => 4294967296 */

      sprintf (buffer, "%010u", id);
      gchar* link_name;
      link_name = g_build_filename (PREFIX
                                    "/var/lib/openvas/mgr/users/",
                                    current_credentials.username,
                                    "reports",
                                    buffer,
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
              fprintf (stderr,
                       "Failed to remove %s: %s.\n",
                       name,
                       error->message);
              g_error_free (error);
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
              return 0;
            }
        }
      else
        return -2;
    }
  else
    return -1;
}

/**
 * @brief Set a report parameter.
 *
 * @param[in]  report     The ID of the report.
 * @param[in]  parameter  The name of the parameter (in any case): COMMENT.
 * @param[in]  value      The value of the parameter.
 *
 * @return 0 success, -1 failed to scan ID, -2 parameter name error,
 *         -3 failed to write parameter to disk.
 */
int
set_report_parameter (char* report_id, const char* parameter, char* value)
{
  tracef ("   set_report_parameter %s %s\n", report_id, parameter);
  if (strncasecmp ("COMMENT", parameter, 7) == 0)
    {
      unsigned int id;
      if (sscanf (report_id, "%u", &id) == 1)
        {
          static char buffer[11]; /* (expt 2 32) => 4294967296 */

          sprintf (buffer, "%010u", id);
          gchar* name;
          name = g_build_filename (PREFIX
                                   "/var/lib/openvas/mgr/users/",
                                   current_credentials.username,
                                   "reports",
                                   buffer,
                                   "comment",
                                   NULL);
          GError* error = NULL;
          g_file_set_contents (name, value, -1, &error);
          if (error)
            {
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
        return -1;
    }
  else
    return -2;
  return 0;
}


/* Tasks. */

/**
 * @brief Reallocation increment for the tasks array.
 */
#define TASKS_INCREMENT 1024

/**
 * @brief The array of all the tasks of the current user.
 */
task_t* tasks = NULL;

/**
 * @brief The size of the \ref tasks array.
 */
unsigned int tasks_size = 0;

/**
 * @brief The number of defined tasks.
 */
unsigned int num_tasks = 0;

/**
 * @brief The task currently running on the server.
 */
task_t* current_server_task = NULL;

/**
 * @brief Return a string version of the ID of a task.
 *
 * @param[in]   task  Task.
 * @param[out]  id    Pointer to a string.  On successful return contains a
 *                    pointer to a static buffer with the task ID as a string.
 *                    The static buffer is overwritten across successive calls.
 *
 * @return 0 success, -1 error.
 */
int
task_id_string (task_t* task, const char ** id)
{
  static char buffer[11]; /* (expt 2 32) => 4294967296 */
  int length = sprintf (buffer, "%010u", task->id);
  assert (length < 11);
  if (length < 1) return -1;
  *id = buffer;
  return 0;
}

#if TRACE
/**
 * @brief Print the server tasks.
 */
void
print_tasks ()
{
  task_t *index = tasks;
  tracef ("   tasks: %p\n", tasks);
  tracef ("   tasks end: %p\n", tasks + tasks_size);
  while (index < tasks + tasks_size)
    {
      //tracef ("   index: %p\n", index);
      if (index->name)
        {
          tracef ("   Task %u: \"%s\" %s\n%s\n\n",
                  index->id,
                  index->name,
                  index->comment ?: "",
                  index->description ?: "");
        }
      index++;
    }
}
#endif

/**
 * @brief Grow the array of tasks.
 *
 * @return 0 on success, -1 on error (out of memory).
 */
int
grow_tasks ()
{
  tracef ("   task_t size: %i\n", sizeof (task_t));
  task_t* new = realloc (tasks,
                         (tasks_size + TASKS_INCREMENT) * sizeof (task_t));
  if (new == NULL) return -1;
  tasks = new;

  /* Clear the new part of the memory. */
  new = tasks + tasks_size;
  memset (new, '\0', TASKS_INCREMENT * sizeof (task_t));

  tasks_size += TASKS_INCREMENT;
  tracef ("   tasks grown to %i\n", tasks_size);
#if TRACE
  print_tasks ();
#endif
  return 0;
}

// FIX should be in otp.c
/**
 * @brief Free a message for g_ptr_array_foreach.
 *
 * @param[in]  message       Pointer to the message.
 * @param[in]  dummy         Dummy parameter.
 */
void
free_message (gpointer message, gpointer dummy)
{
  message_t* msg = (message_t*) message;
  if (msg->description) free (msg->description);
  if (msg->oid) free (msg->oid);
  free (msg);
}

/**
 * @brief Free a task.
 *
 * Free all the members of a task.
 *
 * @param[in]  task  The task to free.
 */
void
free_task (task_t* task)
{
  tracef ("   Freeing task %u: \"%s\" %s (%i) %.*s[...]\n\n",
          task->id,
          task->name,
          task->comment,
          task->description_length,
          (task->description_length > 20) ? 20 : task->description_length,
          task->description);
  free (task->name);
  task->name = NULL;
  free (task->comment);
  free (task->description);
  if (task->start_time) free (task->start_time);
  if (task->end_time) free (task->end_time);
  if (task->open_ports) g_array_free (task->open_ports, TRUE);
  if (task->debugs)
    {
      g_ptr_array_foreach (task->debugs, free_message, NULL);
      g_ptr_array_free (task->debugs, TRUE);
    }
  if (task->holes)
    {
      g_ptr_array_foreach (task->holes, free_message, NULL);
      g_ptr_array_free (task->holes, TRUE);
    }
  if (task->infos)
    {
      g_ptr_array_foreach (task->infos, free_message, NULL);
      g_ptr_array_free (task->infos, TRUE);
    }
  if (task->logs)
    {
      g_ptr_array_foreach (task->logs, free_message, NULL);
      g_ptr_array_free (task->logs, TRUE);
    }
  if (task->notes)
    {
      g_ptr_array_foreach (task->notes, free_message, NULL);
      g_ptr_array_free (task->notes, TRUE);
    }
}

/**
 * @brief Free all tasks and the array of tasks.
 */
void
free_tasks ()
{
  task_t* index = tasks;
  task_t* end = tasks + tasks_size;
  while (index < end)
    {
      if (index->name) free_task (index);
      index++;
    }
  tasks_size = 0;
  free (tasks);
  tasks = NULL;
}

/**
 * @brief Make a task.
 *
 * The char* parameters name and comment are used directly and freed
 * when the task is freed.
 *
 * @param[in]  name     The name of the task.
 * @param[in]  time     The period of the task, in seconds.
 * @param[in]  comment  A comment associated the task.
 *
 * @return A pointer to the new task or NULL when out of memory (in which
 *         case caller must free name and comment).
 */
task_t*
make_task (char* name, unsigned int time, char* comment)
{
  tracef ("   make_task %s %u %s\n", name, time, comment);
  if (tasks == NULL && grow_tasks ()) return NULL;
  task_t* index = tasks;
  task_t* end = tasks + tasks_size;
  while (1)
    {
      while (index < end)
        {
          if (index->name == NULL)
            {
              index->id = index - tasks;
              index->name = name;
              index->time = time;
              index->comment = comment;
              index->description = NULL;
              index->description_size = 0;
              index->run_status = TASK_STATUS_NEW;
              index->report_count = 0;
              index->open_ports = NULL;
              index->debugs = g_ptr_array_new ();
              index->debugs_size = 0;
              index->holes = g_ptr_array_new ();
              index->holes_size = 0;
              index->infos = g_ptr_array_new ();
              index->infos_size = 0;
              index->logs = g_ptr_array_new ();
              index->logs_size = 0;
              index->notes = g_ptr_array_new ();
              index->notes_size = 0;
              tracef ("   Made task %i at %p\n", index->id, index);
              num_tasks++;
              return index;
            }
          index++;
        }
      index = (task_t*) tasks_size;
      /* grow_tasks updates tasks_size. */
      if (grow_tasks ()) return NULL;
      index = index + (int) tasks;
    }
}

/**
 * @brief Load the tasks from disk.
 *
 * @return 0 success, -1 error.
 */
int
load_tasks ()
{
  if (tasks) return -1;

  if (current_credentials.username == NULL) return -1;

  tracef ("   Loading tasks...\n");

  GError* error = NULL;
  gchar* dir_name = g_build_filename (PREFIX
                                      "/var/lib/openvas/mgr/users/",
                                      current_credentials.username,
                                      "tasks",
                                      NULL);

  struct dirent ** names;
  int count;

  count = scandir (dir_name, &names, NULL, alphasort);
  if (count < 0)
    {
      if (errno == ENOENT)
        {
          free (dir_name);
          tracef ("   Loading tasks... done\n");
          return 0;
        }
      fprintf (stderr, "Failed to open dir %s: %s\n",
               dir_name,
               strerror (errno));
      g_free (dir_name);
      return -1;
    }

  int index;
  gchar* file_name = NULL;
  for (index = 0; index < count; index++)
    {
      const char* task_name = names[index]->d_name;

      if (task_name[0] == '.') continue;

      gchar *name, *comment, *description;
      unsigned int time;

      tracef ("     %s\n", task_name);

      file_name = g_build_filename (dir_name, task_name, "name", NULL);
      g_file_get_contents (file_name, &name, NULL, &error);
      if (error) goto contents_fail;

      g_free (file_name);
      file_name = g_build_filename (dir_name, task_name, "time", NULL);
      g_file_get_contents (file_name, &comment, NULL, &error);
      if (error)
        {
          g_free (name);
          goto contents_fail;
        }
      if (sscanf (comment, "%u", &time) != 1)
        {
          fprintf (stderr, "Failed to scan time: %s\n", comment);
          g_free (comment);
          g_free (name);
          goto fail;
        }
      g_free (comment);

      g_free (file_name);
      file_name = g_build_filename (dir_name, task_name, "comment", NULL);
      g_file_get_contents (file_name, &comment, NULL, &error);
      if (error)
        {
          g_free (name);
          goto contents_fail;
        }
      g_free (file_name);

      task_t* task = make_task (name, time, comment);
      if (task == NULL)
        {
          g_free (name);
          g_free (comment);
          g_free (dir_name);
          for (; index < count; index++) free (names[index]);
          free (names);
          free_tasks ();
          return -1;
        }
      /* name and comment are freed with the new task. */

      gsize description_length;
      file_name = g_build_filename (dir_name, task_name, "description", NULL);
      g_file_get_contents (file_name,
                           &description,
                           &description_length,
                           &error);
      if (error) goto contents_fail;

      task->description = description;
      task->description_size = task->description_length = description_length;

      g_free (file_name);
      file_name = g_build_filename (dir_name, task_name, "report_count", NULL);
      g_file_get_contents (file_name, &comment, NULL, &error);
      if (error) goto contents_fail;
      if (sscanf (comment, "%u", &task->report_count) != 1)
        {
          fprintf (stderr, "Failed to scan report count: %s\n", comment);
          goto fail;
        }

      free (names[index]);
    }

  g_free (dir_name);
  free (names);

  tracef ("   Loading tasks... done\n");
  return 0;

 contents_fail:
  fprintf (stderr, "Failed to get contents of %s: %s\n",
           file_name,
           error->message);
 fail:
  g_error_free (error);
  g_free (dir_name);
  g_free (file_name);
  for (; index < count; index++) free (names[index]);
  free (names);
  free_tasks ();
  return -1;
}

/**
 * @brief Save a task to a directory.
 *
 * Save a task to a given directory, ensuring that the directory exists
 * before saving the task.
 *
 * @param[in]  task      The task.
 * @param[in]  dir_name  The directory.
 *
 * @return 0 success, -1 error.
 */
int
save_task (task_t* task, gchar* dir_name)
{
  GError* error = NULL;

  /* Ensure directory exists. */

  if (g_mkdir_with_parents (dir_name, 33216 /* -rwx------ */) == -1)
    {
      fprintf (stderr, "Failed to create task dir %s: %s\n",
               dir_name,
               strerror (errno));
      return -1;
    }

  /* Save each component of the task. */

  gchar* file_name = g_build_filename (dir_name, "name", NULL);

  g_file_set_contents (file_name, task->name, -1, &error);
  if (error) goto contents_fail;
  g_free (file_name);

  file_name = g_build_filename (dir_name, "comment", NULL);
  g_file_set_contents (file_name, task->comment, -1, &error);
  if (error) goto contents_fail;
  g_free (file_name);

  file_name = g_build_filename (dir_name, "description", NULL);
  g_file_set_contents (file_name,
                       task->description,
                       task->description_length,
                       &error);
  if (error) goto contents_fail;
  g_free (file_name);

  file_name = g_build_filename (dir_name, "time", NULL);
  static char buffer[11]; /* (expt 2 32) => 4294967296 */
  int length = sprintf (buffer, "%u", task->time);
  assert (length < 11);
  if (length < 1) goto contents_fail;
  g_file_set_contents (file_name, buffer, -1, &error);
  if (error) goto contents_fail;
  g_free (file_name);

  file_name = g_build_filename (dir_name, "report_count", NULL);
  length = sprintf (buffer, "%u", task->report_count);
  assert (length < 11);
  if (length < 1) goto contents_fail;
  g_file_set_contents (file_name, buffer, -1, &error);
  if (error) goto contents_fail;
  g_free (file_name);

  return 0;

 contents_fail:
  fprintf (stderr, "Failed to set contents of %s: %s\n",
           file_name,
           error->message);
  g_error_free (error);
  g_free (file_name);
  return -1;
}

/**
 * @brief Save all tasks to disk.
 *
 * @return 0 success, -1 error.
 */
int
save_tasks ()
{
  if (tasks == NULL) return 0;
  if (current_credentials.username == NULL) return -1;

  tracef ("   Saving tasks...\n");

  // FIX Could check if up to date already.

  gchar* dir_name = g_build_filename (PREFIX
                                      "/var/lib/openvas/mgr/users/",
                                      current_credentials.username,
                                      "tasks",
                                      NULL);

  /* Write each task in the tasks array to disk. */

  task_t* index = tasks;
  task_t* end = tasks + tasks_size;
  while (index < end)
    {
      if (index->name)
        {
          const char* id;
          tracef ("     %u\n", index->id);

          if (task_id_string (index, &id)) return -1;

          gchar* file_name = g_build_filename (dir_name,
                                               id,
                                               NULL);
          if (save_task (index, file_name))
            {
              g_free (file_name);
              return -1;
            }
          g_free (file_name);
        }
      index++;
    }

  tracef ("   Saving tasks... done.\n");
  return 0;
}

/**
 * @brief Find a task given an identifier.
 *
 * @param[in]  id  A task identifier.
 *
 * @return A pointer to the task with the given ID.
 */
task_t*
find_task (unsigned int id)
{
  task_t* index = tasks;
  task_t* end = tasks + tasks_size;
  while (index < end)
    {
      if (index->name) tracef ("   %u vs %u\n", index->id, id);
      if (index->name && index->id == id) return index; else index++;
    }
  return NULL;
}

/**
 * @brief Set a task parameter.
 *
 * The "value" parameter is used directly and freed either immediately or
 * when the task is freed.
 *
 * @param[in]  task       A pointer to a task.
 * @param[in]  parameter  The name of the parameter (in any case): TASK_FILE,
 *                        IDENTIFIER or COMMENT.
 * @param[in]  value      The value of the parameter, in base64 if parameter
 *                        is "TASK_FILE".
 *
 * @return 0 on success, -1 when out of memory, -2 if parameter name error.
 */
int
set_task_parameter (task_t* task, const char* parameter, char* value)
{
  tracef ("   set_task_parameter %u %s\n", task->id, parameter);
  if (strncasecmp ("TASK_FILE", parameter, 9) == 0)
    {
      gsize out_len;
      guchar* out;
      out = g_base64_decode (value, &out_len);
      free (value);
      free (task->description);
      task->description = (char*) out;
      task->description_length = task->description_size = out_len;
    }
  else if (strncasecmp ("IDENTIFIER", parameter, 10) == 0)
    {
      unsigned int id;
      if (sscanf (value, "%u", &id) != 1) return -1;
      free (value);
      task->id = id;
    }
  else if (strncasecmp ("COMMENT", parameter, 7) == 0)
    {
      task->comment = value;
    }
  else
    return -2;
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
start_task (task_t* task)
{
  tracef ("   start task %u\n", task->id);

  if (task->run_status == TASK_STATUS_REQUESTED
      || task->run_status == TASK_STATUS_RUNNING)
    return 0;

  if (send_to_server ("CLIENT <|> PREFERENCES <|>\n")) return -1;

  if (send_to_server ("ntp_keep_communication_alive <|> yes\n")) return -1;
  if (send_to_server ("ntp_client_accepts_notes <|> yes\n")) return -1;
  //if (send_to_server ("ntp_short_status <|> yes\n")) return -1;
  if (send_to_server ("plugin_set <|> \n")) return -1;
  // FIX
  if (send_to_server ("port_range <|> 21\n")) return -1;
#if 0
  if (send_to_server (task_plugins (task))) return -1;
#endif
  if (send_to_server ("\n")) return -1;
#if 0
  queue_task_preferences (task);
  queue_task_plugin_preferences (task);
#endif
  if (send_to_server ("<|> CLIENT\n")) return -1;

  if (send_to_server ("CLIENT <|> RULES <|>\n")) return -1;
#if 0
  queue_task_rules (task);
#endif
  if (send_to_server ("<|> CLIENT\n")) return -1;

#if 0
  char* targets = task_preference (task, "targets");
  if (send_to_server ("CLIENT <|> LONG_ATTACK <|>\n%d\n%s\n",
                      strlen (targets),
                      targets))
    return -1;
#else
  if (send_to_server ("CLIENT <|> LONG_ATTACK <|>\n3\ndik\n"))
    return -1;
#endif

  task->run_status = TASK_STATUS_REQUESTED;

  if (task->open_ports) g_array_free (task->open_ports, TRUE);
  task->open_ports = g_array_new (FALSE, FALSE, sizeof (port_t));
  task->open_ports_size = 0;
  // FIX holes,...  reset_task_data (task);

  current_server_task = task;

  return 0;
}

/**
 * @brief Stop a task.
 *
 * Use \ref send_to_server to queue the task stop sequence in
 * \ref to_server.
 *
 * @param[in]  task  A pointer to the task.
 *
 * @return 0 on success, -1 if out of space in \ref to_server buffer.
 */
int
stop_task (task_t* task)
{
  tracef ("   stop task %u\n", task->id);
  if (task->run_status == TASK_STATUS_REQUESTED
      || task->run_status == TASK_STATUS_RUNNING)
    {
      // FIX dik
      if (send_to_server ("CLIENT <|> STOP_ATTACK <|> dik <|> CLIENT\n"))
        return -1;
      // FIX TASK_STATUS_STOP_REQUESTED?
      task->run_status = TASK_STATUS_DONE;
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
int
delete_reports (task_t* task)
{
  const char* id;

  if (task_id_string (task, &id)) return -1;

  if (current_credentials.username == NULL) return -1;

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

  int index;
  for (index = 0; index < count; index++)
    {
      const char* report_name = names[index]->d_name;

      if (report_name[0] == '.'
          || strlen (report_name) < 5
          || strcmp (report_name + strlen (report_name) - 4, ".nbe"))
        continue;

      int ret = delete_report (report_name);
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

/**
 * @brief Delete a task.
 *
 * Stop the task beforehand with \ref stop_task, if it is running.
 *
 * @param[in]  task  A pointer to the task.
 *
 * @return 0 on success, -1 if out of space in \ref to_server buffer.
 */
int
delete_task (task_t* task)
{
  const char* id;
  tracef ("   delete task %u\n", task->id);

  if (task_id_string (task, &id)) return -1;

  if (current_credentials.username == NULL) return -1;

  if (stop_task (task) == -1) return -1;

  // FIX may be atomic problems here

  if (delete_reports (task)) return -1;

  gchar* name = g_build_filename (PREFIX
                                  "/var/lib/openvas/mgr/users/",
                                  current_credentials.username,
                                  "tasks",
                                  id,
                                  NULL);
  GError* error = NULL;
  rmdir_recursively (name, &error);
  if (error)
    {
      fprintf (stderr, "Failed to remove task dir %s: %s\n",
               name,
               error->message);
      g_error_free (error);
      g_free (name);
      return -1;
    }
  g_free (name);

  free_task (task);

  return 0;
}

/**
 * @brief Append text to the comment associated with a task.
 *
 * @param[in]  task    A pointer to the task.
 * @param[in]  text    The text to append.
 * @param[in]  length  Length of the text.
 *
 * @return 0 on success, -1 if out of memory.
 */
int
append_to_task_comment (task_t* task, const char* text, int length)
{
  if (task->comment)
    {
      // FIX
      char* new = g_strconcat (task->comment, text, NULL);
      task->comment = new;
      return 0;
    }
  task->comment = strdup (text);
  return task->comment == NULL;
}

/**
 * @brief Append text to the identifier associated with a task.
 *
 * @param[in]  task    A pointer to the task.
 * @param[in]  text    The text to append.
 * @param[in]  length  Length of the text.
 *
 * @return 0 on success, 1 if out of memory.
 */
int
append_to_task_identifier (task_t* task, const char* text, int length)
{
  if (task->name)
    {
      // FIX
      char* new = g_strconcat (task->name, text, NULL);
      task->name = new;
      return 0;
    }
  task->name = strdup (text);
  return task->name == NULL;
}

/**
 * @brief Reallocation increment for a task description.
 */
#define DESCRIPTION_INCREMENT 4096

/**
 * @brief Increase the memory allocated for a task description.
 *
 * @param[in]  task       A pointer to the task.
 * @param[in]  increment  Minimum number of bytes to increase memory.
 *
 * @return 0 on success, -1 if out of memory.
 */
int
grow_description (task_t* task, int increment)
{
  int new_size = task->description_size
                 + (increment < DESCRIPTION_INCREMENT
                    ? DESCRIPTION_INCREMENT : increment);
  char* new = realloc (task->description, new_size);
  if (new == NULL) return -1;
  tracef ("   grew description to %i (at %p).\n", new_size, new);
  task->description = new;
  task->description_size = new_size;
  return 0;
}

/**
 * @brief Add a line to a task description.
 *
 * @param[in]  task         A pointer to the task.
 * @param[in]  line         The line.
 * @param[in]  line_length  The length of the line.
 */
int
add_task_description_line (task_t* task, const char* line, int line_length)
{
  if (task->description_size - task->description_length < line_length
      && grow_description (task, line_length))
    return -1;
  char* description = task->description;
  description += task->description_length;
  strncpy (description, line, line_length);
  task->description_length += line_length;
  return 0;
}

/**
 * @brief Set the ports of a task.
 *
 * @param[in]  task     The task.
 * @param[in]  current  New value for port currently being scanned.
 * @param[in]  max      New value for last port to be scanned.
 */
void
set_task_ports (task_t *task, unsigned int current, unsigned int max)
{
  task->current_port = current;
  task->max_port = max;
}

/**
 * @brief Add an open port to a task.
 *
 * @param[in]  task       The task.
 * @param[in]  number     The port number.
 * @param[in]  protocol   The port protocol.
 */
void
append_task_open_port (task_t *task, unsigned int number, char* protocol)
{
  port_t port;

  port.number = number;
  if (strncasecmp ("udp", protocol, 3) == 0)
    port.protocol = PORT_PROTOCOL_UDP;
  else if (strncasecmp ("tcp", protocol, 3) == 0)
    port.protocol = PORT_PROTOCOL_TCP;
  else
    port.protocol = PORT_PROTOCOL_OTHER;

  g_array_append_val (task->open_ports, port);
  task->open_ports_size++;
}
