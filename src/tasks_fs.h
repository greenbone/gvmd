/* OpenVAS Manager
 * $Id$
 * Description: Manager Manage library: file system based tasks.
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


/* Variables. */

/**
 * @brief Reallocation increment for the tasks array.
 */
#define TASKS_INCREMENT 1024

/**
 * @brief The array of all the tasks of the current user.
 */
task_t tasks = NULL;

/**
 * @brief The size of the \ref tasks array.
 */
unsigned int tasks_size = 0;

/**
 * @brief The number of defined tasks.
 */
unsigned int num_tasks = 0;


/* Functions. */

/**
 * @brief Initialize the manage library for a process.
 *
 * Simply open the SQL database.
 */
void
init_manage_process ()
{
  /* Empty. */
}

/**
 * @brief Initialize the manage library.
 *
 * \todo TODO: Implement.
 *
 * @return 0 on success, else -1.
 */
int
init_manage ()
{
  /* Set requested and running tasks to stopped. */

  return 0;
}

/**
 * @brief Cleanup the manage library.
 */
void
cleanup_manage_process ()
{
  /* Empty. */
}

/**
 * @brief Authenticate credentials.
 *
 * @param[in]  credentials  Credentials.
 *
 * @return 0 if credentials are authentic, -1 on error, else 0.
 */
int
authenticate (credentials_t* credentials)
{
  if (credentials->username && credentials->password)
    return openvas_authenticate (credentials->username, credentials->password);
  return 1;
}

/**
 * @brief Return the number of tasks associated with the current user.
 *
 * @return The number of tasks associated with the current user.
 */
unsigned int
task_count ()
{
  return num_tasks;
}

/**
 * @brief Initialise a task iterator.
 *
 * @param[in]  iterator  Task iterator.
 */
void
init_task_iterator (task_iterator_t* iterator)
{
  iterator->index = tasks;
  iterator->end = tasks + tasks_size;
}

/**
 * @brief Read the next task from an iterator.
 *
 * @param[in]   iterator  Task iterator.
 * @param[out]  task      Task.
 *
 * @return TRUE if there was a next task, else FALSE.
 */
gboolean
next_task (task_iterator_t* iterator, task_t* task)
{
  while (1)
    {
      if (iterator->index == iterator->end) return FALSE;
      if (iterator->index->name) break;
      iterator->index++;
    }
  if (task) *task = iterator->index;
  iterator->index++;
  return TRUE;
}

/**
 * @brief Return the identifier of a task.
 *
 * @param[in]  task  Task.
 *
 * @return ID of task.
 */
unsigned int
task_id (task_t task)
{
  return task->id;
}

/**
 * @brief Return the UUID of a task.
 *
 * \todo TODO: Implement FS task UUIDs.
 *
 * @param[in]   task  Task.
 * @param[out]  id    Pointer to a string.  On successful return contains a
 *                    pointer to a newly allocated buffer with the task ID
 *                    as a string.
 *
 * @return 0 success, -1 error.
 */
int
task_uuid (task_t task, char ** id)
{
  *id = g_strdup_printf ("%010u", task->id);
  return 0;
}

/**
 * @brief Return the name of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Task name.
 */
char*
task_name (task_t task)
{
  return g_strdup (task->name);
}

/**
 * @brief Return the comment of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Comment of task.
 */
char*
task_comment (task_t task)
{
  return g_strdup (task->comment);
}

/**
 * @brief Return the description of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Description of task.
 */
char*
task_description (task_t task)
{
  return g_strdup (task->description);
}

/**
 * @brief Set the description of a task.
 *
 * @param[in]  task         Task.
 * @param[in]  description  Description.  Used directly, freed by free_task.
 * @param[in]  length       Length of description.
 */
void
set_task_description (task_t task, char* description, gsize length)
{
  if (task->description) free (task->description);
  task->description = description;
  task->description_length = length;
  task->description_size = length;
}

/**
 * @brief Return the run state of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Task run status.
 */
task_status_t
task_run_status (task_t task)
{
  return task->run_status;
}

/**
 * @brief Set the run state of a task.
 *
 * @param[in]  task    Task.
 * @param[in]  status  New run status.
 *
 */
void
set_task_run_status (task_t task, task_status_t status)
{
  task->run_status = status;
}

/**
 * @brief Return the most recent start time of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Task start time.
 */
char*
task_start_time (task_t task)
{
  return g_strdup (task->start_time);
}

/**
 * @brief Set the start time of a task.
 *
 * @param[in]  task  Task.
 * @param[in]  time  New time.  Used directly, freed by free_task.
 */
void
set_task_start_time (task_t task, char* time)
{
  if (task->start_time) free (task->start_time);
  task->start_time = time;
}

/**
 * @brief Return the most recent end time of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Task end time.
 */
char*
task_end_time (task_t task)
{
  return g_strdup (task->end_time);
}

/**
 * @brief Set the end time of a task.
 *
 * @param[in]  task  Task.
 * @param[in]  time  New time.  Used directly, freed by free_task.
 */
void
set_task_end_time (task_t task, char* time)
{
  if (task->end_time) free (task->end_time);
  task->end_time = time;
}

/**
 * @brief Return the number of reports associated with a task.
 *
 * @param[in]  task  Task.
 *
 * @return Number of reports.
 */
unsigned int
task_report_count (task_t task)
{
  return task->report_count;
}

/**
 * @brief Return the attack state of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Task attack state.
 */
char*
task_attack_state (task_t task)
{
  return g_strdup (task->attack_state);
}

/**
 * @brief Set the attack state of a task.
 *
 * @param[in]  task   Task.
 * @param[in]  state  New state.
 */
void
set_task_attack_state (task_t task, char* state)
{
  if (task->attack_state) free (task->attack_state);
  task->attack_state = state;
}

/**
 * @brief Return the number of debug messages in the current report of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Number of debug messages.
 */
int
task_debugs_size (task_t task)
{
  return task->debugs_size;
}

/**
 * @brief Increment number of debug messages in the current report of a task.
 *
 * @param[in]  task  Task.
 */
void
inc_task_debugs_size (task_t task)
{
  task->debugs_size++;
}

/**
 * @brief Return the number of hole messages in the current report of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Number of hole messages.
 */
int
task_holes_size (task_t task)
{
  return task->holes_size;
}

/**
 * @brief Increment number of hole messages in the current report of a task.
 *
 * @param[in]  task  Task.
 */
void
inc_task_holes_size (task_t task)
{
  task->holes_size++;
}

/**
 * @brief Return the number of info messages in the current report of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Number of info messages.
 */
int
task_infos_size (task_t task)
{
  return task->infos_size;
}

/**
 * @brief Increment number of info messages in the current report of a task.
 *
 * @param[in]  task  Task.
 */
void
inc_task_infos_size (task_t task)
{
  task->infos_size++;
}

/**
 * @brief Return the number of log messages in the current report of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Number of log messages.
 */
int
task_logs_size (task_t task)
{
  return task->logs_size;
}

/**
 * @brief Increment number of log messages in the current report of a task.
 *
 * @param[in]  task  Task.
 */
void
inc_task_logs_size (task_t task)
{
  task->logs_size++;
}

/**
 * @brief Return the number of note messages in the current report of a task.
 *
 * @param[in]  task  Task.
 *
 * @return Number of note messages.
 */
int
task_notes_size (task_t task)
{
  return task->notes_size;
}

/**
 * @brief Increment number of note messages in the current report of a task.
 *
 * @param[in]  task  Task.
 */
void
inc_task_notes_size (task_t task)
{
  task->notes_size++;
}

/**
 * @brief Increment report count.
 *
 * @param[in]  task  Task.
 */
void
inc_task_report_count (task_t task)
{
  task->report_count++;
}

/**
 * @brief Decrement report count.
 *
 * @param[in]  task  Task.
 */
void
dec_task_report_count (task_t task)
{
  task->report_count--;
}

#if 0
#if TRACE
/**
 * @brief Print the server tasks.
 */
static void
print_tasks ()
{
  task_t index = tasks;

  if (index == NULL)
    tracef ("   Task array still to be created.\n\n");
  else
    {
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
                      index->comment ? index->comment : "",
                      index->description ? index->description : "");
            }
          index++;
        }
    }
}
#endif
#endif

/**
 * @brief Grow the array of tasks.
 *
 * @return TRUE on success, FALSE on error (out of memory).
 */
static gboolean
grow_tasks ()
{
  task_t new;
  tracef ("   task_t size: %i\n", (int) sizeof (fs_task_t));
/*@-compdestroy@*/
/*@-sharedtrans@*/
  /* RATS: ignore *//* Memory cleared below. */
  new = realloc (tasks,
                 (tasks_size + TASKS_INCREMENT) * sizeof (fs_task_t));
/*@=sharedtrans@*/
/*@=compdestroy@*/
/*@-globstate@*/
  if (new == NULL) return FALSE;
/*@=globstate@*/
  tasks = new;

  /* Clear the new part of the memory. */
  new = tasks + tasks_size;
  memset (new, 0, TASKS_INCREMENT * sizeof (fs_task_t));

  tasks_size += TASKS_INCREMENT;
  tracef ("   tasks grown to %u\n", tasks_size);
#if 0
#if TRACE
  print_tasks ();
#endif
#endif
  return TRUE;
}

/**
 * @brief Free a task.
 *
 * Free all the members of a task.
 *
 * @param[in]  task  The task to free.
 */
static void
free_task (/*@special@*/ /*@dependent@*/ task_t task)
  /*@ensures isnull task->name@*/
  /*@releases task->comment, task->open_ports@*/
{
  tracef ("   Freeing task %u: \"%s\" %s (%i) %.*s[...]\n\n",
          task->id,
          task->name,
          task->comment,
          (int) task->description_length,
          (task->description_length > 20) ? 20 : task->description_length,
          task->description ? task->description : "(null)");
  free (task->name);
  task->name = NULL;
  free (task->comment);
  if (task->description) free (task->description);
  if (task->start_time) free (task->start_time);
  if (task->end_time) free (task->end_time);
  if (current_report)
    {
      (void) fclose (current_report); // FIX check for error
      current_report = NULL;
    }
  if (task->open_ports) (void) g_array_free (task->open_ports, TRUE);
}

/**
 * @brief Free all tasks and the array of tasks.
 */
void
free_tasks ()
{
  if (tasks == NULL) return;

  {
    task_t index = tasks;
    task_t end = tasks + tasks_size;
    while (index < end)
      {
        /* This indicates that the state of the task depends on which
         * branch of the `if' is taken. */
        /*@-branchstate@*/
        if (index->name) free_task (index);
        /*@=branchstate@*/
        index++;
      }
    tasks_size = 0;
    free (tasks);
    tasks = NULL;
  }
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
task_t
make_task (char* name, unsigned int time, char* comment)
{
  task_t index;
  task_t end;
  tracef ("   make_task %s %u %s\n", name, time, comment);
  if (tasks == NULL && grow_tasks () == FALSE)
    {
      g_free (name);
      g_free (comment);
      return NULL;
    }
  if (tasks == NULL) abort ();
  index = tasks;
  end = tasks + tasks_size;
  while (1)
    {
      while (index < end)
        {
          if (index->name == NULL)
            {
              index->id = (unsigned int) (index - tasks);
              index->name = name;
              index->time = time;
              /* The annotation is because these are all freed with name. */
              /*@-mustfreeonly@*/
              index->comment = comment;
              index->description = NULL;
              index->description_size = 0;
              index->run_status = TASK_STATUS_NEW;
              index->report_count = 0;
              index->open_ports = NULL;
              /*@=mustfreeonly@*/
              tracef ("   Made task %u at %p\n", index->id, index);
              num_tasks++;
              return index;
            }
          index++;
        }
      index = (task_t) tasks_size;
      /* grow_tasks updates tasks_size. */
      if (grow_tasks ())
        {
          g_free (name);
          g_free (comment);
          return NULL;
        }
      index = index + (int) tasks;
    }
}

typedef /*@only@*/ struct dirent * only_dirent_pointer;

static void
load_tasks_free (/*@only@*/ gchar* dir_name, /*@only@*/ gchar* file_name,
                 int index, int count, /*@only@*/ only_dirent_pointer* names)
{
  g_free (dir_name);
  g_free (file_name);
  for (; index < count; index++) free (names[index]);
  free (names);
  free_tasks ();
}

/**
 * @brief Load the tasks from disk.
 *
 * @return 0 success, -1 error.
 */
int
load_tasks ()
{
  GError* error;
  gchar* dir_name;
  gchar* file_name;
  struct dirent ** names = NULL;
  int count, index;

  if (tasks) return -1;

  if (current_credentials.username == NULL) return -1;

  tracef ("   Loading tasks...\n");

  error = NULL;
  dir_name = g_build_filename (PREFIX
                               "/var/lib/openvas/mgr/users/",
                               current_credentials.username,
                               "tasks",
                               NULL);

  count = scandir (dir_name, &names, NULL, alphasort);
  if (count < 0 || names == NULL)
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

  file_name = NULL;
  for (index = 0; index < count; index++)
    {
      gchar *name, *comment, *description;
      unsigned int time;
      /*@dependent@*/ const char* task_name = names[index]->d_name;
      task_t task;
      gboolean success;

      if (task_name[0] == '.')
        {
          free (names[index]);
          continue;
        }

      tracef ("     %s\n", task_name);

      file_name = g_build_filename (dir_name, task_name, "name", NULL);
      success = g_file_get_contents (file_name, &name, NULL, &error);
      if (success == FALSE)
        {
          if (error)
            {
              fprintf (stderr, "Failed to get contents of %s: %s\n",
                       file_name,
                       error->message);
              g_error_free (error);
            }
          load_tasks_free (dir_name, file_name, index, count, names);
          return -1;
        }

      g_free (file_name);
      file_name = g_build_filename (dir_name, task_name, "time", NULL);
      success = g_file_get_contents (file_name, &comment, NULL, &error);
      if (success == FALSE)
        {
          g_free (name);
          if (error)
            {
              fprintf (stderr, "Failed to get contents of %s: %s\n",
                       file_name,
                       error->message);
              g_error_free (error);
            }
          load_tasks_free (dir_name, file_name, index, count, names);
          return -1;
        }
      if (sscanf (comment, "%u", &time) != 1)
        {
          fprintf (stderr, "Failed to scan time: %s\n", comment);
          g_free (comment);
          g_free (name);
          if (error) g_error_free (error);
          load_tasks_free (dir_name, file_name, index, count, names);
          return -1;
        }
      g_free (comment);

      g_free (file_name);
      file_name = g_build_filename (dir_name, task_name, "comment", NULL);
      comment = NULL;
      success = g_file_get_contents (file_name, &comment, NULL, &error);
      if (success == FALSE)
        {
          g_free (name);
          if (error)
            {
              fprintf (stderr, "Failed to get contents of %s: %s\n",
                       file_name,
                       error->message);
              g_error_free (error);
            }
          load_tasks_free (dir_name, file_name, index, count, names);
          return -1;
        }
      g_free (file_name);

      task = make_task (name, time, comment);
      if (task == NULL)
        {
          g_free (dir_name);
          for (; index < count; index++) free (names[index]);
          free (names);
          free_tasks ();
          return -1;
        }
      /* name and comment are freed with the new task. */

      {
        gsize description_length;

        file_name = g_build_filename (dir_name, task_name, "description", NULL);
        success = g_file_get_contents (file_name,
                                       &description,
                                       &description_length,
                                       &error);
        if (success == FALSE)
          {
            if (error)
              {
                fprintf (stderr, "Failed to get contents of %s: %s\n",
                         file_name,
                         error->message);
                g_error_free (error);
              }
            load_tasks_free (dir_name, file_name, index, count, names);
            return -1;
          }

        task->description = description;
        task->description_size = task->description_length = description_length;
      }

      g_free (file_name);
      file_name = g_build_filename (dir_name, task_name, "report_count", NULL);
      comment = NULL;
      success = g_file_get_contents (file_name, &comment, NULL, &error);
      if (success == FALSE)
        {
          if (error)
            {
              fprintf (stderr, "Failed to get contents of %s: %s\n",
                       file_name,
                       error->message);
              g_error_free (error);
            }
          load_tasks_free (dir_name, file_name, index, count, names);
          return -1;
        }
      if (sscanf (comment, "%u", &task->report_count) != 1)
        {
          fprintf (stderr, "Failed to scan report count: %s\n", comment);
          if (error) g_error_free (error);
          load_tasks_free (dir_name, file_name, index, count, names);
          return -1;
        }

      g_free (file_name);
      free (names[index]);
    }

  g_free (dir_name);
  free (names);

  tracef ("   Loading tasks... done\n");
  return 0;
}

static void
save_task_error (/*@only@*/ gchar* file_name, /*@only@*/ GError* error)
{
  if (error)
    {
      fprintf (stderr, "Failed to set contents of %s: %s\n",
               file_name,
               error->message);
      g_error_free (error);
    }
  g_free (file_name);
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
static int
save_task (task_t task, gchar* dir_name)
{
  gboolean success;
  gchar* file_name;
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

  file_name = g_build_filename (dir_name, "name", NULL);

  success = g_file_set_contents (file_name, task->name, -1, &error);
  if (success == FALSE)
    {
      save_task_error (file_name, error);
      return -1;
    }
  g_free (file_name);

  file_name = g_build_filename (dir_name, "comment", NULL);
  success = g_file_set_contents (file_name, task->comment, -1, &error);
  if (success == FALSE)
    {
      save_task_error (file_name, error);
      return -1;
    }
  g_free (file_name);

  file_name = g_build_filename (dir_name, "description", NULL);
  if (task->description == NULL)
    success = g_file_set_contents (file_name, "", 0, &error);
  else
    success = g_file_set_contents (file_name,
                                   task->description,
                                   task->description_length,
                                   &error);
  if (success == FALSE)
    {
      save_task_error (file_name, error);
      return -1;
    }
  g_free (file_name);

  file_name = g_build_filename (dir_name, "time", NULL);
  {
    static char buffer[11]; /* (expt 2 32) => 4294967296 */
    int length = snprintf (buffer, 11, "%u", task->time);
    assert (length < 11);

    if (length < 1 || length > 10)
      {
        save_task_error (file_name, error);
        return -1;
      }
    success = g_file_set_contents (file_name, buffer, -1, &error);
    if (success == FALSE)
      {
        save_task_error (file_name, error);
        return -1;
      }
    g_free (file_name);

    file_name = g_build_filename (dir_name, "report_count", NULL);
    length = snprintf (buffer, 11, "%u", task->report_count);
    assert (length < 11);
    if (length < 1 || length > 10)
      {
        save_task_error (file_name, error);
        return -1;
      }
    success = g_file_set_contents (file_name, buffer, -1, &error);
    if (success == FALSE)
      {
        save_task_error (file_name, error);
        return -1;
      }
  }
  g_free (file_name);

  return 0;
}

/**
 * @brief Save all tasks to disk.
 *
 * @return 0 success, -1 error.
 */
int
save_tasks ()
{
  gchar* dir_name;
  task_t index;
  task_t end;

  if (tasks == NULL) return 0;
  if (current_credentials.username == NULL) return -1;

  tracef ("   Saving tasks...\n");

  // FIX Could check if up to date already.

  dir_name = g_build_filename (PREFIX
                               "/var/lib/openvas/mgr/users/",
                               current_credentials.username,
                               "tasks",
                               NULL);

  /* Write each task in the tasks array to disk. */

  index = tasks;
  end = tasks + tasks_size;
  while (index < end)
    {
      if (index->name)
        {
          char* tsk_uuid;
          gchar* file_name;
          tracef ("     %u\n", index->id);

          if (task_uuid (index, &tsk_uuid))
            {
              g_free (dir_name);
              return -1;
            }

          file_name = g_build_filename (dir_name,
                                        tsk_uuid,
                                        NULL);
          free (tsk_uuid);
          if (save_task (index, file_name))
            {
              g_free (dir_name);
              g_free (file_name);
              return -1;
            }
          g_free (file_name);
        }
      index++;
    }

  g_free (dir_name);
  tracef ("   Saving tasks... done.\n");
  return 0;
}

/**
 * @brief Set a task parameter.
 *
 * The "value" parameter is used directly and freed either immediately or
 * when the task is freed or when the parameter is next updated.
 *
 * @param[in]  task       A pointer to a task.
 * @param[in]  parameter  The name of the parameter (in any case): TASK_FILE,
 *                        NAME or COMMENT.
 * @param[in]  value      The value of the parameter, in base64 if parameter
 *                        is "TASK_FILE".
 *
 * @return 0 on success, -1 when out of memory, -2 if parameter name error,
 *         -3 value error (NULL).
 */
int
set_task_parameter (task_t task, const char* parameter, /*@only@*/ char* value)
{
  tracef ("   set_task_parameter %u %s\n",
          task->id,
          parameter ? parameter : "(null)");
  if (value == NULL) return -3;
  if (parameter == NULL)
    {
      free (value);
      return -2;
    }
  if (strncasecmp ("TASK_FILE", parameter, 9) == 0)
    {
      gsize out_len;
      guchar* out;
      out = g_base64_decode (value, &out_len);
      free (value);
      if (task->description) free (task->description);
      task->description = (char*) out;
      task->description_length = task->description_size = out_len;
    }
  else if (strncasecmp ("NAME", parameter, 4) == 0)
    {
      free (task->name);
      task->name = value;
    }
  else if (strncasecmp ("COMMENT", parameter, 7) == 0)
    {
      free (task->comment);
      task->comment = value;
    }
  else
    {
      free (value);
      return -2;
    }
  return 0;
}

/**
 * @brief Request deletion of a task.
 *
 * Stop the task beforehand with \ref stop_task, if it is running.
 *
 * @param[in]  task_pointer  A pointer to the task.
 *
 * @return 0 on success, -1 on error.
 */
int
request_delete_task (task_t* task_pointer)
{
  task_t task = *task_pointer;

  tracef ("   request delete task %u\n", task_id (task));

  if (current_credentials.username == NULL) return -1;

  if (stop_task (task) == -1) return -1;

  set_task_run_status (task, TASK_STATUS_DELETE_REQUESTED);

  return 0;
}

/**
 * @brief Complete deletion of a task.
 *
 * @param[in]  task  The task.
 *
 * @return 0 on success, -1 on error.
 */
int
delete_task (task_t task)
{
  gboolean success;
  char* tsk_uuid;
  gchar* name;
  GError* error;

  tracef ("   delete task %u\n", task_id (task));

  if (current_credentials.username == NULL) return -1;

  if (task_uuid (task, &tsk_uuid)) return -1;

  // FIX may be atomic problems here

  if (delete_reports (task))
    {
      free (tsk_uuid);
      return -1;
    }

  name = g_build_filename (PREFIX
                           "/var/lib/openvas/mgr/users/",
                           current_credentials.username,
                           "tasks",
                           tsk_uuid,
                           NULL);
  free (tsk_uuid);
  error = NULL;
  success = rmdir_recursively (name, &error);
  if (success == FALSE)
    {
      if (error)
        {
          fprintf (stderr, "Failed to remove task dir %s: %s\n",
                   name,
                   error->message);
          g_error_free (error);
        }
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
append_to_task_comment (task_t task, const char* text, /*@unused@*/ int length)
{
  char* new;
  if (task->comment)
    {
      // FIX
      new = g_strconcat (task->comment, text, NULL);
      free (task->comment);
      task->comment = new;
      return 0;
    }
  new = strdup (text);
  if (new == NULL) return -1;
  task->comment = new;
  return 0;
}

/**
 * @brief Append text to the identifier associated with a task.
 *
 * @param[in]  task    A pointer to the task.
 * @param[in]  text    The text to append.
 * @param[in]  length  Length of the text.
 *
 * @return 0 on success, -1 if out of memory.
 */
int
append_to_task_identifier (task_t task, const char* text,
                           /*@unused@*/ int length)
{
  char* new;
  if (task->name)
    {
      new = g_strconcat (task->name, text, NULL);
      g_free (task->name);
      task->name = new;
      return 0;
    }
  new = strdup (text);
  if (new == NULL) return -1;
  task->name = new;
  return 0;
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
static int
grow_description (task_t task, size_t increment)
{
  size_t new_size = task->description_size
                    + (increment < DESCRIPTION_INCREMENT
                       ? DESCRIPTION_INCREMENT : increment);
  /* RATS: ignore *//* Memory cleared below. */
  char* new = realloc (task->description, new_size);
  if (new == NULL) return -1;
  memset (new, (int) '\0', new_size - task->description_size);
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
add_task_description_line (task_t task, const char* line, size_t line_length)
{
  char* description;
  if (task->description_size - task->description_length < line_length
      && grow_description (task, line_length) < 0)
    return -1;
  description = task->description;
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
set_task_ports (task_t task, unsigned int current, unsigned int max)
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
append_task_open_port (task_t task, unsigned int number, char* protocol)
{
  assert (task->open_ports != NULL);
  if (task->open_ports)
    {
      port_t port;

      port.number = number;
      if (strncasecmp ("udp", protocol, 3) == 0)
        port.protocol = PORT_PROTOCOL_UDP;
      else if (strncasecmp ("tcp", protocol, 3) == 0)
        port.protocol = PORT_PROTOCOL_TCP;
      else
        port.protocol = PORT_PROTOCOL_OTHER;

      (void) g_array_append_val (task->open_ports, port);
      task->open_ports_size++;
    }
}

/**
 * @brief Find a task from a task identifier string.
 *
 * @param[in]   id_string  A task identifier string.
 * @param[out]  task       The task, if found.
 *
 * @return 0 if task found, else -1.
 */
int
find_task (const char* id_string, task_t* task)
{
  if (tasks)
    {
      unsigned int id;

      if (sscanf (id_string, "%u", &id) == 1)
        {
          task_t index = tasks;
          task_t end = tasks + tasks_size;
          while (index < end)
            {
              if (index->name) tracef ("   %u vs %u\n", index->id, id);

              if (index->name == NULL)
                index++;
              else if (index->id == id)
                {
                  tracef ("Found task %s at %p\n", id_string, index);
                  *task = index;
                  return 0;
                }
              else
                index++;
            }
        }
    }
  return -1;
}
