/* OpenVAS Manager
 * $Id$
 * Description: Manager Manage library: SQL based tasks.
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

#include <sqlite3.h>


/* Variables. */

sqlite3* task_db = NULL;


/* SQL helpers. */

gchar*
sql_quote (const char* string, size_t length)
{
  gchar *new, *new_start;
  const gchar *start, *end;
  int count = 0;

  /* Count number of apostrophes. */

  start = string;
  while ((start = strchr (start, '\''))) count++;

  /* Allocate new string. */

  new = new_start = g_malloc0 (length + count + 1);

  /* Copy string, replacing apostrophes with double apostrophes. */

  start = string;
  end = string + length;
  for (; start < end; start++, new++)
    {
      char ch = *start;
      if (ch == '\'')
        {
          *new = '\'';
          new++;
          *new = '\'';
        }
      else
        *new = ch;
    }

  return new_start;
}

void
sql (char* sql, ...)
{
  const char* tail;
  int ret;
  sqlite3_stmt* stmt;
  va_list args;
  gchar* formatted;

  va_start (args, sql);
  formatted = g_strdup_vprintf (sql, args);
  va_end (args);

  tracef ("   sql: %s\n", formatted);

  ret = sqlite3_prepare (task_db, (char*) formatted, -1, &stmt, &tail);
  g_free (formatted);
  if (ret != SQLITE_OK || stmt == NULL)
    {
      fprintf (stderr, "sqlite3_prepare failed: %s\n",
               sqlite3_errmsg (task_db));
      abort ();
    }
  while (1)
    {
      ret = sqlite3_step (stmt);
      if (ret == SQLITE_BUSY) continue;
      if (ret == SQLITE_DONE) break;
      if (ret == SQLITE_ERROR || ret == SQLITE_MISUSE)
        {
          if (ret == SQLITE_ERROR) ret = sqlite3_reset (stmt);
          fprintf (stderr, "sqlite3_step failed: %s\n",
                   sqlite3_errmsg (task_db));
          abort ();
        }
    }
  sqlite3_finalize (stmt);
}

void
sql_x (unsigned int col, unsigned int row, char* sql, va_list args,
       sqlite3_stmt** stmt_return)
{
  const char* tail;
  int ret;
  sqlite3_stmt* stmt;
  gchar* formatted;

  //va_start (args, sql);
  formatted = g_strdup_vprintf (sql, args);
  //va_end (args);

  tracef ("   sql_x: %s\n", formatted);

  ret = sqlite3_prepare (task_db, (char*) formatted, -1, &stmt, &tail);
  g_free (formatted);
  *stmt_return = stmt;
  if (ret != SQLITE_OK || stmt == NULL)
    {
      fprintf (stderr, "sqlite3_prepare failed: %s\n",
               sqlite3_errmsg (task_db));
      abort ();
    }
  while (1)
    {
      ret = sqlite3_step (stmt);
      if (ret == SQLITE_BUSY) continue;
      if (ret == SQLITE_DONE)
        {
          fprintf (stderr, "sqlite3_step finished too soon\n");
          abort ();
        }
      if (ret == SQLITE_ERROR || ret == SQLITE_MISUSE)
        {
          if (ret == SQLITE_ERROR) ret = sqlite3_reset (stmt);
          fprintf (stderr, "sqlite3_step failed: %s\n",
                   sqlite3_errmsg (task_db));
          abort ();
        }
      if (row == 0) break;
      row--;
      tracef ("   sql_x row %i\n", row);
    }

  tracef ("   sql_x end\n");
}

int
sql_int (unsigned int col, unsigned int row, char* sql, ...)
{
  sqlite3_stmt* stmt;
  va_list args;
  va_start (args, sql);
  sql_x (col, row, sql, args, &stmt);
  va_end (args);
  int ret = sqlite3_column_int (stmt, col);
  sqlite3_finalize (stmt);
  return ret;
}

char*
sql_string (unsigned int col, unsigned int row, char* sql, ...)
{
  sqlite3_stmt* stmt;
  const unsigned char* ret2;
  char* ret;
  va_list args;
  va_start (args, sql);
  sql_x (col, row, sql, args, &stmt);
  va_end (args);
  ret2 = sqlite3_column_text (stmt, col);
  /* TODO: For efficiency, save this duplication by adjusting the task
           interface. */
  ret = g_strdup ((char*) ret2);
  sqlite3_finalize (stmt);
  return ret;
}

long long int
sql_int64 (unsigned int col, unsigned int row, char* sql, ...)
{
  sqlite3_stmt* stmt;
  va_list args;
  va_start (args, sql);
  sql_x (col, row, sql, args, &stmt);
  va_end (args);
  long long int ret = sqlite3_column_int64 (stmt, col);
  sqlite3_finalize (stmt);
  return ret;
}


/* Task functions. */

void
inc_task_int (task_t task, const char* field)
{
  int current = sql_int (0, 0,
                         "SELECT %s FROM tasks_%s WHERE ROWID = %llu;",
                         field,
                         current_credentials.username,
                         task);
  sql ("UPDATE tasks_%s SET %s = %i WHERE ROWID = %llu;",
       current_credentials.username,
       field,
       current + 1,
       task);
}

void
dec_task_int (task_t task, const char* field)
{
  int current = sql_int (0, 0,
                         "SELECT %s FROM tasks_%s WHERE ROWID = %llu;",
                         field,
                         current_credentials.username,
                         task);
  sql ("UPDATE tasks_%s SET %s = %i WHERE ROWID = %llu;",
       current_credentials.username,
       field,
       current - 1,
       task);
}

void
append_to_task_string (task_t task, const char* field, const char* value)
{
  char* current;
  current = sql_string (0, 0,
                        "SELECT %s FROM tasks_%s WHERE ROWID = %llu;",
                        field,
                        current_credentials.username,
                        task);
  gchar* quote;
  if (current)
    {
      gchar* new = g_strconcat ((const gchar*) current, value, NULL);
      free (current);
      quote = sql_quote (new, strlen (new));
      g_free (new);
    }
  else
    quote = sql_quote (value, strlen (value));
  sql ("UPDATE tasks_%s SET %s = '%s' WHERE ROWID = %llu;",
       current_credentials.username,
       field,
       quote,
       task);
  g_free (quote);
}



/**
 * @brief Initialize the manage library.
 */
void
init_manage ()
{
  /* Open the database. */
  int ret = sqlite3_open (PREFIX "/var/lib/openvas/mgr/tasks.db", &task_db);
  if (ret)
    {
      fprintf (stderr, "sqlite3_open failed: %s\n",
               sqlite3_errmsg (task_db));
      abort ();
    }
}

/**
 * @brief Cleanup the manage library.
 */
void
cleanup_manage ()
{
  if (task_db)
    {
      sqlite3_close (task_db);
      task_db = NULL;
    }
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
  if (credentials.username)
    {
      sql ("CREATE TABLE IF NOT EXISTS tasks_%s (uuid, name, time, comment, description, run_status, start_time, end_time, report_count, attack_state, current_port, max_port, debugs_size, holes_size, infos_size, logs_size, notes_size)",
           current_credentials.username);
      return 1;
    }
  return 0;
}

/**
 * @brief Return the number of tasks associated with the current user.
 *
 * @return The number of tasks associated with the current user.
 */
unsigned int
task_count ()
{
  return (unsigned int) sql_int (0, 0,
                                 "SELECT count(*) FROM tasks_%s;",
                                 current_credentials.username);
}

/**
 * @brief Initialise a task iterator.
 *
 * @param[in]  iterator  Task iterator.
 */
void
init_task_iterator (task_iterator_t* iterator)
{
  int ret;
  const char* tail;
  gchar* formatted;
  sqlite3_stmt* stmt;

  iterator->done = FALSE;
  formatted = g_strdup_printf ("SELECT ROWID FROM tasks_%s",
                                current_credentials.username);
  tracef ("   sql (iterator): %s\n", formatted);
  ret = sqlite3_prepare (task_db, (char*) formatted, -1, &stmt, &tail);
  g_free (formatted);
  iterator->stmt = stmt;
  if (ret != SQLITE_OK || stmt == NULL)
    {
      fprintf (stderr, "sqlite3_prepare failed: %s\n",
               sqlite3_errmsg (task_db));
      abort ();
    }
}

/**
 * @brief Cleanup a task iterator.
 *
 * @param[in]  iterator  Task iterator.
 */
void
cleanup_task_iterator (task_iterator_t* iterator)
{
  sqlite3_finalize (iterator->stmt);
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
  int ret;

  tracef ("next_task (%s)\n", iterator->done ? "done" : "");

  if (iterator->done) return FALSE;

  while ((ret = sqlite3_step (iterator->stmt)) == SQLITE_BUSY);
  if (ret == SQLITE_DONE)
    {
      tracef ("  reached done\n");
      iterator->done = TRUE;
      return FALSE;
    }
  if (ret == SQLITE_ERROR || ret == SQLITE_MISUSE)
    {
      if (ret == SQLITE_ERROR) ret = sqlite3_reset (iterator->stmt);
      fprintf (stderr, "sqlite3_step failed: %s\n",
               sqlite3_errmsg (task_db));
      abort ();
    }
  *task = sqlite3_column_int64 (iterator->stmt, 0);
  tracef ("  ret %llu", *task);
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
  // FIX cast hack for tasks_fs compat, task is long long int
  return (unsigned int) task;
}

/**
 * @brief Return a string version of the ID of a task.
 *
 * @param[in]   task  Task.
 * @param[out]  id    Pointer to a string.
 *
 * @return 0.
 */
int
task_id_string (task_t task, const char ** id)
{
#if 0
  const unsigned char* str;
  str = sql_string (0, 0,
                    "SELECT uuid FROM tasks_%s WHERE ROWID = %llu;",
                    current_credentials.username,
                    task);
  // FIX caller must free
  *id = (const char*) str;
#else
  *id = g_strdup_printf ("%llu", task);
#endif
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
  return sql_string (0, 0,
                     "SELECT name FROM tasks_%s WHERE ROWID = %llu;",
                     current_credentials.username,
                     task);
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
  return sql_string (0, 0,
                     "SELECT comment FROM tasks_%s WHERE ROWID = %llu;",
                     current_credentials.username,
                     task);
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
  return sql_string (0, 0,
                     "SELECT description FROM tasks_%s WHERE ROWID = %llu;",
                     current_credentials.username,
                     task);
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
  gchar* quote = sql_quote (description, strlen (description));
  sql ("UPDATE tasks_%s SET description = '%s' WHERE ROWID = %llu;",
       current_credentials.username,
       quote,
       task);
  g_free (quote);
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
  return (unsigned int) sql_int (0, 0,
                                 "SELECT run_status FROM tasks_%s WHERE ROWID = %llu;",
                                 current_credentials.username,
                                 task);
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
  sql ("UPDATE tasks_%s SET run_status = %u WHERE ROWID = %llu;",
       current_credentials.username,
       status,
       task);
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
  return sql_string (0, 0,
                     "SELECT start_time FROM tasks_%s WHERE ROWID = %llu;",
                     current_credentials.username,
                     task);
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
  sql ("UPDATE tasks_%s SET start_time = '%.*s' WHERE ROWID = %llu;",
       current_credentials.username,
       strlen (time),
       time,
       task);
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
  return sql_string (0, 0,
                     "SELECT end_time FROM tasks_%s WHERE ROWID = %llu;",
                     current_credentials.username,
                     task);
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
  sql ("UPDATE tasks_%s SET end_time = '%.*s' WHERE ROWID = %llu;",
       current_credentials.username,
       strlen (time),
       time,
       task);
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
  return (unsigned int) sql_int (0, 0,
                                 "SELECT report_count FROM tasks_%s WHERE ROWID = %llu;",
                                 current_credentials.username,
                                 task);
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
  return sql_string (0, 0,
                     "SELECT attack_state FROM tasks_%s WHERE ROWID = %llu;",
                     current_credentials.username,
                     task);
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
  sql ("UPDATE tasks_%s SET attack_state = '%.*s' WHERE ROWID = %llu;",
       current_credentials.username,
       strlen (state),
       state,
       task);
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
  return sql_int (0, 0,
                  "SELECT debugs_size FROM tasks_%s WHERE ROWID = %llu;",
                  current_credentials.username,
                  task);
}

/**
 * @brief Increment number of debug messages in the current report of a task.
 *
 * @param[in]  task  Task.
 */
void
inc_task_debugs_size (task_t task)
{
  inc_task_int (task, "debugs_size");
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
  return sql_int (0, 0,
                  "SELECT holes_size FROM tasks_%s WHERE ROWID = %llu;",
                  current_credentials.username,
                  task);
}

/**
 * @brief Increment number of hole messages in the current report of a task.
 *
 * @param[in]  task  Task.
 */
void
inc_task_holes_size (task_t task)
{
  inc_task_int (task, "holes_size");
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
  return sql_int (0, 0,
                  "SELECT infos_size FROM tasks_%s WHERE ROWID = %llu;",
                  current_credentials.username,
                  task);
}

/**
 * @brief Increment number of info messages in the current report of a task.
 *
 * @param[in]  task  Task.
 */
void
inc_task_infos_size (task_t task)
{
  inc_task_int (task, "holes_size");
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
  return sql_int (0, 0,
                  "SELECT logs_size FROM tasks_%s WHERE ROWID = %llu;",
                  current_credentials.username,
                  task);
}

/**
 * @brief Increment number of log messages in the current report of a task.
 *
 * @param[in]  task  Task.
 */
void
inc_task_logs_size (task_t task)
{
  inc_task_int (task, "logs_size");
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
  return sql_int (0, 0,
                  "SELECT notes_size FROM tasks_%s WHERE ROWID = %llu;",
                  current_credentials.username,
                  task);
}

/**
 * @brief Increment number of note messages in the current report of a task.
 *
 * @param[in]  task  Task.
 */
void
inc_task_notes_size (task_t task)
{
  inc_task_int (task, "notes_size");
}


/**
 * @brief Increment report count.
 *
 * @param[in]  task  Task.
 */
void
inc_task_report_count (task_t task)
{
  inc_task_int (task, "report_count");
}

/**
 * @brief Decrement report count.
 *
 * @param[in]  task  Task.
 */
void
dec_task_report_count (task_t task)
{
  dec_task_int (task, "report_count");
}

/**
 * @brief Dummy function.
 */
void
free_tasks ()
{
  /* Empty. */
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
  sql ("INSERT into tasks_%s (name, time, comment) VALUES (%s, %u, %s);",
       current_credentials.username, name, time, comment);
  free (name);
  free (comment);
  return sqlite3_last_insert_rowid (task_db);
}

typedef /*@only@*/ struct dirent * only_dirent_pointer;

/**
 * @brief Dummy function.
 *
 * @return 0.
 */
int
load_tasks ()
{
  return 0;
}

/**
 * @brief Dummy function.
 *
 * @return 0.
 */
int
save_tasks ()
{
  return 0;
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
 * @return 0 on success, -1 when out of memory, -2 if parameter name error,
 *         -3 value error (NULL).
 */
int
set_task_parameter (task_t task, const char* parameter, /*@only@*/ char* value)
{
  tracef ("   set_task_parameter %u %s\n",
          task_id (task),
          parameter ? parameter : "(null)");
  if (value == NULL) return -3;
  if (parameter == NULL)
    {
      free (value);
      return -2;
    }
  if (strncasecmp ("TASK_FILE", parameter, 9) == 0)
    {
      gchar* quote = sql_quote (value, strlen (value));
      sql ("UPDATE tasks_%s SET description = '%s' WHERE ROWID = %llu;",
           current_credentials.username,
           quote,
           task);
      g_free (quote);
    }
  else if (strncasecmp ("NAME", parameter, 4) == 0)
    {
      gchar* quote = sql_quote (value, strlen (value));
      sql ("UPDATE tasks_%s SET name = '%s' WHERE ROWID = %llu;",
           current_credentials.username,
           value,
           task);
      g_free (quote);
    }
  else if (strncasecmp ("COMMENT", parameter, 7) == 0)
    {
      gchar* quote = sql_quote (value, strlen (value));
      sql ("UPDATE tasks_%s SET comment = '%s' WHERE ROWID = %llu;",
           current_credentials.username,
           value,
           task);
      g_free (quote);
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
 * @return 0 on success, -1 if error.
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
 * @param[in]  task  A pointer to the task.
 *
 * @return 0 on success, -1 on error.
 */
int
delete_task (task_t task)
{
  gboolean success;
  const char* id;
  gchar* name;
  GError* error;

  tracef ("   delete task %u\n", task_id (task));

  if (current_credentials.username == NULL) return -1;

  if (task_id_string (task, &id)) return -1;

  // FIX may be atomic problems here

  if (delete_reports (task)) return -1;

  /* Remove the task directory, which contained the reports. */

  name = g_build_filename (PREFIX
                           "/var/lib/openvas/mgr/users/",
                           current_credentials.username,
                           "tasks",
                           id,
                           NULL);
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

  sql ("DELETE FROM tasks_%s WHERE ROWID = %llu;",
       current_credentials.username,
       task);

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
  append_to_task_string (task, "comment", text);
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
  append_to_task_string (task, "name", text);
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
add_task_description_line (task_t task, const char* line,
                           /*@unused@*/ size_t line_length)
{
  append_to_task_string (task, "description", line);
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
  sql ("UPDATE tasks_%s SET current_port = %i, max_port = %i WHERE ROWID = %llu;",
       current_credentials.username,
       current,
       max,
       task);
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
  // FIX
}

/**
 * @brief Find a task given an identifier.
 *
 * @param[in]   uuid  A task identifier.
 * @param[out]  task  Task return.
 *
 * @return TRUE on success, FALSE on error.
 */
gboolean
find_task (const char* uuid, task_t* task)
{
#if 0
  *task = sql_int64 (0, 0,
                     "SELECT ROWID FROM tasks_%s WHERE uuid = %llu;",
                     current_credentials.username,
                     uuid);
  return TRUE;
#else
  int count;
  unsigned long long int result;
  errno = 0;
  result = strtoull (uuid, NULL, 10);
  if (errno) return TRUE;

  count = sql_int (0, 0,
                   "SELECT count(*) FROM tasks_%s where ROWID = %llu",
                   current_credentials.username,
                   result);
  if (count == 1)
    {
      *task = result;
      return FALSE;
    }
  return TRUE;
#endif
}
