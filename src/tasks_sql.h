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

/**
 * @brief Get a particular cell from a SQL query.
 *
 * @param  col          Column.
 * @param  row          Row.
 * @param  sql          Format string for SQL query.
 * @param  args         Arguments for format string.
 * @param  stmt_return  Return from statement.
 *
 * @return 0 success, 1 too few rows, -1 error.
 */
int
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
      return -1;
    }
  while (1)
    {
      ret = sqlite3_step (stmt);
      if (ret == SQLITE_BUSY) continue;
      if (ret == SQLITE_DONE)
        {
          fprintf (stderr, "sqlite3_step finished too soon\n");
          return 1;
        }
      if (ret == SQLITE_ERROR || ret == SQLITE_MISUSE)
        {
          if (ret == SQLITE_ERROR) ret = sqlite3_reset (stmt);
          fprintf (stderr, "sqlite3_step failed: %s\n",
                   sqlite3_errmsg (task_db));
          return -1;
        }
      if (row == 0) break;
      row--;
      tracef ("   sql_x row %i\n", row);
    }

  tracef ("   sql_x end\n");
  return 0;
}

int
sql_int (unsigned int col, unsigned int row, char* sql, ...)
{
  sqlite3_stmt* stmt;
  va_list args;
  va_start (args, sql);
  int sql_x_ret = sql_x (col, row, sql, args, &stmt);
  va_end (args);
  if (sql_x_ret)
    {
      sqlite3_finalize (stmt);
      abort ();
    }
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
  int sql_x_ret = sql_x (col, row, sql, args, &stmt);
  va_end (args);
  if (sql_x_ret)
    {
      sqlite3_finalize (stmt);
      abort ();
    }
  ret2 = sqlite3_column_text (stmt, col);
  /* TODO: For efficiency, save this duplication by adjusting the task
           interface. */
  ret = g_strdup ((char*) ret2);
  sqlite3_finalize (stmt);
  return ret;
}

/**
 * @brief Get a particular cell from a SQL query, as an int64.
 *
 * @param  ret    Return value.
 * @param  sql    Format string for SQL query.
 * @param  args   Arguments for format string.
 *
 * @return 0 success, 1 too few rows, -1 error.
 */
int
sql_int64 (long long int* ret, unsigned int col, unsigned int row, char* sql, ...)
{
  sqlite3_stmt* stmt;
  va_list args;
  va_start (args, sql);
  int sql_x_ret = sql_x (col, row, sql, args, &stmt);
  va_end (args);
  switch (sql_x_ret)
    {
      case  0:
        break;
      case  1:
        sqlite3_finalize (stmt);
        return 1;
        break;
      default:
        assert (0);
        /* Fall through. */
      case -1:
        sqlite3_finalize (stmt);
        return -1;
        break;
    }
  *ret = sqlite3_column_int64 (stmt, col);
  sqlite3_finalize (stmt);
  return 0;
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
 * @brief Initialize the manage library for a process.
 *
 * Simply open the SQL database.
 */
void
init_manage_process ()
{
  if (task_db) return;
  /* Open the database. */
  int ret = sqlite3_open (PREFIX "/var/lib/openvas/mgr/tasks.db", &task_db);
  if (ret)
    {
      fprintf (stderr, "sqlite3_open failed: %s\n",
               sqlite3_errmsg (task_db));
      abort (); // FIX
    }
}

/**
 * @brief Initialize the manage library.
 *
 * Ensure all tasks are in a clean initial state.
 *
 * Beware that calling this function while tasks are running may lead to
 * problems.
 *
 * @return 0 on success, else -1.
 */
int
init_manage ()
{
  const char* tail;
  int ret;
  sqlite3_stmt* stmt;

  init_manage_process ();

  /* Set requested and running tasks to stopped. */

  ret = sqlite3_prepare (task_db,
                         "SELECT name from sqlite_master WHERE type='table';",
                         -1, &stmt, &tail);
  if (ret != SQLITE_OK || stmt == NULL)
    {
      fprintf (stderr, "sqlite3_prepare 1 failed: %s\n",
               sqlite3_errmsg (task_db));
      return -1;
    }
  while (1)
    {
      const unsigned char* name;

      ret = sqlite3_step (stmt);
      if (ret == SQLITE_BUSY) continue;
      if (ret == SQLITE_DONE) break;
      if (ret == SQLITE_ERROR || ret == SQLITE_MISUSE)
        {
          if (ret == SQLITE_ERROR) ret = sqlite3_reset (stmt);
          fprintf (stderr, "sqlite3_step 1 failed: %s\n",
                   sqlite3_errmsg (task_db));
          return -1;
        }
      name = sqlite3_column_text (stmt, 0);
      tracef ("   table %s\n", name);

      if (strlen ((const char*) name) > strlen ("tasks_"))
        {
          task_t index;
          task_iterator_t iterator;

          current_credentials.username = g_strdup ((const char*) name
                                                   + strlen ("tasks_"));
          init_task_iterator (&iterator);
          while (next_task (&iterator, &index))
            {
              switch (task_run_status (index))
                {
                  case TASK_STATUS_DELETE_REQUESTED:
                  case TASK_STATUS_REQUESTED:
                  case TASK_STATUS_RUNNING:
                  case TASK_STATUS_STOP_REQUESTED:
                    set_task_run_status (index, TASK_STATUS_STOPPED);
                    break;
                  default:
                    break;
                }
            }
          cleanup_task_iterator (&iterator);
          g_free (current_credentials.username);
          current_credentials.username = NULL;
        }
    }
  switch (sqlite3_finalize (stmt))
    {
      case SQLITE_OK: return 0;
      default: return -1;
    }
}

/**
 * @brief Cleanup the manage library.
 */
void
cleanup_manage_process ()
{
  if (task_db)
    {
      if (current_server_task)
        {
          if (task_run_status (current_server_task) == TASK_STATUS_REQUESTED)
            set_task_run_status (current_server_task, TASK_STATUS_STOPPED);
        }
      sqlite3_close (task_db);
      task_db = NULL;
    }
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
    {
      sql ("CREATE TABLE IF NOT EXISTS tasks_%s (uuid, name, time, comment, description, run_status, start_time, end_time, report_count, attack_state, current_port, max_port, debugs_size, holes_size, infos_size, logs_size, notes_size)",
           credentials->username);
      return openvas_authenticate (credentials->username,
                                   credentials->password);
    }
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
  return (unsigned int) sql_int (0, 0,
                                 "SELECT count(*) FROM tasks_%s;",
                                 current_credentials.username);
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
 * @brief Return the UUID of a task.
 *
 * @param[in]   task  Task.
 * @param[out]  id    Pointer to a newly allocated string.
 *
 * @return 0.
 */
int
task_uuid (task_t task, char ** id)
{
  *id = sql_string (0, 0,
                    "SELECT uuid FROM tasks_%s WHERE ROWID = %llu;",
                    current_credentials.username,
                    task);
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
 * @return A pointer to the new task or the NULL task on error (in which
 *         case the caller must free name and comment).
 */
task_t
make_task (char* name, unsigned int time, char* comment)
{
  task_t task;
  char* uuid = make_task_uuid ();
  if (uuid == NULL) return (task_t) NULL;
  // TODO: Escape name and comment.
  sql ("INSERT into tasks_%s (uuid, name, time, comment)"
       " VALUES ('%s', %s, %u, %s);",
       current_credentials.username, uuid, name, time, comment);
  task = sqlite3_last_insert_rowid (task_db);
  set_task_run_status (task, TASK_STATUS_NEW);
  free (uuid);
  free (name);
  free (comment);
  return task;
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
 * @param[in]  parameter  The name of the parameter (in any case): RCFILE,
 *                        NAME or COMMENT.
 * @param[in]  value      The value of the parameter, in base64 if parameter
 *                        is "RCFILE".
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
  if (strncasecmp ("RCFILE", parameter, 6) == 0)
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
 * @return 0 if deleted, 1 if delete requested, -1 if error.
 */
int
request_delete_task (task_t* task_pointer)
{
  task_t task = *task_pointer;

  tracef ("   request delete task %u\n", task_id (task));

  if (current_credentials.username == NULL) return -1;

  switch (stop_task (task))
    {
      case 0:    /* Stopped. */
        delete_task (task);
        return 0;
      case 1:    /* Stop requested. */
        set_task_run_status (task, TASK_STATUS_DELETE_REQUESTED);
        return 1;
      default:   /* Programming error. */
        assert (0);
      case -1:   /* Error. */
        return -1;
        break;
    }

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
  char* tsk_uuid;
  gchar* name;
  GError* error;

  tracef ("   delete task %u\n", task_id (task));

  if (current_credentials.username == NULL) return -1;

  if (task_uuid (task, &tsk_uuid)) return -1;

  // FIX may be atomic problems here

  if (delete_reports (task)) return -1;

  /* Remove the task directory, which contained the reports. */

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
 * @brief Append text to the name associated with a task.
 *
 * @param[in]  task    A pointer to the task.
 * @param[in]  text    The text to append.
 * @param[in]  length  Length of the text.
 *
 * @return 0 on success, -1 if out of memory.
 */
int
append_to_task_name (task_t task, const char* text,
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
 * @param[out]  task  Task return, 0 if succesfully failed to find task.
 *
 * @return FALSE on success (including if failed to find task), TRUE on error.
 */
gboolean
find_task (const char* uuid, task_t* task)
{
  switch (sql_int64 (task, 0, 0,
                     "SELECT ROWID FROM tasks_%s WHERE uuid = '%s';",
                     current_credentials.username,
                     uuid))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *task = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        return TRUE;
        break;
    }

  return FALSE;
}
