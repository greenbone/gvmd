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

#include <openvas/openvas_logging.h>


/* Types. */

typedef long long int config_t;


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
  while ((start = strchr (start, '\''))) start++, count++;

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

  /* Prepare statement. */

  while (1)
    {
      ret = sqlite3_prepare (task_db, (char*) formatted, -1, &stmt, &tail);
      if (ret == SQLITE_BUSY) continue;
      g_free (formatted);
      if (ret == SQLITE_OK)
        {
          if (stmt == NULL)
            {
              g_warning ("%s: sqlite3_prepare failed with NULL stmt: %s\n",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              abort ();
            }
          break;
        }
      g_warning ("%s: sqlite3_prepare failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      abort ();
    }

  /* Run statement. */

  while (1)
    {
      ret = sqlite3_step (stmt);
      if (ret == SQLITE_BUSY) continue;
      if (ret == SQLITE_DONE) break;
      if (ret == SQLITE_ERROR || ret == SQLITE_MISUSE)
        {
          if (ret == SQLITE_ERROR) ret = sqlite3_reset (stmt);
          g_warning ("%s: sqlite3_step failed: %s\n",
                     __FUNCTION__,
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

  /* Prepare statement. */

  while (1)
    {
      ret = sqlite3_prepare (task_db, (char*) formatted, -1, &stmt, &tail);
      if (ret == SQLITE_BUSY) continue;
      g_free (formatted);
      *stmt_return = stmt;
      if (ret == SQLITE_OK)
        {
          if (stmt == NULL)
            {
              g_warning ("%s: sqlite3_prepare failed with NULL stmt: %s\n",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              return -1;
            }
          break;
        }
      g_warning ("%s: sqlite3_prepare failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      return -1;
    }

  /* Run statement. */

  while (1)
    {
      ret = sqlite3_step (stmt);
      if (ret == SQLITE_BUSY) continue;
      if (ret == SQLITE_DONE)
        {
          g_warning ("%s: sqlite3_step finished too soon\n",
                     __FUNCTION__);
          return 1;
        }
      if (ret == SQLITE_ERROR || ret == SQLITE_MISUSE)
        {
          if (ret == SQLITE_ERROR) ret = sqlite3_reset (stmt);
          g_warning ("%s: sqlite3_step failed: %s\n",
                     __FUNCTION__,
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
      return NULL;
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
                         "SELECT %s FROM tasks WHERE ROWID = %llu;",
                         field,
                         task);
  sql ("UPDATE tasks SET %s = %i WHERE ROWID = %llu;",
       field,
       current + 1,
       task);
}

void
dec_task_int (task_t task, const char* field)
{
  int current = sql_int (0, 0,
                         "SELECT %s FROM tasks WHERE ROWID = %llu;",
                         field,
                         task);
  sql ("UPDATE tasks SET %s = %i WHERE ROWID = %llu;",
       field,
       current - 1,
       task);
}

void
append_to_task_string (task_t task, const char* field, const char* value)
{
  char* current;
  current = sql_string (0, 0,
                        "SELECT %s FROM tasks WHERE ROWID = %llu;",
                        field,
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
  sql ("UPDATE tasks SET %s = '%s' WHERE ROWID = %llu;",
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
  if (current_credentials.username)
    formatted = g_strdup_printf ("SELECT ROWID FROM tasks WHERE owner ="
                                 " (SELECT ROWID FROM users WHERE name = '%s');",
                                  current_credentials.username);
  else
    formatted = g_strdup_printf ("SELECT ROWID FROM tasks;");
  tracef ("   sql (iterator): %s\n", formatted);
  while (1)
    {
      ret = sqlite3_prepare (task_db, (char*) formatted, -1, &stmt, &tail);
      if (ret == SQLITE_BUSY) continue;
      g_free (formatted);
      iterator->stmt = stmt;
      if (ret == SQLITE_OK)
        {
          if (stmt == NULL)
            {
              g_warning ("%s: sqlite3_prepare failed with NULL stmt: %s\n",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              abort ();
            }
          break;
        }
      g_warning ("%s: sqlite3_prepare failed: %s\n",
                 __FUNCTION__,
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

  if (iterator->done) return FALSE;

  while ((ret = sqlite3_step (iterator->stmt)) == SQLITE_BUSY);
  if (ret == SQLITE_DONE)
    {
      iterator->done = TRUE;
      return FALSE;
    }
  if (ret == SQLITE_ERROR || ret == SQLITE_MISUSE)
    {
      if (ret == SQLITE_ERROR) ret = sqlite3_reset (iterator->stmt);
      g_warning ("%s: sqlite3_step failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      abort ();
    }
  *task = sqlite3_column_int64 (iterator->stmt, 0);
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
  gchar *mgr_dir;
  int ret;

  if (task_db) return;

  /* Ensure the mgr directory exists. */
  mgr_dir = g_build_filename (OPENVAS_STATE_DIR "/mgr/", NULL);
  ret = g_mkdir_with_parents (mgr_dir, 0755 /* "rwxr-xr-x" */);
  g_free (mgr_dir);
  if (ret == -1)
    {
      g_warning ("%s: failed to create mgr directory: %s\n",
                 __FUNCTION__,
                 strerror (errno));
      abort (); // FIX
    }

  /* Open the database. */
  if (sqlite3_open (OPENVAS_STATE_DIR "/mgr/tasks.db", &task_db))
    {
      g_warning ("%s: sqlite3_open failed: %s\n",
                 __FUNCTION__,
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
init_manage (GSList *log_config)
{
  task_t index;
  task_iterator_t iterator;

  g_log_set_handler (G_LOG_DOMAIN,
                     ALL_LOG_LEVELS,
                     (GLogFunc) openvas_log_func,
                     log_config);

  init_manage_process ();

  /* Ensure the tables exist. */

  sql ("CREATE TABLE IF NOT EXISTS users   (name, password);");
  sql ("CREATE TABLE IF NOT EXISTS nvt_selectors (name, exclude INTEGER, type INTEGER, family_or_nvt);");
  sql ("CREATE TABLE IF NOT EXISTS configs (name UNIQUE, nvt_selector);");
  sql ("CREATE TABLE IF NOT EXISTS config_preferences (config INTEGER, type, name, value);");
  sql ("CREATE TABLE IF NOT EXISTS tasks   (uuid, name, time, comment, description, owner, run_status, start_time, end_time);");
  sql ("CREATE TABLE IF NOT EXISTS results (task INTEGER, subnet, host, port, nvt, type, description)");
  sql ("CREATE TABLE IF NOT EXISTS reports (uuid, task INTEGER, date INTEGER, start_time, end_time, nbefile, comment);");
  sql ("CREATE TABLE IF NOT EXISTS report_hosts (report INTEGER, host, start_time, end_time, attack_state, current_port, max_port);");
  sql ("CREATE TABLE IF NOT EXISTS report_results (report INTEGER, result INTEGER);");
  sql ("CREATE TABLE IF NOT EXISTS targets (name, hosts);");

  /* Always create a single user, for now. */

  if (sql_int (0, 0, "SELECT count(*) FROM users;") == 0)
    sql ("INSERT into users (name, password) VALUES ('om', '');");

  /* Setup predefined selectors and configs. */

  if (sql_int (0, 0, "SELECT count(*) FROM nvt_selectors;") == 0
      && sql_int (0, 0, "SELECT count(*) FROM configs;") == 0)
    {
      sql ("INSERT into nvt_selectors (name, exclude, type, family_or_nvt)"
           " VALUES ('All', 0, 0, NULL);");
      sql ("INSERT into configs (name, nvt_selector)"
           " VALUES ('Full', 'All');");
      // FIX setup full preferences
      //     create_config ("full", OPENVAS_STATE_DIR "/mgr/openvasrc-full");?
      //         depends on scanner?
    }

  /* Set requested and running tasks to stopped. */

  assert (current_credentials.username == NULL);
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

  sqlite3_close (task_db);
  task_db = NULL;
  return 0;
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
                                 "SELECT count(*) FROM tasks WHERE owner ="
                                 " (SELECT ROWID FROM users WHERE name = '%s');",
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
                    "SELECT uuid FROM tasks WHERE ROWID = %llu;",
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
                     "SELECT name FROM tasks WHERE ROWID = %llu;",
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
                     "SELECT comment FROM tasks WHERE ROWID = %llu;",
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
                     "SELECT description FROM tasks WHERE ROWID = %llu;",
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
  sql ("UPDATE tasks SET description = '%s' WHERE ROWID = %llu;",
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
                                 "SELECT run_status FROM tasks WHERE ROWID = %llu;",
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
  sql ("UPDATE tasks SET run_status = %u WHERE ROWID = %llu;",
       status,
       task);
}

/**
 * @brief Return the report currently being produced.
 *
 * @param[in]  task  Task.
 *
 * @return Current report of task if task is active, else (report_t) NULL.
 */
report_t
task_running_report (task_t task)
{
  task_status_t run_status = task_run_status (task);
  if (run_status == TASK_STATUS_REQUESTED
      || run_status == TASK_STATUS_RUNNING)
    {
      return (unsigned int) sql_int (0, 0,
                                     "SELECT ROWID FROM reports"
                                     " WHERE task = %llu AND end_time IS NULL;",
                                     task);
    }
  return (report_t) NULL;
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
                     "SELECT start_time FROM tasks WHERE ROWID = %llu;",
                     task);
}

/**
 * @brief Set the start time of a task.
 *
 * @param[in]  task  Task.
 * @param[in]  time  New time.  Freed before return.
 */
void
set_task_start_time (task_t task, char* time)
{
  sql ("UPDATE tasks SET start_time = '%.*s' WHERE ROWID = %llu;",
       strlen (time),
       time,
       task);
  free (time);
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
                     "SELECT end_time FROM tasks WHERE ROWID = %llu;",
                     task);
}

/**
 * @brief Get the report ID from the most recently completed invocation of task.
 *
 * @param[in]  task  The task.
 *
 * @return The UUID of the task as a newly allocated string.
 */
gchar*
task_last_report_id (task_t task)
{
  return sql_string (0, 0,
                     "SELECT uuid FROM reports WHERE task = %llu"
                     " ORDER BY date DESC LIMIT 1;",
                     task);
}

/**
 * @brief Get report ID from second most recently completed invocation of task.
 *
 * @param[in]  task  The task.
 *
 * @return The UUID of the task as a newly allocated string.
 */
gchar*
task_second_last_report_id (task_t task)
{
  return sql_string (0, 1,
                     "SELECT uuid FROM reports WHERE task = %llu"
                     " ORDER BY date DESC LIMIT 2;",
                     task);
}


/* Iterators. */

/**
 * @brief Cleanup an iterator.
 *
 * @param[in]  iterator  Iterator.
 */
void
cleanup_iterator (iterator_t* iterator)
{
  sqlite3_finalize (iterator->stmt);
}

/**
 * @brief Increment an iterator.
 *
 * @param[in]   iterator  Task iterator.
 *
 * @return TRUE if there was a next item, else FALSE.
 */
gboolean
next (iterator_t* iterator)
{
  int ret;

  if (iterator->done) return FALSE;

  while ((ret = sqlite3_step (iterator->stmt)) == SQLITE_BUSY);
  if (ret == SQLITE_DONE)
    {
      iterator->done = TRUE;
      return FALSE;
    }
  if (ret == SQLITE_ERROR || ret == SQLITE_MISUSE)
    {
      if (ret == SQLITE_ERROR) ret = sqlite3_reset (iterator->stmt);
      g_warning ("%s: sqlite3_step failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      abort ();
    }
  return TRUE;
}


/* Results. */

/**
 * @brief Make a result.
 *
 * @param[in]  task         The task associated with the result.
 * @param[in]  subnet       Subnet.
 * @param[in]  subnet       Host.
 * @param[in]  port         The port the result refers to.
 * @param[in]  nvt          The OID of the NVT that produced the result.
 * @param[in]  type         Type of result.  "Security Hole", etc.
 * @param[in]  description  Description of the result.
 *
 * @return A result descriptor for the new result.
 */
result_t
make_result (task_t task, const char* subnet, const char* host,
             const char* port, const char* nvt, const char* type,
             const char* description)
{
  result_t result;
  // TODO: Escape description.
  sql ("INSERT into results (task, subnet, host, port, nvt, type, description)"
       " VALUES (%llu, '%s', '%s', '%s', '%s', '%s', '%s');",
       task, subnet, host, port, nvt, type, description);
  result = sqlite3_last_insert_rowid (task_db);
  return result;
}


/* Reports. */

/**
 * @brief Make a report.
 *
 * @param[in]  task  The task associated with the report.
 * @param[in]  uuid  The UUID of the report.
 *
 * @return A report descriptor for the new report.
 */
report_t
make_report (task_t task, const char* uuid)
{
  report_t report;
  sql ("INSERT into reports (uuid, task, date, nbefile, comment)"
       " VALUES ('%s', %llu, %i, '', '');",
       uuid, task, time (NULL));
  report = sqlite3_last_insert_rowid (task_db);
  return report;
}

/**
 * @brief Create the current report for a task.
 *
 * @param[in]  task   The task.
 *
 * @return 0 success, -1 current_report is already set, -2 failed to generate ID.
 */
static int
create_report (task_t task)
{
  char* report_id;

  assert (current_report == (report_t) NULL);
  if (current_report) return -1;

  /* Generate report UUID. */

  report_id = make_report_uuid ();
  if (report_id == NULL) return -2;

  /* Create the report. */

  current_report = make_report (task, report_id);

  return 0;
}

/**
 * @brief Return the UUID of a report.
 *
 * @param[in]  report  Report.
 *
 * @return Report UUID.
 */
char*
report_uuid (report_t report)
{
  return sql_string (0, 0,
                     "SELECT uuid FROM reports WHERE ROWID = %llu;",
                     report);
}

/**
 * @brief Get the number of holes in a report.
 *
 * @param[in]   report  Report.
 * @param[in]   host    The host whose holes to count.  NULL for all hosts.
 * @param[out]  holes   On success, number of holes.
 *
 * @return 0.
 */
int
report_holes (report_t report, const char* host, int* holes)
{
  if (host)
    *holes = sql_int (0, 0,
                      "SELECT count(*) FROM results, report_results"
                      " WHERE results.type = 'Security Hole'"
                      " AND results.ROWID = report_results.result"
                      " AND report_results.report = %llu"
                      " AND results.host = '%s';",
                      report);
  else
    *holes = sql_int (0, 0,
                      "SELECT count(*) FROM results, report_results"
                      " WHERE results.type = 'Security Hole'"
                      " AND results.ROWID = report_results.result"
                      " AND report_results.report = %llu;",
                      report);
  return 0;
}

/**
 * @brief Get the number of notes in a report.
 *
 * @param[in]   report  Report.
 * @param[in]   host    The host whose notes to count.  NULL for all hosts.
 * @param[out]  notes   On success, number of notes.
 *
 * @return 0.
 */
int
report_notes (report_t report, const char* host, int* notes)
{
  if (host)
    *notes = sql_int (0, 0,
                      "SELECT count(*) FROM results, report_results"
                      " WHERE results.type = 'Security Note'"
                      " AND results.ROWID = report_results.result"
                      " AND report_results.report = %llu"
                      " AND results.host = '%s';",
                      report);
  else
    *notes = sql_int (0, 0,
                      "SELECT count(*) FROM results, report_results"
                      " WHERE results.type = 'Security Note'"
                      " AND results.ROWID = report_results.result"
                      " AND report_results.report = %llu;",
                      report);
  return 0;
}

/**
 * @brief Get the number of warnings in a report.
 *
 * @param[in]   report    Report.
 * @param[in]   host      The host whose warnings to count.  NULL for all hosts.
 * @param[out]  warnings  On success, number of warnings.
 *
 * @return 0.
 */
int
report_warnings (report_t report, const char* host, int* warnings)
{
  if (host)
    *warnings = sql_int (0, 0,
                         "SELECT count(*) FROM results, report_results"
                         " WHERE results.type = 'Security Warning'"
                         " AND results.ROWID = report_results.result"
                         " AND report_results.report = %llu"
                         " AND results.host = '%s';",
                         report);
  else
    *warnings = sql_int (0, 0,
                         "SELECT count(*) FROM results, report_results"
                         " WHERE results.type = 'Security Warning'"
                         " AND results.ROWID = report_results.result"
                         " AND report_results.report = %llu;",
                         report);
  return 0;
}

/**
 * @brief Add a result to a report.
 *
 * @param[in]  report  The report.
 * @param[in]  result  The result.
 */
void
report_add_result (report_t report, result_t result)
{
  sql ("INSERT into report_results (report, result)"
       " VALUES (%llu, %llu);",
       report, result);
}

/**
 * @brief Initialise a report iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  task      Task whose reports the iterator loops over.
 *                       All tasks if NULL.
 */
void
init_report_iterator (iterator_t* iterator, task_t task)
{
  int ret;
  const char* tail;
  gchar* sql;
  sqlite3_stmt* stmt;

  iterator->done = FALSE;
  if (task)
    sql = g_strdup_printf ("SELECT ROWID FROM reports WHERE task = %llu;",
                           task);
  else
    sql = g_strdup_printf ("SELECT ROWID FROM reports;");
  tracef ("   sql (report iterator): %s\n", sql);
  while (1)
    {
      ret = sqlite3_prepare (task_db, (char*) sql, -1, &stmt, &tail);
      if (ret == SQLITE_BUSY) continue;
      g_free (sql);
      iterator->stmt = stmt;
      if (ret == SQLITE_OK)
        {
          if (stmt == NULL)
            {
              g_warning ("%s: sqlite3_prepare failed with NULL stmt: %s\n",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              abort ();
            }
          break;
        }
      g_warning ("%s: sqlite3_prepare failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      abort ();
    }
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
next_report (iterator_t* iterator, report_t* report)
{
  int ret;

  if (iterator->done) return FALSE;

  while ((ret = sqlite3_step (iterator->stmt)) == SQLITE_BUSY);
  if (ret == SQLITE_DONE)
    {
      iterator->done = TRUE;
      return FALSE;
    }
  if (ret == SQLITE_ERROR || ret == SQLITE_MISUSE)
    {
      if (ret == SQLITE_ERROR) ret = sqlite3_reset (iterator->stmt);
      g_warning ("%s: sqlite3_step failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      abort ();
    }
  *report = sqlite3_column_int64 (iterator->stmt, 0);
  return TRUE;
}

/**
 * @brief Initialise a result iterator.
 *
 * The results are ordered by host, then port, then type (severity).
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  report    Report whose results the iterator loops over.
 *                       All results if NULL.
 * @param[in]  host      Host whose results the iterator loops over.
 *                       All results if NULL.  Only considered if report given.
 */
void
init_result_iterator (iterator_t* iterator, report_t report, const char* host)
{
  int ret;
  const char* tail;
  gchar* sql;
  sqlite3_stmt* stmt;

  iterator->done = FALSE;
  if (report)
    {
      if (host)
        sql = g_strdup_printf ("SELECT subnet, host, port, nvt, type, description"
                               " FROM results, reports"
                               " WHERE reports.task = results.task"
                               " AND reports.ROWID = %llu"
                               " AND results.host = '%s'"
                               " ORDER BY port, type;",
                               report,
                               host);
      else
        sql = g_strdup_printf ("SELECT subnet, host, port, nvt, type, description"
                               " FROM results, reports"
                               " WHERE reports.task = results.task"
                               " AND reports.ROWID = %llu"
                               " ORDER BY host, port, type;",
                               report);
    }
  else
    sql = g_strdup_printf ("SELECT * FROM results;");
  tracef ("   sql (result iterator): %s\n", sql);
  while (1)
    {
      ret = sqlite3_prepare (task_db, (char*) sql, -1, &stmt, &tail);
      if (ret == SQLITE_BUSY) continue;
      g_free (sql);
      iterator->stmt = stmt;
      if (ret == SQLITE_OK)
        {
          if (stmt == NULL)
            {
              g_warning ("%s: sqlite3_prepare failed with NULL stmt: %s\n",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              abort ();
            }
          break;
        }
      g_warning ("%s: sqlite3_prepare failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      abort ();
    }
}

#if 0
/**
 * @brief Get the subnet from a result iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The subnet of the result as a newly allocated string, or NULL on
 *         error.
 */
char*
result_iterator_subnet (iterator_t* iterator)
{
  const char *ret;
  if (iterator->done) return NULL;
  ret = (const char*) sqlite3_column_text (iterator->stmt, 1);
  return ret ? g_strdup (ret) : NULL;
}
#endif

#if 0
/**
 * @brief Get the NAME from a result iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The NAME of the result.  Caller must use only before calling
 *         cleanup_iterator.
 */
#endif

#define DEF_ACCESS(name, col) \
const char* \
result_iterator_ ## name (iterator_t* iterator) \
{ \
  const char *ret; \
  if (iterator->done) return NULL; \
  ret = (const char*) sqlite3_column_text (iterator->stmt, col); \
  return ret; \
}

DEF_ACCESS (subnet, 0);
DEF_ACCESS (host, 1);
DEF_ACCESS (port, 2);
DEF_ACCESS (nvt, 3);
DEF_ACCESS (type, 4);
DEF_ACCESS (descr, 5);

#undef DEF_ACCESS

/**
 * @brief Initialise a host iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  report    Report whose hosts the iterator loops over.
 *                       All hosts if NULL.
 */
void
init_host_iterator (iterator_t* iterator, report_t report)
{
  int ret;
  const char* tail;
  gchar* sql;
  sqlite3_stmt* stmt;

  iterator->done = FALSE;
  if (report)
    sql = g_strdup_printf ("SELECT * FROM report_hosts WHERE report = %llu;",
                           report);
  else
    sql = g_strdup_printf ("SELECT * FROM report_hosts;");
  tracef ("   sql (host iterator): %s\n", sql);
  while (1)
    {
      ret = sqlite3_prepare (task_db, (char*) sql, -1, &stmt, &tail);
      if (ret == SQLITE_BUSY) continue;
      g_free (sql);
      iterator->stmt = stmt;
      if (ret == SQLITE_OK)
        {
          if (stmt == NULL)
            {
              g_warning ("%s: sqlite3_prepare failed with NULL stmt: %s\n",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              abort ();
            }
          break;
        }
      g_warning ("%s: sqlite3_prepare failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      abort ();
    }
}

#if 0
/**
 * @brief Get the NAME from a host iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The NAME of the host.  Caller must use only before calling
 *         cleanup_iterator.
 */
#endif

#define DEF_ACCESS(name, col) \
const char* \
name (iterator_t* iterator) \
{ \
  const char *ret; \
  if (iterator->done) return NULL; \
  ret = (const char*) sqlite3_column_text (iterator->stmt, col); \
  return ret; \
}

DEF_ACCESS (host_iterator_host, 1);
DEF_ACCESS (host_iterator_start_time, 2);
DEF_ACCESS (host_iterator_end_time, 3);
DEF_ACCESS (host_iterator_attack_state, 4);

int
host_iterator_current_port (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (int) sqlite3_column_int (iterator->stmt, 5);
  return ret;
}

int
host_iterator_max_port (iterator_t* iterator)
{
  int ret;
  if (iterator->done) return -1;
  ret = (int) sqlite3_column_int (iterator->stmt, 6);
  return ret;
}

/**
 * @brief Set the end time of a task.
 *
 * @param[in]  task  Task.
 * @param[in]  time  New time.  Freed before return.
 */
void
set_task_end_time (task_t task, char* time)
{
  sql ("UPDATE tasks SET end_time = '%.*s' WHERE ROWID = %llu;",
       strlen (time),
       time,
       task);
  free (time);
}

/**
 * @brief Get the start time of a scan.
 *
 * @param[in]  report  The report associated with the scan.
 *
 * @return Start time of scan, in a newly allocated string.
 */
char*
scan_start_time (report_t report)
{
  return sql_string (0, 0,
                     "SELECT start_time FROM reports WHERE ROWID = %llu;",
                     report);
}

/**
 * @brief Set the start time of a scan.
 *
 * @param[in]  report     The report associated with the scan.
 * @param[in]  timestamp  Start time.
 */
void
set_scan_start_time (report_t report, const char* timestamp)
{
  sql ("UPDATE reports SET start_time = '%s' WHERE ROWID = %llu;",
       timestamp, report);
}

/**
 * @brief Get the end time of a scan.
 *
 * @param[in]  report  The report associated with the scan.
 *
 * @return End time of scan, in a newly allocated string.
 */
char*
scan_end_time (report_t report)
{
  return sql_string (0, 0,
                     "SELECT end_time FROM reports WHERE ROWID = %llu;",
                     report);
}

/**
 * @brief Set the end time of a scan.
 *
 * @param[in]  report     The report associated with the scan.
 * @param[in]  timestamp  End time.
 */
void
set_scan_end_time (report_t report, const char* timestamp)
{
  sql ("UPDATE reports SET end_time = '%s' WHERE ROWID = %llu;",
       timestamp, report);
}

/**
 * @brief Set the end time of a scanned host.
 *
 * @param[in]  report     Report associated with the scan.
 * @param[in]  host       Host.
 * @param[in]  timestamp  End time.
 */
void
set_scan_host_end_time (report_t report, const char* host,
                        const char* timestamp)
{
  if (sql_int (0, 0,
               "SELECT COUNT(*) FROM report_hosts"
               " WHERE report = %llu AND host = '%s';",
               report, host))
    sql ("UPDATE report_hosts SET end_time = '%s'"
         " WHERE report = %llu AND host = '%s';",
         timestamp, report, host);
  else
    sql ("INSERT into report_hosts (report, host, end_time)"
         " VALUES (%llu, '%s', '%s');",
         report, host, timestamp);
}

/**
 * @brief Set the start time of a scanned host.
 *
 * @param[in]  report     Report associated with the scan.
 * @param[in]  host       Host.
 * @param[in]  timestamp  Start time.
 */
void
set_scan_host_start_time (report_t report, const char* host,
                          const char* timestamp)
{
  if (sql_int (0, 0,
               "SELECT COUNT(*) FROM report_hosts"
               " WHERE report = %llu AND host = '%s';",
               report, host))
    sql ("UPDATE report_hosts SET start_time = '%s'"
         " WHERE report = %llu AND host = '%s';",
         timestamp, report, host);
  else
    sql ("INSERT into report_hosts (report, host, start_time)"
         " VALUES (%llu, '%s', '%s');",
         report, host, timestamp);
}

/**
 * @brief Get the timestamp of a report.
 *
 * @param[in]   report_id    UUID of report.
 * @param[out]  timestamp    Timestamp on success.  Caller must free.
 *
 * @return 0 on success, -1 on error.
 */
int
report_timestamp (const char* report_id, gchar** timestamp)
{
  const char* stamp;
  time_t time = sql_int (0, 0,
                         "SELECT date FROM reports where uuid = '%s';",
                         report_id);
  stamp = ctime (&time);
  if (stamp == NULL) return -1;
  /* Allocate a copy, clearing the newline from the end of the timestamp. */
  *timestamp = g_strndup (stamp, strlen (stamp) - 1);
  return 0;
}

#define REPORT_COUNT(var, name) \
  *var = sql_int (0, 0, \
                  "SELECT count(*) FROM results, report_results" \
                  " WHERE results.type = '" name "'" \
                  " AND results.ROWID = report_results.result" \
                  " AND report_results.report" \
                  " = (SELECT ROWID FROM reports WHERE uuid = '%s');", \
                  report_id)

/**
 * @brief Get the message counts for a report.
 *
 * @param[in]   report_id    ID of report.
 * @param[out]  debugs       Number of debug messages.
 * @param[out]  holes        Number of hole messages.
 * @param[out]  infos        Number of info messages.
 * @param[out]  logs         Number of log messages.
 * @param[out]  warnings     Number of warning messages.
 *
 * @return 0 on success, -1 on error.
 */
int
report_counts (const char* report_id, int* debugs, int* holes, int* infos,
               int* logs, int* warnings)
{
  REPORT_COUNT (debugs,   "Debug Message");
  REPORT_COUNT (holes,    "Security Hole");
  REPORT_COUNT (infos,    "Security Warning");
  REPORT_COUNT (logs,     "Log Message");
  REPORT_COUNT (warnings, "Security Note");
  return 0;
}

#undef REPORT_COUNT

/**
 * @brief Delete a report.
 *
 * @param[in]  report_id  ID of report.
 *
 * @return 0 success.
 */
int
delete_report (report_t report)
{
  sql ("DELETE FROM report_hosts WHERE report = %llu;", report);
  sql ("DELETE FROM report_results WHERE report = %llu;", report);
  sql ("DELETE FROM reports WHERE ROWID = %llu;", report);
  return 0;
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
set_report_parameter (report_t report, const char* parameter, char* value)
{
  tracef ("   set_report_parameter %llu %s\n", report, parameter);
  if (strncasecmp ("COMMENT", parameter, 7) == 0)
    {
      gchar* quote = sql_quote (value, strlen (value));
      sql ("UPDATE reports SET comment = '%s' WHERE ROWID = %llu;",
           value,
           report);
      g_free (quote);
    }
  else
    return -2;
  return 0;
}


/* FIX More task stuff. */

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
                                 "SELECT count(*) FROM reports WHERE task = %llu;",
                                 task);
}

/**
 * @brief Set the attack state of a task.
 *
 * @param[in]  task   Task.
 * @param[in]  state  New state.
 */
void
set_scan_attack_state (report_t report, const char* host, const char* state)
{
  sql ("UPDATE report_hosts SET attack_state = '%s'"
       " WHERE host = '%s' AND report = %llu;",
       state,
       state,
       host,
       report);
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
                  "SELECT count(*) FROM results"
                  " WHERE task = %llu AND results.type = 'Debug Message';",
                  task);
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
                  "SELECT count(*) FROM results"
                  " WHERE task = %llu AND results.type = 'Security Hole';",
                  task);
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
                  "SELECT count(*) FROM results"
                  " WHERE task = %llu AND results.type = 'Security Warning';",
                  task);
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
                  "SELECT count(*) FROM results"
                  " WHERE task = %llu AND results.type = 'Log Message';",
                  task);
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
                  "SELECT count(*) FROM results"
                  " WHERE task = %llu AND results.type = 'Security Note';",
                  task);
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
  sql ("INSERT into tasks (owner, uuid, name, time, comment)"
       " VALUES ((SELECT ROWID FROM users WHERE name = '%s'),"
       "         '%s', %s, %u, %s);",
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
      gsize out_len;
      guchar* out;
      gchar* quote;
      out = g_base64_decode (value, &out_len);
      quote = sql_quote ((gchar*) out, out_len);
      g_free (out);
      sql ("UPDATE tasks SET description = '%s' WHERE ROWID = %llu;",
           quote,
           task);
      g_free (quote);
    }
  else if (strncasecmp ("NAME", parameter, 4) == 0)
    {
      gchar* quote = sql_quote (value, strlen (value));
      sql ("UPDATE tasks SET name = '%s' WHERE ROWID = %llu;",
           value,
           task);
      g_free (quote);
    }
  else if (strncasecmp ("COMMENT", parameter, 7) == 0)
    {
      gchar* quote = sql_quote (value, strlen (value));
      sql ("UPDATE tasks SET comment = '%s' WHERE ROWID = %llu;",
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
  char* tsk_uuid;

  tracef ("   delete task %u\n", task_id (task));

  if (current_credentials.username == NULL) return -1;

  if (task_uuid (task, &tsk_uuid)) return -1;

  // FIX may be atomic problems here

  if (delete_reports (task)) return -1;

  sql ("DELETE FROM results WHERE task = %llu;", task);
  sql ("DELETE FROM tasks WHERE ROWID = %llu;", task);

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
 * @brief Set the ports for a particular host in a scan.
 *
 * @param[in]  report   Report associated with scan.
 * @param[in]  host     Host.
 * @param[in]  current  New value for port currently being scanned.
 * @param[in]  max      New value for last port to be scanned.
 */
void
set_scan_ports (report_t report, const char* host, unsigned int current,
                unsigned int max)
{
  sql ("UPDATE report_hosts SET current_port = %i, max_port = %i"
       " WHERE host = '%s' AND report = %llu;",
       current, max, host, report);
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
                     "SELECT ROWID FROM tasks WHERE uuid = '%s';",
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

/**
 * @brief Find a report given an identifier.
 *
 * @param[in]   uuid    A report identifier.
 * @param[out]  report  Report return, 0 if succesfully failed to find task.
 *
 * @return FALSE on success (including if failed to find report), TRUE on error.
 */
gboolean
find_report (const char* uuid, report_t* report)
{
  switch (sql_int64 (report, 0, 0,
                     "SELECT ROWID FROM reports WHERE uuid = '%s';",
                     uuid))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *report = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        return TRUE;
        break;
    }

  return FALSE;
}

/**
 * @brief Reset all running information for a task.
 *
 * @param[in]  task  Task.
 */
void
reset_task (task_t task)
{
  sql ("UPDATE tasks SET"
       " start_time = '',"
       " end_time = ''"
       " WHERE ROWID = %llu;",
       task);
}


/* Targets. */

/**
 * @brief Create a target.
 *
 * @param[in]  name   Name of target.
 * @param[in]  hosts  Host list of target.
 *
 * @return 0 success, -1 error.
 */
int
create_target (const char* name, const char* hosts)
{
  gchar* quoted_name = sql_quote (name, strlen (name));
  gchar* quoted_hosts;

  if (sql_int (0, 0, "SELECT COUNT(*) FROM targets WHERE name = '%s';",
               quoted_name))
    {
      g_free (quoted_name);
      return -1;
    }

  quoted_hosts = sql_quote (hosts, strlen (hosts));
  sql ("INSERT INTO targets (name, hosts)"
       " VALUES ('%s', '%s');",
       quoted_name, quoted_hosts);
  g_free (quoted_name);
  g_free (quoted_hosts);
  return 0;
}

/**
 * @brief Delete a target.
 *
 * @param[in]  name   Name of target.
 *
 * @return 0 success, -1 error.
 */
int
delete_target (const char* name)
{
  gchar* quoted_name = sql_quote (name, strlen (name));
  sql ("DELETE FROM targets WHERE name = '%s';", quoted_name);
  g_free (quoted_name);
  return 0;
}

/**
 * @brief Initialise a table iterator.
 *
 * @param[in]  iterator  Iterator.
 */
static void
init_table_iterator (iterator_t* iterator, const char* table)
{
  int ret;
  const char* tail;
  gchar* formatted;
  sqlite3_stmt* stmt;

  iterator->done = FALSE;
  formatted = g_strdup_printf ("SELECT * FROM %s;", table);
  while (1)
    {
      ret = sqlite3_prepare (task_db, (char*) formatted, -1, &stmt, &tail);
      if (ret == SQLITE_BUSY) continue;
      g_free (formatted);
      iterator->stmt = stmt;
      if (ret == SQLITE_OK)
        {
          if (stmt == NULL)
            {
              g_warning ("%s: sqlite3_prepare failed with NULL stmt: %s\n",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              abort ();
            }
          break;
        }
      g_warning ("%s: sqlite3_prepare failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      abort ();
    }
}

/**
 * @brief Initialise a target iterator.
 *
 * @param[in]  iterator  Iterator.
 */
void
init_target_iterator (iterator_t* iterator)
{
  init_table_iterator (iterator, "targets");
}

DEF_ACCESS (target_iterator_name, 0);
DEF_ACCESS (target_iterator_hosts, 1);


/* Config. */

/**
 * @brief Copy the preferences and nvt selector from an RC file to a config.
 *
 * @param[in]  config   Config.
 * @param[in]  rc       Text of RC file.
 *
 * @return 0 success, -1 error.
 */
static int
insert_rc_into_config (config_t config, const char *config_name, const char *rc)
{
  char* seek;

  if (rc == NULL || config_name == NULL) return -1;

  while (1)
    {
      char* eq;
      seek = strchr (rc, '\n');
      eq = seek
           ? memchr (rc, '=', seek - rc)
           : strchr (rc, '=');
      if (eq)
        {
          char* rc_end = eq;
          rc_end--;
          while (*rc_end == ' ') rc_end--;
          rc_end++;
          while (*rc == ' ') rc++;
          if (rc < rc_end)
            {
              gchar *name, *value;
              name = sql_quote (rc, rc_end - rc);
              value = sql_quote (eq + 2, /* Daring. */
                                 (seek ? seek - (eq + 2) : strlen (eq + 2)));
              sql ("INSERT OR REPLACE INTO config_preferences"
                   " (config, type, name, value)"
                   " VALUES ('%llu', NULL, '%.*s', '%.*s');",
                   config, name, value);
              g_free (name);
              g_free (value);
            }
        }
      else if ((seek ? seek - rc >= 7 + strlen ("PLUGIN_SET") : 0)
               && (strncmp (rc, "begin(", 6) == 0)
               && (strncmp (rc + 6, "PLUGIN_SET", strlen ("PLUGIN_SET")) == 0)
               && (rc[6 + strlen ("PLUGIN_SET")] == ')'))
        {
          /* Create an NVT selector from the plugin list. */
          rc = seek + 1;
          while ((seek = strchr (rc, '\n')))
            {
              char* eq2;

              if ((seek ? seek - rc > 5 : 1)
                  && strncmp (rc, "end(", 4) == 0)
                {
                  break;
                }

              eq2 = memchr (rc, '=', seek - rc);
              if (eq2)
                {
                  char* rc_end = eq2;
                  rc_end--;
                  while (*rc_end == ' ') rc_end--;
                  rc_end++;
                  while (*rc == ' ') rc++;
                  if (rc < rc_end)
                    {
                      int value_len = (seek ? seek - (eq2 + 2)
                                            : strlen (eq2 + 2));
                      sql ("INSERT INTO nvt_selectors"
                           " (name, exclude, type, family_or_nvt)"
                           " VALUES ('%s', %i, 2, '%.*s');",
                           config_name,
                           ((value_len == 3)
                            && strncasecmp (eq2 + 2, "yes", 3) == 0),
                           rc_end - rc,
                           rc);
                    }
                }

              rc = seek + 1;
            }
        }
      else if ((seek ? seek - rc > 7 : 0)
               && (strncmp (rc, "begin(", 6) == 0))
        {
          gchar *section_name;

          section_name = sql_quote (rc + 6, seek - (rc + 6));

          /* Insert the section. */

          rc = seek + 1;
          while ((seek = strchr (rc, '\n')))
            {
              char* eq2;

              if ((seek ? seek - rc > 5 : 1)
                  && strncmp (rc, "end(", 4) == 0)
                {
                  break;
                }

              eq2 = memchr (rc, '=', seek - rc);
              if (eq2)
                {
                  char* rc_end = eq2;
                  rc_end--;
                  while (*rc_end == ' ') rc_end--;
                  rc_end++;
                  while (*rc == ' ') rc++;
                  if (rc < rc_end)
                    {
                      gchar *name, *value;
                      name = sql_quote (rc, rc_end - rc);
                      value = sql_quote (eq2 + 2, /* Daring. */
                                         seek - (eq2 + 2));
                      sql ("INSERT OR REPLACE INTO config_preferences"
                           " (config, type, name, value)"
                           " VALUES (%llu, '%s', '%s', '%s');",
                           config, section_name, name, value);
                      g_free (name);
                      g_free (value);
                    }
                }

              rc = seek + 1;
            }

          g_free (section_name);
        }
      if (seek == NULL) break;
      rc = seek + 1;
    }

  // FIX convert nvt_selector plugin list into an actual nvt selector

  return 0;
}

/**
 * @brief Create a config.
 *
 * @param[in]  name   Name of config.
 * @param[in]  rc     RC file text.
 *
 * @return 0 success, -1 error.
 */
int
create_config (const char* name, const char* rc)
{
  gchar* quoted_name = sql_quote (name, strlen (name));
  config_t config;

  if (sql_int (0, 0, "SELECT COUNT(*) FROM configs WHERE name = '%s';",
               quoted_name))
    {
      g_free (quoted_name);
      return -1;
    }

  if (sql_int (0, 0, "SELECT COUNT(*) FROM nvt_selectors WHERE name = '%s';",
               quoted_name))
    {
      g_free (quoted_name);
      return -1;
    }

  sql ("INSERT INTO configs (name, nvt_selector)"
       " VALUES ('%s', '%s');",
       quoted_name, quoted_name);

  /* Insert the RC into the config_preferences table. */

  config = sqlite3_last_insert_rowid (task_db);
  if (insert_rc_into_config (config, quoted_name, rc))
    {
      g_free (quoted_name);
      return -1;
    }

  g_free (quoted_name);
  return 0;
}

/**
 * @brief Delete a config.
 *
 * @param[in]  name   Name of config.
 *
 * @return 0 success, -1 error.
 */
int
delete_config (const char* name)
{
  gchar* quoted_name = sql_quote (name, strlen (name));
  sql ("DELETE FROM nvt_selectors WHERE name = '%s';",
       quoted_name);
  sql ("DELETE FROM config_preferences"
       " WHERE config = (SELECT ROWID from configs WHERE name = '%s');",
       quoted_name);
  sql ("DELETE FROM configs WHERE name = '%s';", quoted_name);
  g_free (quoted_name);
  return 0;
}

/**
 * @brief Initialise a config iterator.
 *
 * @param[in]  iterator  Iterator.
 */
void
init_config_iterator (iterator_t* iterator)
{
  init_table_iterator (iterator, "configs");
}

DEF_ACCESS (config_iterator_name, 0);
DEF_ACCESS (config_iterator_nvt_selector, 1);

#undef DEF_ACCESS
