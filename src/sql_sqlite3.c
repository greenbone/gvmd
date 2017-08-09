/* OpenVAS Manager
 * $Id$
 * Description: Manager Manage library: the SQL library.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2014 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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

#include "sql.h"
#include "utils.h"

#include <assert.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>

/**
 * @brief Chunk size for SQLite memory allocation.
 */
#define DB_CHUNK_SIZE 1 * 1024 * 1024

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"

/**
 * @brief Busy timeout, in milliseconds.
 */
#define BUSY_TIMEOUT 1000


/* Headers of sql.c symbols used only here. */

int
sqlv (int, char*, va_list);


/* Types. */

struct sql_stmt
{
  sqlite3_stmt *stmt;
};


/* Variables. */

/**
 * @brief Handle on the database.
 */
sqlite3* task_db = NULL;


/* Helpers. */

/**
 * @brief Get whether backend is SQLite3.
 *
 * @return 1.
 */
int
sql_is_sqlite3 ()
{
  return 1;
}

/**
 * @brief Get main schema name.
 *
 * @return Schema name.
 */
const char *
sql_schema ()
{
  return "main";
}

/**
 * @brief Get keyword for "greatest" SQL function.
 *
 * @return Keyword.
 */
const char *
sql_greatest ()
{
  return "max";
}

/**
 * @brief Setup a LIMIT argument.
 *
 * @param[in]  max  Max.
 *
 * @return Argument for LIMIT as a static string.
 */
const char *
sql_select_limit (int max)
{
  static char string[20];
  if (max < 0)
    return "-1";
  if (snprintf (string, 19, "%i", max) < 0)
    {
      g_warning ("%s: snprintf failed\n", __FUNCTION__);
      abort ();
    }
  string[19] = '\0';
  return string;
}

/**
 * @brief Get case insensitive LIKE operator.
 *
 * @return Like operator.
 */
const char *
sql_ilike_op ()
{
  return "LIKE";
}

/**
 * @brief Get regular expression operator.
 *
 * @return Regexp operator.
 */
const char *
sql_regexp_op ()
{
  return "REGEXP";
}

/**
 * @brief Check whether the database is open.
 *
 * @return 1 if open, else 0.
 */
int
sql_is_open ()
{
  return task_db ? 1 : 0;
}

/**
 * @brief Return file name of current database.
 *
 * @return File name of database.
 */
const char *
sql_database ()
{
  /* This is currently only used by Postgres. */
  return "TODO";
}

/**
 * @brief Return name of default database file.
 *
 * @return File name.
 */
const char *
sql_default_database ()
{
  return OPENVAS_STATE_DIR "/mgr/tasks.db";
}

/**
 * @brief Open the database.
 *
 * @param[in]  database  Database, or NULL for default.
 *
 * @return 0 success, -1 error.
 */
int
sql_open (const char *database)
{
  int chunk_size = DB_CHUNK_SIZE;
  struct stat state;
  int err, ret;
  gchar *mgr_dir;

  /* Ensure the mgr directory exists. */

  mgr_dir = g_build_filename (OPENVAS_STATE_DIR, "mgr", NULL);
  ret = g_mkdir_with_parents (mgr_dir, 0755 /* "rwxr-xr-x" */);
  g_free (mgr_dir);
  if (ret == -1)
    {
      g_warning ("%s: failed to create mgr directory: %s\n",
                 __FUNCTION__,
                 strerror (errno));
      abort ();
    }

  err = stat (database ? database : sql_default_database (),
              &state);
  if (err)
    switch (errno)
      {
        case ENOENT:
          break;
        default:
          g_warning ("%s: failed to stat database: %s\n",
                     __FUNCTION__,
                     strerror (errno));
          abort ();
      }
  else if (state.st_mode & (S_IXUSR | S_IRWXG | S_IRWXO))
    {
      g_warning ("%s: database permissions are too loose, repairing\n",
                 __FUNCTION__);
      if (chmod (database ? database : sql_default_database (),
                 S_IRUSR | S_IWUSR))
        {
          g_warning ("%s: chmod failed: %s\n",
                     __FUNCTION__,
                     strerror (errno));
          abort ();
        }
    }

  /* Workaround for SQLite temp file name conflicts that can occur if
   * concurrent forked processes have the same PRNG state. */
#if SQLITE_VERSION_NUMBER < 3008003
    sqlite3_test_control (SQLITE_TESTCTRL_PRNG_RESET);
#endif

  if (sqlite3_open (database ? database : sql_default_database (),
                    &task_db))
    {
      g_warning ("%s: sqlite3_open failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      return -1;
    }

  sqlite3_busy_timeout (task_db, BUSY_TIMEOUT);

  g_debug ("   %s: db open, max retry sleep time is %i\n",
           __FUNCTION__,
           OPENVAS_SQLITE_SLEEP_MAX);

  sqlite3_file_control (task_db, NULL, SQLITE_FCNTL_CHUNK_SIZE, &chunk_size);

  sql ("PRAGMA journal_mode=WAL;");
  sql ("PRAGMA journal_size_limit=134217728;");  /* 128 MB. */

  return 0;
}

/**
 * @brief Close the database.
 */
void
sql_close ()
{
  if (sqlite3_close (task_db) == SQLITE_BUSY)
    /* Richard Hipp on how to find the open statements:
     *
     * There is no published way to do this.  If you run in a debugger,
     * you can look at the linked list of "struct Vdbe" objects that
     * sqlite3.pVdbe points to.  This is the list of open statements
     * in the current implementation (and subject to change without
     * notice). */
    g_warning ("%s: attempt to close db with open statement(s)\n",
               __FUNCTION__);
  task_db = NULL;
}

/**
 * @brief Close the database in a forked process.
 */
void
sql_close_fork ()
{
  task_db = NULL;
}

/**
 * @brief Get the number of rows changed or inserted in last statement.
 */
int
sql_changes ()
{
  return sqlite3_changes (task_db);
}

/**
 * @brief Get the ID of the last inserted row.
 */
resource_t
sql_last_insert_id ()
{
  return sqlite3_last_insert_rowid (task_db);
}

/**
 * @brief Perform an SQL statement, retrying if database is busy or locked.
 *
 * @param[out] resource  Last inserted resource.
 * @param[in]  sql       Format string for SQL statement.
 * @param[in]  ...       Arguments for format string.
 */
void
sqli (resource_t *resource, char* sql, ...)
{
  va_list args;

  va_start (args, sql);
  if (sqlv (1, sql, args) == -1)
    abort ();
  va_end (args);
  if (resource)
    *resource = sql_last_insert_id ();
}

/**
 * @brief Prepare a statement.
 *
 * @param[in]  retry  Whether to keep retrying while database is busy or locked.
 * @param[in]  log    Whether to keep retrying while database is busy or locked.
 * @param[in]  sql    Format string for SQL statement.
 * @param[in]  args   Arguments for format string.
 * @param[out] stmt   Statement return.
 *
 * @return 0 success, 1 gave up, -1 error.
 */
int
sql_prepare_internal (int retry, int log, const char* sql, va_list args,
                      sql_stmt_t **stmt)
{
  const char* tail;
  int ret;
  unsigned int retries;
  gchar* formatted;
  sqlite3_stmt *sqlite_stmt;

  assert (stmt);

  formatted = g_strdup_vprintf (sql, args);

  if (log)
    g_debug ("   sql: %s\n", formatted);

  if (retry == 0)
    sqlite3_busy_timeout (task_db, 0);

  retries = 0;
  *stmt = (sql_stmt_t*) g_malloc0 (sizeof (sql_stmt_t));
  sqlite_stmt = NULL;
  while (1)
    {
      ret = sqlite3_prepare_v2 (task_db, (char*) formatted, -1, &sqlite_stmt,
                                &tail);
      if (ret == SQLITE_BUSY || ret == SQLITE_LOCKED)
        {
          if (retry)
            {
              if ((retries > 10) && (OPENVAS_SQLITE_SLEEP_MAX > 0))
                openvas_usleep (MIN ((retries - 10) * 10000,
                                     OPENVAS_SQLITE_SLEEP_MAX));
              retries++;
              continue;
            }
          if (retries++ < 10)
            continue;
          g_free (formatted);
          if (retry == 0)
            sqlite3_busy_timeout (task_db, BUSY_TIMEOUT);
          return 1;
        }
      g_free (formatted);
      (*stmt)->stmt = sqlite_stmt;
      if (ret == SQLITE_OK)
        {
          if (sqlite_stmt == NULL)
            {
              g_warning ("%s: sqlite3_prepare failed with NULL stmt: %s\n",
                         __FUNCTION__,
                         sqlite3_errmsg (task_db));
              if (retry == 0)
                sqlite3_busy_timeout (task_db, BUSY_TIMEOUT);
              return -1;
            }
          break;
        }
      g_warning ("%s: sqlite3_prepare failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      if (retry == 0)
        sqlite3_busy_timeout (task_db, BUSY_TIMEOUT);
      return -1;
    }

  if (retry == 0)
    sqlite3_busy_timeout (task_db, BUSY_TIMEOUT);
  return 0;
}

/**
 * @brief Execute a prepared statement.
 *
 * @param[in]  retry  Whether to keep retrying while database is busy or locked.
 * @param[in]  stmt   Statement.
 *
 * @return 0 complete, 1 row available in results, 2 condition where caller must rerun
 *         prepare (for example schema changed internally after VACUUM), -1 error,
 *         -2 gave up.
 */
int
sql_exec_internal (int retry, sql_stmt_t *stmt)
{
  unsigned int retries;

  if (retry == 0)
    sqlite3_busy_timeout (task_db, 0);

  retries = 0;
  while (1)
    {
      int ret;
      ret = sqlite3_step (stmt->stmt);
      if (ret == SQLITE_BUSY)
        {
          if (retry)
            {
              if ((retries > 10) && (OPENVAS_SQLITE_SLEEP_MAX > 0))
                openvas_usleep (MIN ((retries - 10) * 10000,
                                     OPENVAS_SQLITE_SLEEP_MAX));
              retries++;
              continue;
            }
          if (retries++ < 10)
            continue;
          return -2;
        }
      if (retry == 0)
        sqlite3_busy_timeout (task_db, BUSY_TIMEOUT);
      if (ret == SQLITE_DONE)
        return 0;
      if (ret == SQLITE_ROW)
        return 1;
      g_warning ("%s: sqlite3_step failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      return -1;
    }
}

/**
 * @brief Write debug messages with the query plan for an SQL query to the log.
 *
 * @param[in] sql   Format string for the SQL query.
 * @param[in] args  Format string arguments in a va_list.
 *
 * @return 0 success, -1 error.
 */
int
sql_explain_internal (const char* sql, va_list args)
{
  char *explain_sql;
  sql_stmt_t *explain_stmt;
  int explain_ret;

  explain_sql = g_strconcat ("EXPLAIN QUERY PLAN ", sql, NULL);
  if (sql_prepare_internal (1, 1, explain_sql, args, &explain_stmt))
    {
      g_warning ("%s : Failed to prepare EXPLAIN statement", __FUNCTION__);
      g_free (explain_sql);
      return -1;
    }

  while (1)
    {
      explain_ret = sql_exec_internal (1, explain_stmt);
      if (explain_ret == 1)
        g_debug ("%s : %s|%s|%s|%s",
                __FUNCTION__,
                sqlite3_column_text (explain_stmt->stmt, 0),
                sqlite3_column_text (explain_stmt->stmt, 1),
                sqlite3_column_text (explain_stmt->stmt, 2),
                sqlite3_column_text (explain_stmt->stmt, 3));
      else if (explain_ret == 0)
        break;
      else
        {
          g_warning ("%s : Failed to get EXPLAIN row", __FUNCTION__);
          sql_finalize (explain_stmt);
          g_free (explain_sql);
          return -1;
        }
    }

  sql_finalize (explain_stmt);
  g_free (explain_sql);
  return 0;
}


/* Transactions. */

/**
 * @brief Begin an exclusive transaction.
 */
void
sql_begin_exclusive ()
{
  sql ("BEGIN EXCLUSIVE;");
}

/**
 * @brief Begin an exclusive transaction, giving up on failure.
 *
 * @return 0 got lock, 1 gave up, -1 error.
 */
int
sql_begin_exclusive_giveup ()
{
  return sql_giveup ("BEGIN EXCLUSIVE;");
}

/**
 * @brief Begin an exclusive transaction.
 */
void
sql_begin_immediate ()
{
  sql ("BEGIN IMMEDIATE;");
}

/**
 * @brief Begin an exclusive transaction.
 *
 * @return 0 got lock, 1 gave up, -1 error.
 */
int
sql_begin_immediate_giveup ()
{
  return sql_giveup ("BEGIN IMMEDIATE;");
}

/**
 * @brief Commit a transaction.
 */
void
sql_commit ()
{
  sql ("COMMIT;");
}

/**
 * @brief Roll a transaction back.
 */
void
sql_rollback ()
{
  sql ("ROLLBACK;");
}


/* Iterators. */

/**
 * @brief Get whether a column is NULL.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  col       Column offset.
 *
 * @return 1 if NULL, else 0.
 */
int
iterator_null (iterator_t* iterator, int col)
{
  if (iterator->done) abort ();
  return sqlite3_column_type (iterator->stmt->stmt, col) == SQLITE_NULL;
}

/**
 * @brief Get a column name from an iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  col       Column offset.
 *
 * @return Name of given column.
 */
const char*
iterator_column_name (iterator_t* iterator, int col)
{
  if (iterator->done) abort ();
  return (const char*) sqlite3_column_name (iterator->stmt->stmt, col);
}

/**
 * @brief Get number of columns from an iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Number of columns.
 */
int
iterator_column_count (iterator_t* iterator)
{
  if (iterator->done) abort ();
  return sqlite3_column_count (iterator->stmt->stmt);
}


/* Prepared statements. */

/**
 * @brief Bind a blob to a statement.
 *
 * @param[in]  stmt        Statement.
 * @param[in]  position    Position in statement.
 * @param[in]  value       Blob.
 * @param[in]  value_size  Blob size.
 *
 * @return 0 success, -1 error.
 */
int
sql_bind_blob (sql_stmt_t *stmt, int position, const void *value,
               int value_size)
{
  unsigned int retries;
  retries = 0;
  while (1)
    {
      int ret;
      ret = sqlite3_bind_blob (stmt->stmt,
                               position,
                               value,
                               value_size,
                               SQLITE_TRANSIENT);
      if (ret == SQLITE_BUSY)
        {
          if ((retries > 10) && (OPENVAS_SQLITE_SLEEP_MAX > 0))
            openvas_usleep (MIN ((retries - 10) * 10000,
                                 OPENVAS_SQLITE_SLEEP_MAX));
          retries++;
          continue;
        }
      if (ret == SQLITE_OK) break;
      g_warning ("%s: sqlite3_bind_blob failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      return -1;
    }
  return 0;
}

/**
 * @brief Bind an int64 value to a statement.
 *
 * @param[in]  stmt        Statement.
 * @param[in]  position    Position in statement.
 * @param[in]  value       Value.
 *
 * @return 0 success, -1 error.
 */
int
sql_bind_int64 (sql_stmt_t *stmt, int position, long long int *value)
{
  unsigned int retries;
  retries = 0;
  while (1)
    {
      int ret;
      ret = sqlite3_bind_int64 (stmt->stmt, position, *value);
      if (ret == SQLITE_BUSY)
        {
          if ((retries > 10) && (OPENVAS_SQLITE_SLEEP_MAX > 0))
            openvas_usleep (MIN ((retries - 10) * 10000,
                                 OPENVAS_SQLITE_SLEEP_MAX));
          retries++;
          continue;
        }
      if (ret == SQLITE_OK) break;
      g_warning ("%s: sqlite3_bind_int64 failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      return -1;
    }
  return 0;
}

/**
 * @brief Bind a double value to a statement.
 *
 * @param[in]  stmt        Statement.
 * @param[in]  position    Position in statement.
 * @param[in]  value       Value.
 *
 * @return 0 success, -1 error.
 */
int
sql_bind_double (sql_stmt_t *stmt, int position, double *value)
{
  unsigned int retries;
  retries = 0;
  while (1)
    {
      int ret;
      ret = sqlite3_bind_double (stmt->stmt, position, *value);
      if (ret == SQLITE_BUSY)
        {
          if ((retries > 10) && (OPENVAS_SQLITE_SLEEP_MAX > 0))
            openvas_usleep (MIN ((retries - 10) * 10000,
                                 OPENVAS_SQLITE_SLEEP_MAX));
          retries++;
          continue;
        }
      if (ret == SQLITE_OK) break;
      g_warning ("%s: sqlite3_bind_double failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      return -1;
    }
  return 0;
}

/**
 * @brief Bind a text value to a statement.
 *
 * @param[in]  stmt        Statement.
 * @param[in]  position    Position in statement.
 * @param[in]  value       Value.
 * @param[in]  value_size  Value size, or -1 to use strlen of value.
 *
 * @return 0 success, -1 error.
 */
int
sql_bind_text (sql_stmt_t *stmt, int position, const gchar *value,
               gsize value_size)
{
  unsigned int retries;
  retries = 0;
  while (1)
    {
      int ret;
      ret = sqlite3_bind_text (stmt->stmt,
                               position,
                               value,
                               value_size,
                               SQLITE_TRANSIENT);
      if (ret == SQLITE_BUSY)
        {
          if ((retries > 10) && (OPENVAS_SQLITE_SLEEP_MAX > 0))
            openvas_usleep (MIN ((retries - 10) * 10000,
                                 OPENVAS_SQLITE_SLEEP_MAX));
          retries++;
          continue;
        }
      if (ret == SQLITE_OK) break;
      g_warning ("%s: sqlite3_bind_text failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      return -1;
    }
  return 0;
}

/**
 * @brief Free a prepared statement.
 *
 * @param[in]  stmt  Statement.
 */
void
sql_finalize (sql_stmt_t *stmt)
{
  if (stmt->stmt)
    sqlite3_finalize (stmt->stmt);
  g_free (stmt);
}

/**
 * @brief Reset a prepared statement.
 *
 * @param[in]  stmt  Statement.
 *
 * @return 0 success, -1 error.
 */
int
sql_reset (sql_stmt_t *stmt)
{
  unsigned int retries;
  sqlite3_clear_bindings (stmt->stmt);
  retries = 0;
  while (1)
    {
      int ret;
      ret = sqlite3_reset (stmt->stmt);
      if (ret == SQLITE_BUSY)
        {
          if ((retries > 10) && (OPENVAS_SQLITE_SLEEP_MAX > 0))
            openvas_usleep (MIN ((retries - 10) * 10000,
                                 OPENVAS_SQLITE_SLEEP_MAX));
          retries++;
          continue;
        }
      if (ret == SQLITE_DONE || ret == SQLITE_OK) break;
      if (ret == SQLITE_ERROR || ret == SQLITE_MISUSE)
        {
          g_warning ("%s: sqlite3_reset failed: %s\n",
                     __FUNCTION__,
                     sqlite3_errmsg (task_db));
          return -1;
        }
    }
  return 0;
}

/**
 * @brief Return a column as a double from a prepared statement.
 *
 * @param[in]  stmt      Statement.
 * @param[in]  position  Column position.
 *
 * @return 0 success, -1 error.
 */
double
sql_column_double (sql_stmt_t *stmt, int position)
{
  return sqlite3_column_double (stmt->stmt, position);
}

/**
 * @brief Return a column as text from a prepared statement.
 *
 * @param[in]  stmt      Statement.
 * @param[in]  position  Column position.
 *
 * @return 0 success, -1 error.
 */
const char *
sql_column_text (sql_stmt_t *stmt, int position)
{
  return (const char*) sqlite3_column_text (stmt->stmt, position);
}

/**
 * @brief Return a column as an integer from a prepared statement.
 *
 * @param[in]  stmt      Statement.
 * @param[in]  position  Column position.
 *
 * @return 0 success, -1 error.
 */
int
sql_column_int (sql_stmt_t *stmt, int position)
{
  return sqlite3_column_int (stmt->stmt, position);
}

/**
 * @brief Return a column as an int64 from a prepared statement.
 *
 * @param[in]  stmt      Statement.
 * @param[in]  position  Column position.
 *
 * @return 0 success, -1 error.
 */
long long int
sql_column_int64 (sql_stmt_t *stmt, int position)
{
  return sqlite3_column_int64 (stmt->stmt, position);
}

/**
 * @brief Cancels the current SQL statement.
 *
 * @return 0 on success, -1 on error.
 */
int
sql_cancel_internal ()
{
  if (task_db)
    {
      sqlite3_interrupt (task_db);
      return 0;
    }
  else
    {
      return -1;
    }
}
