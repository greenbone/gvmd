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

#include "sql.h"
#include "tracef.h"

#include <assert.h>
#include <sqlite3.h>
#include <string.h>

/**
 * @brief Chunk size for SQLite memory allocation.
 */
#define DB_CHUNK_SIZE 1 * 1024 * 1024


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

  if (sqlite3_open (database ? database : OPENVAS_STATE_DIR "/mgr/tasks.db",
                    &task_db))
    {
      g_warning ("%s: sqlite3_open failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      return -1;
    }

  sqlite3_file_control (task_db, NULL, SQLITE_FCNTL_CHUNK_SIZE, &chunk_size);
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
sql_last_insert_rowid ()
{
  return sqlite3_last_insert_rowid (task_db);
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
  int ret, retries;
  gchar* formatted;
  sqlite3_stmt *sqlite_stmt;

  assert (stmt);

  formatted = g_strdup_vprintf (sql, args);

  if (log)
    tracef ("   sql: %s\n", formatted);

  retries = 10;
  *stmt = (sql_stmt_t*) g_malloc0 (sizeof (sql_stmt_t));
  sqlite_stmt = NULL;
  while (1)
    {
      ret = sqlite3_prepare (task_db, (char*) formatted, -1, &sqlite_stmt,
                             &tail);
      if (ret == SQLITE_BUSY || ret == SQLITE_LOCKED)
        {
          if (retry)
            continue;
          if (retries--)
            continue;
          g_free (formatted);
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
              return -1;
            }
          break;
        }
      g_warning ("%s: sqlite3_prepare failed: %s\n",
                 __FUNCTION__,
                 sqlite3_errmsg (task_db));
      return -1;
    }

  return 0;
}

/**
 * @brief Execute a prepared statement.
 *
 * @param[in]  retry  Whether to keep retrying while database is busy or locked.
 * @param[in]  stmt   Statement.
 *
 * @return 0 complete, 1 row available in results, -1 error, -2 gave up.
 */
int
sql_exec_internal (int retry, sql_stmt_t *stmt)
{
  int retries;

  retries = 10;
  while (1)
    {
      int ret;
      ret = sqlite3_step (stmt->stmt);
      if (ret == SQLITE_BUSY)
        {
          if (retry)
            continue;
          if (retries--)
            continue;
          return -2;
        }
      if (ret == SQLITE_DONE)
        return 0;
      if (ret == SQLITE_ERROR || ret == SQLITE_MISUSE)
        {
          if (ret == SQLITE_ERROR)
            {
              ret = sqlite3_reset (stmt->stmt);
              if (ret == SQLITE_BUSY || ret == SQLITE_LOCKED)
                {
                  if (retry)
                    continue;
                  return -2;
                }
            }
          g_warning ("%s: sqlite3_step failed: %s\n",
                     __FUNCTION__,
                     sqlite3_errmsg (task_db));
          return -1;
        }
      assert (ret == SQLITE_ROW);
      return 1;
    }
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
  while (1)
    {
      int ret;
      ret = sqlite3_bind_blob (stmt->stmt,
                               position,
                               value,
                               value_size,
                               SQLITE_TRANSIENT);
      if (ret == SQLITE_BUSY) continue;
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
sql_bind_int64 (sql_stmt_t *stmt, int position, long long int value)
{
  while (1)
    {
      int ret;
      ret = sqlite3_bind_int64 (stmt->stmt, position, value);
      if (ret == SQLITE_BUSY) continue;
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
sql_bind_double (sql_stmt_t *stmt, int position, double value)
{
  while (1)
    {
      int ret;
      ret = sqlite3_bind_double (stmt->stmt, position, value);
      if (ret == SQLITE_BUSY) continue;
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
  while (1)
    {
      int ret;
      ret = sqlite3_bind_text (stmt->stmt,
                               position,
                               value,
                               value_size,
                               SQLITE_TRANSIENT);
      if (ret == SQLITE_BUSY) continue;
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
  sqlite3_clear_bindings (stmt->stmt);
  while (1)
    {
      int ret;
      ret = sqlite3_reset (stmt->stmt);
      if (ret == SQLITE_BUSY) continue;
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
