/* OpenVAS Manager
 * $Id$
 * Description: Manager Manage library: the SQL library.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2009,2010,2012 Greenbone Networks GmbH
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
#include <string.h>

/**
 * @brief Chunk size for SQLite memory allocation.
 */
#define DB_CHUNK_SIZE 1 * 1024 * 1024


/* Variables. */

/**
 * @brief Handle on the database.
 */
sqlite3* task_db;


/* Helpers. */

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
 * @brief Quotes a string of a known length to be passed to sql statements.
 *
 * @param[in]  string  String to quote.
 * @param[in]  length  Size of \p string.
 *
 * @return Freshly allocated, quoted string. Free with g_free.
 */
gchar*
sql_nquote (const char* string, size_t length)
{
  gchar *new, *new_start;
  const gchar *start, *end;
  int count = 0;

  assert (string);

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

/**
 * @brief Quotes a string to be passed to sql statements.
 *
 * @param[in]  string  String to quote, has to be \\0 terminated.
 *
 * @return Freshly allocated, quoted string. Free with g_free.
 */
gchar*
sql_quote (const char* string)
{
  assert (string);
  return sql_nquote (string, strlen (string));
}

/**
 * @brief Get the SQL insert expression for a string.
 *
 * @param[in]  string  The string, which may be NULL.
 *
 * @return Freshly allocated expression suitable for an INSERT statement,
 *         including SQL quotation marks.
 */
gchar *
sql_insert (const char *string)
{
  if (string)
    {
      gchar *quoted_value = sql_quote (string);
      gchar *insert = g_strdup_printf ("'%s'", quoted_value);
      g_free (quoted_value);
      return insert;
    }
  return g_strdup ("NULL");
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

  formatted = g_strdup_vprintf (sql, args);

  if (log)
    tracef ("   sql: %s\n", formatted);

  retries = 10;
  *stmt = NULL;
  while (1)
    {
      ret = sqlite3_prepare (task_db, (char*) formatted, -1, stmt, &tail);
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
      if (ret == SQLITE_OK)
        {
          if (*stmt == NULL)
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
static int
sql_exec_internal (int retry, sql_stmt_t *stmt)
{
  int retries;

  retries = 10;
  while (1)
    {
      int ret;
      ret = sqlite3_step (stmt);
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
              ret = sqlite3_reset (stmt);
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

/**
 * @brief Perform an SQL statement.
 *
 * @param[in]  retry  Whether to keep retrying while database is busy or locked.
 * @param[in]  sql    Format string for SQL statement.
 * @param[in]  args   Arguments for format string.
 *
 * @return 0 success, 1 gave up, -1 error.
 */
static int
sqlv (int retry, char* sql, va_list args)
{
  int ret;
  sql_stmt_t* stmt;

  /* Prepare statement. */

  ret = sql_prepare_internal (retry, 1, sql, args, &stmt);
  if (ret == -1)
    g_warning ("%s: sql_prepare_internal failed\n", __FUNCTION__);
  if (ret)
    return ret;

  /* Run statement. */

  while ((ret = sql_exec_internal (retry, stmt)) > 0);
  if (ret == -1)
    g_warning ("%s: sql_exec_internal failed\n", __FUNCTION__);
  sql_finalize (stmt);
  if (ret == -2)
    return 1;
  return ret;
}

/**
 * @brief Perform an SQL statement, retrying if database is busy or locked.
 *
 * @param[in]  sql    Format string for SQL statement.
 * @param[in]  ...    Arguments for format string.
 */
void
sql (char* sql, ...)
{
  va_list args;

  va_start (args, sql);
  if (sqlv (1, sql, args) == -1)
    abort ();
  va_end (args);
}

/**
 * @brief Perform an SQL statement, retrying if database is busy or locked.
 *
 * Return on error, instead of aborting.
 *
 * @param[in]  sql    Format string for SQL statement.
 * @param[in]  ...    Arguments for format string.
 *
 * @return 0 success, -1 error.
 */
int
sql_error (char* sql, ...)
{
  int ret;
  va_list args;

  va_start (args, sql);
  ret = sqlv (1, sql, args);
  va_end (args);

  return ret;
}

/**
 * @brief Perform an SQL statement, giving up if database is busy or locked.
 *
 * @param[in]  sql    Format string for SQL statement.
 * @param[in]  ...    Arguments for format string.
 *
 * @return 0 success, 1 gave up, -1 error.
 */
int
sql_giveup (char* sql, ...)
{
  int ret;
  va_list args;

  va_start (args, sql);
  ret = sqlv (0, sql, args);
  va_end (args);
  return ret;
}

/**
 * @brief Perform an SQL statement, without logging.
 *
 * @param[in]  sql    Format string for SQL statement.
 * @param[in]  ...    Arguments for format string.
 */
void
sql_quiet (char* sql, ...)
{
  int ret;
  sql_stmt_t *stmt;
  va_list args;

  /* Prepare statement. */

  va_start (args, sql);
  ret = sql_prepare_internal (1, 0, sql, args, &stmt);
  va_end (args);
  if (ret)
    {
      g_warning ("%s: sql_prepare failed\n", __FUNCTION__);
      abort ();
    }

  /* Run statement. */

  while ((ret = sql_exec_internal (1, stmt)) > 0);
  if (ret == -1)
    {
      g_warning ("%s: sql_exec_internal failed\n", __FUNCTION__);
      abort ();
    }
  sql_finalize (stmt);
}

/**
 * @brief Get a particular cell from a SQL query.
 *
 * @param[in]   log          Whether to do tracef logging.
 * @param[in]   sql          Format string for SQL query.
 * @param[in]   args         Arguments for format string.
 * @param[out]  stmt_return  Return from statement.
 *
 * @return 0 success, 1 too few rows, -1 error.
 */
static int
sql_x_internal (int log, char* sql, va_list args, sql_stmt_t** stmt_return)
{
  int ret;

  assert (stmt_return);

  /* Prepare statement. */

  ret = sql_prepare_internal (1, 1, sql, args, stmt_return);
  if (ret)
    {
      g_warning ("%s: sql_prepare failed\n", __FUNCTION__);
      return -1;
    }

  /* Run statement. */

  ret = sql_exec_internal (1, *stmt_return);
  if (ret == -1)
    {
      g_warning ("%s: sql_exec_internal failed\n", __FUNCTION__);
      return -1;
    }
  if (ret == 0)
    /* Too few rows. */
    return 1;
  assert (ret == 1);
  if (log)
    tracef ("   sql_x end\n");
  return 0;
}

/**
 * @brief Get a particular cell from a SQL query.
 *
 * Do logging as usual.
 *
 * @param[in]   sql          Format string for SQL query.
 * @param[in]   args         Arguments for format string.
 * @param[out]  stmt_return  Return from statement.
 *
 * @return 0 success, 1 too few rows, -1 error.
 */
static int
sql_x (char* sql, va_list args, sql_stmt_t** stmt_return)
{
  return sql_x_internal (1, sql, args, stmt_return);
}

/**
 * @brief Get a particular cell from a SQL query.
 *
 * Skip any logging.
 *
 * @param[in]   sql          Format string for SQL query.
 * @param[in]   args         Arguments for format string.
 * @param[out]  stmt_return  Return from statement.
 *
 * @return 0 success, 1 too few rows, -1 error.
 */
static int
sql_x_quiet (char* sql, va_list args, sql_stmt_t** stmt_return)
{
  return sql_x_internal (0, sql, args, stmt_return);
}

/**
 * @brief Get the first value from a SQL query, as a double.
 *
 * @warning Aborts on invalid queries.
 *
 * @warning Aborts when the query returns fewer rows than \p row.  The
 *          caller must ensure that the query will return sufficient rows.
 *
 * @param[in]  sql    Format string for SQL query.
 * @param[in]  ...    Arguments for format string.
 *
 * @return Result of the query as an integer.
 */
double
sql_double (char* sql, ...)
{
  sql_stmt_t* stmt;
  va_list args;
  double ret;

  int sql_x_ret;
  va_start (args, sql);
  sql_x_ret = sql_x (sql, args, &stmt);
  va_end (args);
  if (sql_x_ret)
    {
      sql_finalize (stmt);
      abort ();
    }
  ret = sql_column_double (stmt, 0);
  sql_finalize (stmt);
  return ret;
}

/**
 * @brief Get a particular cell from a SQL query, as an int.
 *
 * @warning Aborts on invalid queries.
 *
 * @warning Aborts when the query returns fewer rows than \p row.  The
 *          caller must ensure that the query will return sufficient rows.
 *
 * @param[in]  sql    Format string for SQL query.
 * @param[in]  ...    Arguments for format string.
 *
 * @return Result of the query as an integer.
 */
int
sql_int (char* sql, ...)
{
  sql_stmt_t* stmt;
  va_list args;
  int ret;

  int sql_x_ret;
  va_start (args, sql);
  sql_x_ret = sql_x (sql, args, &stmt);
  va_end (args);
  if (sql_x_ret)
    {
      sql_finalize (stmt);
      abort ();
    }
  ret = sqlite3_column_int (stmt, 0);
  sql_finalize (stmt);
  return ret;
}

/**
 * @brief Get a particular cell from a SQL query, as an string.
 *
 * @param[in]  sql    Format string for SQL query.
 * @param[in]  ...    Arguments for format string.
 *
 * @return Freshly allocated string containing the result, NULL otherwise.
 *         NULL means that either the selected value was NULL or there were
 *         no rows in the result.
 */
char*
sql_string (char* sql, ...)
{
  sql_stmt_t* stmt;
  const char* ret2;
  char* ret;
  int sql_x_ret;

  va_list args;
  va_start (args, sql);
  sql_x_ret = sql_x (sql, args, &stmt);
  va_end (args);
  if (sql_x_ret)
    {
      sql_finalize (stmt);
      return NULL;
    }
  ret2 = sql_column_text (stmt, 0);
  ret = g_strdup (ret2);
  sql_finalize (stmt);
  return ret;
}

/**
 * @brief Get the first value from a SQL query, as a string.
 *
 * @param[in]  sql    Format string for SQL query.
 * @param[in]  ...    Arguments for format string.
 *
 * @return Freshly allocated string containing the result, NULL otherwise.
 *         NULL means that either the selected value was NULL or there were
 *         fewer rows in the result than \p row.
 */
char*
sql_string_quiet (char* sql, ...)
{
  sql_stmt_t* stmt;
  const char* ret2;
  char* ret;
  int sql_x_ret;

  va_list args;
  va_start (args, sql);
  sql_x_ret = sql_x_quiet (sql, args, &stmt);
  va_end (args);
  if (sql_x_ret)
    {
      sql_finalize (stmt);
      return NULL;
    }
  ret2 = sql_column_text (stmt, 0);
  ret = g_strdup (ret2);
  sql_finalize (stmt);
  return ret;
}

/**
 * @brief Get a particular cell from a SQL query, as an int64.
 *
 * @param[in]  ret    Return value.
 * @param[in]  sql    Format string for SQL query.
 * @param[in]  ...    Arguments for format string.
 *
 * @return 0 success, 1 too few rows, -1 error.
 */
int
sql_int64 (long long int* ret, char* sql, ...)
{
  sql_stmt_t* stmt;
  int sql_x_ret;
  va_list args;

  va_start (args, sql);
  sql_x_ret = sql_x (sql, args, &stmt);
  va_end (args);
  switch (sql_x_ret)
    {
      case  0:
        break;
      case  1:
        sql_finalize (stmt);
        return 1;
        break;
      default:
        assert (0);
        /* Fall through. */
      case -1:
        sql_finalize (stmt);
        return -1;
        break;
    }
  *ret = sqlite3_column_int64 (stmt, 0);
  sql_finalize (stmt);
  return 0;
}


/* Iterators. */

/**
 * @brief Initialise an iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  stmt      Statement.
 */
void
init_prepared_iterator (iterator_t* iterator, sql_stmt_t* stmt)
{
  iterator->done = FALSE;
  iterator->stmt = stmt;
  iterator->prepared = 1;
  iterator->crypt_ctx = NULL;
  tracef ("   sql: init prepared %p\n", stmt);
}

/**
 * @brief Initialise an iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  sql       Format string for SQL.
 */
void
init_iterator (iterator_t* iterator, const char* sql, ...)
{
  int ret;
  sql_stmt_t* stmt;
  va_list args;

  iterator->done = FALSE;
  iterator->prepared = 0;
  iterator->crypt_ctx = NULL;

  va_start (args, sql);
  ret = sql_prepare_internal (1, 1, sql, args, &stmt);
  va_end (args);
  if (ret)
    {
      g_warning ("%s: sql_prepare failed\n", __FUNCTION__);
      abort ();
    }
  iterator->stmt = stmt;
}

/**
 * @brief Get a double column from an iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  col       Column offset.
 *
 * @return Value of given column.
 */
double
iterator_double (iterator_t* iterator, int col)
{
  if (iterator->done) abort ();
  return sql_column_double (iterator->stmt, col);
}

/**
 * @brief Get a int column from an iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  col       Column offset.
 *
 * @return Value of given column.
 */
int
iterator_int (iterator_t* iterator, int col)
{
  if (iterator->done) abort ();
  return sqlite3_column_int (iterator->stmt, col);
}

/**
 * @brief Get an integer column from an iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  col       Column offset.
 *
 * @return Value of given column.
 */
long long int
iterator_int64 (iterator_t* iterator, int col)
{
  if (iterator->done) abort ();
  return (long long int) sqlite3_column_int64 (iterator->stmt, col);
}

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
  return sqlite3_column_type (iterator->stmt, col) == SQLITE_NULL;
}

/**
 * @brief Get a string column from an iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  col       Column offset.
 *
 * @return Value of given column.
 */
const char*
iterator_string (iterator_t* iterator, int col)
{
  if (iterator->done) abort ();
  return sql_column_text (iterator->stmt, col);
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
  return (const char*) sqlite3_column_name (iterator->stmt, col);
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
  return sqlite3_column_count (iterator->stmt);
}

/**
 * @brief Cleanup an iterator.
 *
 * @param[in]  iterator  Iterator.
 */
void
cleanup_iterator (iterator_t* iterator)
{
  if (iterator == NULL)
    {
      g_warning ("%s: null iterator pointer.\n", __FUNCTION__);
      return;
    }

  if (iterator->prepared == 0)
    sql_finalize (iterator->stmt);
  if (iterator->crypt_ctx)
    {
      lsc_crypt_release (iterator->crypt_ctx);
      iterator->crypt_ctx = NULL;
    }
}

/**
 * @brief Increment an iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return TRUE if there was a next item, else FALSE.
 */
gboolean
next (iterator_t* iterator)
{
  int ret;

  if (iterator->done) return FALSE;

  lsc_crypt_flush (iterator->crypt_ctx);
  ret = sql_exec_internal (1, iterator->stmt);
  if (ret == 0)
    {
      iterator->done = TRUE;
      return FALSE;
    }
  if (ret == -1)
    {
      g_warning ("%s: sql_exec_internal failed\n", __FUNCTION__);
      abort ();
    }
  assert (ret == 1);
  return TRUE;
}


/* Prepared statements. */

/**
 * @brief Prepare a statement.
 *
 * @param[in]  sql  Format string for SQL.
 *
 * @return Statement on success, NULL on error.
 */
sql_stmt_t *
sql_prepare (const char* sql, ...)
{
  int ret;
  sql_stmt_t* stmt;
  va_list args;

  va_start (args, sql);
  ret = sql_prepare_internal (1, 1, sql, args, &stmt);
  va_end (args);
  if (ret)
    return NULL;
  return stmt;
}

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
      ret = sqlite3_bind_blob (stmt,
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
      ret = sqlite3_bind_int64 (stmt, position, value);
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
      ret = sqlite3_bind_double (stmt, position, value);
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
      ret = sqlite3_bind_text (stmt,
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
 * @brief Execute a prepared statement.
 *
 * @param[in]  stmt  Statement.
 *
 * @return 0 complete, 1 row available in results, -1 error.
 */
int
sql_exec (sql_stmt_t *stmt)
{
  return sql_exec_internal (1, stmt);
}

/**
 * @brief Free a prepared statement.
 *
 * @param[in]  stmt  Statement.
 */
void
sql_finalize (sql_stmt_t *stmt)
{
  sqlite3_finalize (stmt);
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
  sqlite3_clear_bindings (stmt);
  while (1)
    {
      int ret;
      ret = sqlite3_reset (stmt);
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
 * @brief Return a column as text from a prepared statement.
 *
 * @param[in]  stmt      Statement.
 * @param[in]  position  Column position.
 *
 * @return 0 success, -1 error.
 */
double
sql_column_double (sql_stmt_t *stmt, int position)
{
  return sqlite3_column_double (stmt, position);
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
  return (const char*) sqlite3_column_text (stmt, position);
}
