/* Copyright (C) 2014-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Generic SQL interface: PostgreSQL backend
 *
 * PostreSQL backend of the SQL interface.
 */

#include "ipc.h"
#include "sql.h"

#include <arpa/inet.h>
#include <assert.h>
#include <endian.h>
#include <errno.h>
#include <glib.h>
#include <gvm/base/array.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <postgresql/libpq-fe.h>
#include <stdlib.h>
#include <string.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"


/* Types. */

/**
 * @brief An SQL statement.
 */
struct sql_stmt
{
  gchar *sql;            ///< SQL statement.
  PGresult *result;      ///< Result set.
  int current_row;       ///< Row position in results.
  int executed;          ///< Whether statement has been executed.
  array_t *param_values; ///< Parameter values.
  GArray *param_lengths; ///< Parameter lengths (int's).
  GArray *param_formats; ///< Parameter formats (int's).
};


/* Variables. */

/**
 * @brief Whether to log errors.
 *
 * Used to turn off logging when cancelling statements on exit.  Defined
 * in sql.c.
 */
extern int log_errors;

/**
 * @brief Handle on the database.
 */
static PGconn *conn = NULL;


/* Helpers. */

/**
 * @brief Get main schema name.
 *
 * @return Schema name.
 */
const char *
sql_schema ()
{
  return "public";
}

/**
 * @brief Get keyword for "greatest" SQL function.
 *
 * @return Keyword.
 */
const char *
sql_greatest ()
{
  return "greatest";
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
    return "ALL";
  if (snprintf (string, 19, "%i", max) < 0)
    {
      g_warning ("%s: snprintf failed", __func__);
      abort ();
    }
  string[19] = '\0';
  return string;
}

/**
 * @brief Init statement, preserving SQL.
 *
 * @param[in]  stmt  Statement.
 */
static void
sql_stmt_init (sql_stmt_t *stmt)
{
  memset (stmt, 0, sizeof (*stmt));
  stmt->param_values = make_array ();
  stmt->param_lengths = g_array_new (FALSE, TRUE, sizeof (int));
  stmt->param_formats = g_array_new (FALSE, TRUE, sizeof (int));
  stmt->current_row = -1;
}

/**
 * @brief Get case insensitive LIKE operator.
 *
 * @return Like operator.
 */
const char *
sql_ilike_op ()
{
  return "ILIKE";
}

/**
 * @brief Get regular expression operator.
 *
 * @return Regexp operator.
 */
const char *
sql_regexp_op ()
{
  return "?~#";
}

/**
 * @brief Check whether the database is open.
 *
 * @return 1 if open, else 0.
 */
int
sql_is_open ()
{
  return conn ? 1 : 0;
}

#ifndef NDEBUG
#include <execinfo.h>

/**
 * @brief Maximum number of frames in backtrace.
 *
 * For debugging backtrace in \ref log_notice.
 */
#define BA_SIZE 100
#endif

/**
 * @brief Log a NOTICE message.
 *
 * @param[in]  arg     Dummy arg.
 * @param[in]  result  Arg.
 */
static void
log_notice (void *arg, const PGresult *result)
{
  g_debug ("PQ notice: %s", PQresultErrorMessage (result));

#ifndef NDEBUG
  char *verbose;

  verbose = PQresultVerboseErrorMessage (result, PQERRORS_VERBOSE,
                                         PQSHOW_CONTEXT_ALWAYS);
  g_debug ("PQ notice: verbose: %s", verbose);
  PQfreemem (verbose);
#endif

  g_debug ("PQ notice: detail: %s",
           PQresultErrorField (result, PG_DIAG_MESSAGE_DETAIL));
  g_debug ("PQ notice: hint: %s",
           PQresultErrorField (result, PG_DIAG_MESSAGE_HINT));
  g_debug ("PQ notice:     table %s.%s",
           PQresultErrorField (result, PG_DIAG_SCHEMA_NAME),
           PQresultErrorField (result, PG_DIAG_TABLE_NAME));
  g_debug ("PQ notice:     from %s in %s:%s",
           PQresultErrorField (result, PG_DIAG_SOURCE_FUNCTION),
           PQresultErrorField (result, PG_DIAG_SOURCE_FILE),
           PQresultErrorField (result, PG_DIAG_SOURCE_LINE));
  g_debug ("PQ notice: context:\n%s",
           PQresultErrorField (result, PG_DIAG_CONTEXT));

#ifndef NDEBUG
  void *frames[BA_SIZE];
  int frame_count, index;
  char **frames_text;

  /* Print a backtrace. */
  frame_count = backtrace (frames, BA_SIZE);
  frames_text = backtrace_symbols (frames, frame_count);
  if (frames_text == NULL)
    {
      perror ("backtrace symbols");
      frame_count = 0;
    }
  for (index = 0; index < frame_count; index++)
    g_debug ("%s", frames_text[index]);
  free (frames_text);
#endif
}

/**
 * @brief Return name of current database.
 *
 * @return Name of database.
 */
const char *
sql_database ()
{
  return PQdb (conn);
}

/**
 * @brief Return name of default database.
 *
 * @return Name.
 */
const char *
sql_default_database ()
{
  return "gvmd";
}

/**
 * @brief Open the database.
 *
 * @param[in]  database  Database, or NULL for default.
 *
 * @return 0 success, -1 error.
 */
int
sql_open (const db_conn_info_t *database)
{
  gchar *conn_info;
  PostgresPollingStatusType poll_status;
  int socket;

  conn_info = g_strdup_printf (
    "dbname='%s'"
    " host='%s'"
    " port='%s'"
    " user='%s'"
    " application_name='%s'",
    database->name ? database->name : sql_default_database (),
    database->host ? database->host : "", database->port ? database->port : "",
    database->user ? database->user : "", "gvmd");

  if (semaphore_op (SEMAPHORE_DB_CONNECTIONS, -1, database->semaphore_timeout))
    {
      g_warning ("%s: error signaling database connection semaphore", __func__);
      g_free (conn_info);
      return -1;
    }
  conn = PQconnectStart (conn_info);
  g_free (conn_info);
  if (conn == NULL)
    {
      g_warning ("%s: PQconnectStart failed to allocate conn", __func__);
      semaphore_op (SEMAPHORE_DB_CONNECTIONS, +1, 0);
      return -1;
    }
  if (PQstatus (conn) == CONNECTION_BAD)
    {
      g_warning ("%s: PQconnectStart to '%s' failed: %s", __func__,
                 database->name ? database->name : sql_default_database (),
                 PQerrorMessage (conn));
      goto fail;
    }

  socket = PQsocket (conn);
  if (socket == 0)
    {
      g_warning ("%s: PQsocket 0", __func__);
      goto fail;
    }

  poll_status = PGRES_POLLING_WRITING;

  g_debug ("%s: polling", __func__);

  while (1)
    {
      if (poll_status == PGRES_POLLING_READING)
        {
          fd_set readfds, writefds;
          int ret;

          FD_ZERO (&readfds);
          FD_ZERO (&writefds);
          FD_SET (socket, &readfds);
          ret = select (socket + 1, &readfds, &writefds, NULL, NULL);
          if (ret == 0)
            continue;
          if (ret < 0)
            {
              g_warning ("%s: write select failed: %s", __func__,
                         strerror (errno));
              goto fail;
            }
          /* Poll again. */
        }
      else if (poll_status == PGRES_POLLING_WRITING)
        {
          fd_set readfds, writefds;
          int ret;

          FD_ZERO (&readfds);
          FD_ZERO (&writefds);
          FD_SET (socket, &writefds);
          ret = select (socket + 1, &readfds, &writefds, NULL, NULL);
          if (ret == 0)
            continue;
          if (ret < 0)
            {
              g_warning ("%s: read select failed: %s", __func__,
                         strerror (errno));
              goto fail;
            }
          /* Poll again. */
        }
      else if (poll_status == PGRES_POLLING_FAILED)
        {
          g_warning ("%s: PQconnectPoll failed", __func__);
          g_warning ("%s: PQerrorMessage (conn): %s", __func__,
                     PQerrorMessage (conn));
          goto fail;
        }
      else if (poll_status == PGRES_POLLING_OK)
        /* Connection is ready, exit loop. */
        break;

      poll_status = PQconnectPoll (conn);
    }

  PQsetNoticeReceiver (conn, log_notice, NULL);

  g_debug ("%s:   db: %s", __func__, PQdb (conn));
  g_debug ("%s: user: %s", __func__, PQuser (conn));
  g_debug ("%s: host: %s", __func__, PQhost (conn));
  g_debug ("%s: port: %s", __func__, PQport (conn));
  g_debug ("%s: socket: %i", __func__, PQsocket (conn));
  g_debug ("%s: postgres version: %i", __func__, PQserverVersion (conn));

  if (PQserverVersion (conn) < 90600)
    {
      g_warning ("%s: PostgreSQL version 9.6 (90600) or higher is required",
                 __func__);
      g_warning ("%s: Current version is %i", __func__, PQserverVersion (conn));
      goto fail;
    }

  return 0;

fail:
  PQfinish (conn);
  conn = NULL;
  semaphore_op (SEMAPHORE_DB_CONNECTIONS, +1, 0);
  return -1;
}

/**
 * @brief Close the database.
 */
void
sql_close ()
{
  PQfinish (conn);
  conn = NULL;
  semaphore_op (SEMAPHORE_DB_CONNECTIONS, +1, 0);
}

/**
 * @brief Close the database in a forked process.
 */
void
sql_close_fork ()
{
  conn = NULL;
}

/**
 * @brief Return 0.
 *
 * @return 0.
 */
int
sql_changes ()
{
  /* TODO PQcmdTuples needs a PQresult.  Callers use for info only anyway. */
  return 0;
}

/**
 * @brief Get the ID of the last inserted row.
 *
 * @return Resource.
 */
resource_t
sql_last_insert_id ()
{
  return sql_int ("SELECT LASTVAL ();");
}

/**
 * @brief Prepare a statement.
 *
 * @param[in]  log    Whether to log SQL statements as debug messages.
 * @param[in]  sql    Format string for SQL statement.
 * @param[in]  args   Arguments for format string.
 * @param[out] stmt   Statement return.
 */
void
sql_prepare_internal (int log, const char *sql, va_list args, sql_stmt_t **stmt)
{
  assert (stmt);

  *stmt = (sql_stmt_t *) g_malloc (sizeof (sql_stmt_t));
  sql_stmt_init (*stmt);
  (*stmt)->sql = g_strdup_vprintf (sql, args);

  if (log)
    g_debug ("   sql: %s", (*stmt)->sql);
}

/**
 * @brief Prepare a statement in prepared statement syntax.
 *
 * The list of parameter values must be passed as pointers to
 *  sql_param_t structs and include a NULL sentinel at the end.
 *
 * @see sql_param_t for more info about passing the parameters.
 *
 * @param[in]  log    Whether to log SQL statements as debug messages.
 * @param[in]  sql    SQL statement template in prepared statement syntax.
 * @param[in]  args   Parameters passed as a va_list.
 * @param[out] stmt   Statement return.
 */
void
sql_prepare_ps_internal (int log, const char *sql, va_list args,
                         sql_stmt_t **stmt)
{
  assert (stmt);
  va_list args_copy;
  sql_param_t *param;
  int n_params = 0;

  *stmt = (sql_stmt_t *) g_malloc (sizeof (sql_stmt_t));
  sql_stmt_init (*stmt);
  (*stmt)->sql = g_strdup (sql);

  if (log)
    g_debug ("   sql: %s", (*stmt)->sql);

  va_copy (args_copy, args);
  while ((param = va_arg (args_copy, sql_param_t *)) != NULL)
    n_params++;
  va_end (args_copy);

  g_ptr_array_set_size ((*stmt)->param_values, n_params);
  g_array_set_size ((*stmt)->param_formats, n_params);
  g_array_set_size ((*stmt)->param_lengths, n_params);

  va_copy (args_copy, args);
  for (int i = 0; i < n_params; i++)
    {
      gchar *pq_value = NULL;
      param = va_arg (args_copy, sql_param_t *);

      switch (param->type)
        {
        case SQL_PARAM_TYPE_NULL:
          // Send a null pointer for null values
          if (log)
            g_debug ("sql param $%d (null)", i + 1);
          break;
        case SQL_PARAM_TYPE_DOUBLE:
          pq_value = g_strdup_printf ("%lg", param->value.double_value);
          if (log)
            g_debug ("sql param $%d (double) = %s", i + 1, pq_value);
          break;
        case SQL_PARAM_TYPE_INT:
          pq_value = g_strdup_printf ("%d", param->value.int_value);
          if (log)
            g_debug ("sql param $%d (int) = %s", i + 1, pq_value);
          break;
        case SQL_PARAM_TYPE_STRING:
          pq_value = g_strdup (param->value.str_value ?: "");
          if (log)
            g_debug ("sql param $%d (string) = %s", i + 1, pq_value);
          break;
        case SQL_PARAM_TYPE_RESOURCE:
          pq_value = g_strdup_printf ("%llu", param->value.resource_value);
          if (log)
            g_debug ("sql param $%d (resource) = %s", i + 1, pq_value);
          break;
        }

      (*stmt)->param_values->pdata[i] = pq_value;
      if (pq_value)
        (*stmt)->param_lengths->data[i] = strlen (pq_value);
    }
  va_end (args_copy);
}

/**
 * @brief Execute a statement.
 *
 * @param[in]  stmt   Statement.
 *
 * @return 0 complete, 1 row available in results, -1 error, -2 gave up,
 *         -3 lock unavailable, -4 unique constraint violation.
 */
int
sql_exec_internal (sql_stmt_t *stmt)
{
  PGresult *result;

  assert (stmt->sql);

  if (stmt->executed == 0)
    {
      result = PQexecParams (conn, stmt->sql, stmt->param_values->len,
                             NULL, /* Default param types. */
                             (const char *const *) stmt->param_values->pdata,
                             (const int *) stmt->param_lengths->data,
                             (const int *) stmt->param_formats->data,
                             0); /* Results as text. */
      ExecStatusType status = PQresultStatus (result);

      if (status != PGRES_TUPLES_OK && status != PGRES_COMMAND_OK
          && status != PGRES_COPY_IN)
        {
          char *sqlstate;

          sqlstate = PQresultErrorField (result, PG_DIAG_SQLSTATE);
          g_debug ("%s: sqlstate: %s", __func__, sqlstate);
          if (sqlstate && (strcmp (sqlstate, "57014") == 0))
            {
              /* query_canceled */
              log_errors = 0;
              g_debug ("%s: canceled SQL: %s", __func__, stmt->sql);
            }
          else if (sqlstate && (strcmp (sqlstate, "55P03") == 0))
            {
              /* lock_not_available */
              g_debug ("%s: lock unavailable: %s", __func__,
                       PQresultErrorMessage (result));
              return -3;
            }
          else if (sqlstate && (strcmp (sqlstate, "23505") == 0))
            {
              /* unique_violation */
              g_warning ("%s: constraint violation: %s", __func__,
                         PQresultErrorMessage (result));
              g_warning ("%s: SQL: %s", __func__, stmt->sql);
              return -4;
            }
          else if (sqlstate && (strcmp (sqlstate, "40P01") == 0))
            {
              /* deadlock_detected */
              g_debug ("%s: deadlock: %s", __func__,
                       PQresultErrorMessage (result));
              g_debug ("%s: SQL: %s", __func__, stmt->sql);
              return -5;
            }
          if (log_errors)
            {
              g_warning ("%s: PQexec failed: %s (%i)", __func__,
                         PQresultErrorMessage (result), status);
              g_warning ("%s: SQL: %s", __func__, stmt->sql);
            }
          return -1;
        }

      stmt->result = result;
      stmt->executed = 1;
    }

  if (stmt->current_row < (PQntuples (stmt->result) - 1))
    {
      stmt->current_row++;
      return 1;
    }

  return 0;
}


/* Transactions. */

/**
 * @brief Begin an immediate transaction.
 */
void
sql_begin_immediate ()
{
  sql ("BEGIN;");
}

/**
 * @brief Begin an immediate transaction.
 *
 * @return 0 got lock, 1 gave up, -1 error.
 */
int
sql_begin_immediate_giveup ()
{
  int ret;

  ret = sql_giveup ("BEGIN;");
  if (ret)
    return ret;
  return 0;
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

/**
 * Try to lock a table in exclusive mode, timing out after a given time.
 *
 * @param[in]  table         The table to lock.
 * @param[in]  lock_timeout  The lock timeout in milliseconds, 0 for unlimited.
 *
 * @return 1 if locked, 0 if failed / timed out.
 */
int
sql_table_lock_wait (const char *table, int lock_timeout)
{
  int old_lock_timeout = sql_int ("SHOW lock_timeout;");
  sql ("SET LOCAL lock_timeout = %d;", lock_timeout);

  // This requires the gvmd functions to be defined first.
  int ret = sql_int ("SELECT try_exclusive_lock_wait ('%s');", table);

  sql ("SET LOCAL lock_timeout = %d;", old_lock_timeout);
  return ret;
}

/**
 * Try to lock a table in shared mode, timing out after a given time.
 *
 * @param[in]  table         The table to lock.
 * @param[in]  lock_timeout  The lock timeout in milliseconds, 0 for unlimited.
 *
 * @return 1 if locked, 0 if failed / timed out.
 */
int
sql_table_shared_lock_wait (const char *table, int lock_timeout)
{
  int old_lock_timeout = sql_int ("SHOW lock_timeout;");
  sql ("SET LOCAL lock_timeout = %d;", lock_timeout);

  // This requires the gvmd functions to be defined first.
  int ret = sql_int ("SELECT try_shared_lock_wait ('%s');", table);

  sql ("SET LOCAL lock_timeout = %d;", old_lock_timeout);
  return ret;
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
iterator_null (iterator_t *iterator, int col)
{
  if (iterator->done)
    abort ();
  assert (iterator->stmt->result);
  return PQgetisnull (iterator->stmt->result, iterator->stmt->current_row, col);
}

/**
 * @brief Rewind an iterator to the beginning.
 *
 * This lets the caller iterate over the data again.
 *
 * @param[in]  iterator  Iterator.
 */
void
iterator_rewind (iterator_t *iterator)
{
  iterator->done = FALSE;
  iterator->stmt->current_row = -1;
}


/* Statements. */

/**
 * @brief Free a statement.
 *
 * @param[in]  stmt  Statement.
 */
void
sql_finalize (sql_stmt_t *stmt)
{
  PQclear (stmt->result);
  g_free (stmt->sql);
  array_free (stmt->param_values);
  g_array_free (stmt->param_lengths, TRUE);
  g_array_free (stmt->param_formats, TRUE);
  g_free (stmt);
}

/**
 * @brief Return a column as a double from a statement.
 *
 * It's up to the caller to ensure that there is a row available.
 *
 * @param[in]  stmt      Statement.
 * @param[in]  position  Column position.
 *
 * @return 0 success, -1 error.
 */
double
sql_column_double (sql_stmt_t *stmt, int position)
{
  if (PQgetisnull (stmt->result, stmt->current_row, position))
    return 0.0;

  return atof (PQgetvalue (stmt->result, stmt->current_row, position));
}

/**
 * @brief Return a column as text from a statement.
 *
 * It's up to the caller to ensure that there is a row available.
 *
 * @param[in]  stmt      Statement.
 * @param[in]  position  Column position.
 *
 * @return Column value.  NULL if column is NULL.
 */
const char *
sql_column_text (sql_stmt_t *stmt, int position)
{
  if (PQgetisnull (stmt->result, stmt->current_row, position))
    return NULL;

  return (const char *) PQgetvalue (stmt->result, stmt->current_row, position);
}

/**
 * @brief Return a column as an integer from a statement.
 *
 * It's up to the caller to ensure that there is a row available.
 *
 * @param[in]  stmt      Statement.
 * @param[in]  position  Column position.
 *
 * @return Column value.  0 if column is NULL or false.  1 if column true.
 */
int
sql_column_int (sql_stmt_t *stmt, int position)
{
  char *cell;

  if (PQgetisnull (stmt->result, stmt->current_row, position))
    return 0;

  cell = PQgetvalue (stmt->result, stmt->current_row, position);

  switch (PQftype (stmt->result, position))
    {
    case 16: /* BOOLOID */
      return strcmp (cell, "f") ? 1 : 0;

    default:
      return atoi (cell);
    }
}

/**
 * @brief Return a column as an int64 from a statement.
 *
 * It's up to the caller to ensure that there is a row available.
 *
 * @param[in]  stmt      Statement.
 * @param[in]  position  Column position.
 *
 * @return Column value.  0 if column is NULL or false.  1 if column true.
 */
long long int
sql_column_int64 (sql_stmt_t *stmt, int position)
{
  char *cell;

  if (PQgetisnull (stmt->result, stmt->current_row, position))
    return 0;

  cell = PQgetvalue (stmt->result, stmt->current_row, position);

  switch (PQftype (stmt->result, position))
    {
    case 16: /* BOOLOID */
      return strcmp (cell, "f") ? 1 : 0;

    default:
      return atol (cell);
    }
}

/**
 * @brief Return a column as text from a statement.
 *
 * It's up to the caller to ensure that there is a row available.
 *
 * @param[in]  stmt      Statement.
 * @param[in]  position  Column position.
 *
 * @return Column value.  NULL if column is NULL.
 */
gchar **
sql_column_array (sql_stmt_t *stmt, int position)
{
  const char *text;

  if (PQgetisnull (stmt->result, stmt->current_row, position))
    return NULL;

  /* {DFN-CERT-2017-1238,DFN-CERT-2014-1366,DFN-CERT-2014-1354} */

  text = (const char *) PQgetvalue (stmt->result, stmt->current_row, position);
  if (text && text[0] == '{')
    {
      gchar **array, **point, **last;

      if (text[1] == '}')
        return (gchar **) g_malloc0 (sizeof (gchar *));

      array = g_strsplit (text + 1, ",", 0);
      point = last = array;
      while (*point)
        {
          last = point;
          point++;
        }
      if (*last)
        {
          gchar *last_element;

          last_element = *last;
          if (*last_element == '\0')
            /* Weird, last element should always have a }. */
            g_warning ("%s: last element missing closing }", __func__);
          else
            {
              while (*last_element)
                last_element++;
              last_element--;
              /* Clip the trailing }. */
              *last_element = '\0';
            }
        }
      return array;
    }

  /* This shouldn't happen. */
  assert (0);
  g_warning ("%s: array column not NULL and does not contain array", __func__);
  return NULL;
}

/**
 * @brief Cancels the current SQL statement.
 *
 * @return 0 on success, -1 on error.
 */
int
sql_cancel_internal ()
{
  PGcancel *cancel;
  char errbuf[256] = "";

  cancel = PQgetCancel (conn);
  if (cancel)
    {
      if (PQcancel (cancel, errbuf, 256))
        {
          log_errors = 0;
          PQfreeCancel (cancel);
        }
      else
        {
          PQfreeCancel (cancel);
          return -1;
        }
    }
  else
    {
      return -1;
    }

  return 0;
}

/**
 * @brief Check whether a table exists in a schema.
 *
 * @return 1 if exists, 0 if not exists, -1 on error.
 */
int
sql_table_exists (const gchar *schema, const gchar *table)
{
  const gchar *schema_name;

  if (table == NULL || *table == '\0')
    return -1;

  schema_name = (schema && *schema) ? schema : sql_schema ();

  return sql_int_ps (
    "SELECT EXISTS ("
    "  SELECT 1"
    "  FROM pg_catalog.pg_tables"
    "  WHERE schemaname = $1 AND tablename = $2"
    ");",
    SQL_STR_PARAM (schema_name),
    SQL_STR_PARAM (table),
    NULL);
}

/**
 * @brief Tries to transfer data for a COPY ... FROM STDIN statement.
 *
 * To finalize the data transfer for the statement, call sql_copy_end
 *  afterwards.
 *
 * @param[in]  str  The string to transfer.
 * @param[in]  len  Length of the string to write, -1 to use strlen.
 *
 * @return 0 success, -1 error.
 */
int
sql_copy_write_str (const char *str, int len)
{
  int put_copy_data_ret =
    PQputCopyData (conn, str, len >= 0 ? len : strlen (str));
  if (put_copy_data_ret == 0)
    {
      g_warning ("%s: could not send data: queue blocked", __func__);
      return -1;
    }
  else if (put_copy_data_ret != 1)
    {
      g_warning ("%s: could not send data: %s", __func__,
                 PQerrorMessage (conn));
    }

  return 0;
}

/**
 * @brief Tries to finalize the current COPY ... FROM STDIN data transfer.
 *
 * The data is only validated and written after calling this.
 *
 * @return 0 success, -1 error.
 */
int
sql_copy_end ()
{
  int put_copy_end_ret = PQputCopyEnd (conn, NULL);
  PGresult *result;
  if (put_copy_end_ret == 0)
    {
      g_warning ("%s: could not send end of data: queue blocked", __func__);
      return -1;
    }
  else if (put_copy_end_ret != 1)
    {
      g_warning ("%s: could not send end of data: %s", __func__,
                 PQerrorMessage (conn));
      return -1;
    }

  result = PQgetResult (conn);
  if (PQresultStatus (result) != PGRES_COMMAND_OK)
    {
      g_warning ("%s: PQexec failed: %s (%i)", __func__,
                 PQresultErrorMessage (result), PQresultStatus (result));
      PQclear (result);
      return -1;
    }

  PQclear (result);
  return 0;
}

/**
 * @brief Escapes a string for tab-delimited data of TEXT type COPY statements.
 *
 * @param[in]  str  The string to escape.
 *
 * @return The newly allocated, escaped copy of the string.
 */
gchar *
sql_copy_escape (const char *str)
{
  if (str == NULL)
    return NULL;

  gssize i;
  gssize len = strlen (str);
  GString *escaped = g_string_sized_new (len);

  for (i = 0; i < len; i++)
    {
      switch (str[i])
        {
        case '\\':
          g_string_append (escaped, "\\\\");
          break;
        case '\b':
          g_string_append (escaped, "\\b");
          break;
        case '\f':
          g_string_append (escaped, "\\f");
          break;
        case '\n':
          g_string_append (escaped, "\\n");
          break;
        case '\r':
          g_string_append (escaped, "\\r");
          break;
        case '\t':
          g_string_append (escaped, "\\t");
          break;
        case '\v':
          g_string_append (escaped, "\\v");
          break;
        default:
          g_string_append_c (escaped, str[i]);
        }
    }
  return g_string_free (escaped, FALSE);
}
