/* Copyright (C) 2009-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * @file
 * @brief Generic SQL interface
 *
 * This is a small generic interface for SQL database access.
 *
 * To add support for a specific database, like Postgres, a few functions
 * (for example, sql_prepare_internal and sql_exec_internal) need to be
 * implemented for that database.
 */

#include "sql.h"

#include "utils.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"
/**
 * @brief amount of ms sql should wait before retrying when a deadlock occurred
 */
#define DEADLOCK_SLEEP 1000

/**
 * @brief defines the amount of retries after a deadlock is considered a warning
 */
#define DEADLOCK_THRESHOLD 25


/* Headers of internal symbols defined in backend files. */

int
sql_cancel_internal ();

void
sql_prepare_internal (int, const char *, va_list, sql_stmt_t **);

void
sql_prepare_ps_internal (int, const char *, va_list, sql_stmt_t **);

sql_exec_status_t
sql_exec_internal (sql_stmt_t *);

void
sql_finalize (sql_stmt_t *);

double
sql_column_double (sql_stmt_t *, int);

const char *
sql_column_text (sql_stmt_t *, int);

int
sql_column_int (sql_stmt_t *, int);

long long int
sql_column_int64 (sql_stmt_t *, int);

gchar **
sql_column_array (sql_stmt_t *, int);


/* Variables. */

typedef struct
{
  sql_cancel_handler_t handler;
  void *data;
  pid_t pid;
} sql_cancel_context_t;

/**
 * @brief Thread-local handler for unwinding an expected query cancellation.
 */
static GPrivate cancel_context = G_PRIVATE_INIT (g_free);

/**
 * @brief Return the active query cancellation context for this process.
 *
 * A PID check prevents a child forked during a GMP request from using the
 * parent's cancellation boundary.
 *
 * @return Active cancellation context, or NULL.
 */
static sql_cancel_context_t *
sql_cancel_context ()
{
  sql_cancel_context_t *context;

  context = g_private_get (&cancel_context);
  if (context && context->pid == getpid ())
    return context;
  return NULL;
}


/* Helpers. */

/**
 * @brief Quotes a string of a known length to be passed to sql statements.
 *
 * @param[in]  string  String to quote.
 * @param[in]  length  Size of \p string.
 *
 * @return Freshly allocated, quoted string. Free with g_free.
 */
gchar *
sql_nquote (const char *string, size_t length)
{
  gchar *new, *new_start;
  const gchar *start, *end;
  int count = 0;

  assert (string);

  /* Count number of apostrophes. */

  start = string;
  while ((start = strchr (start, '\'')))
    start++, count++;

  /* Allocate new string. */

  new = new_start = g_malloc0 (length + count + 1);

  /* Copy string, replacing apostrophes with double apostrophes. */

  start = string;
  end = string + length;
  for (; start < end; start++, new ++)
    {
      char ch = *start;
      if (ch == '\'')
        {
          *new = '\'';
          new ++;
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
gchar *
sql_quote (const char *string)
{
  assert (string);
  return sql_nquote (string, strlen (string));
}

/**
 * @brief Quotes a string for use in SQL statements, also ASCII escaping it.
 *
 * The ASCII escaping excludes characters 0x80 - 0xFF for valid UTF-8 strings
 * and includes them otherwise.
 *
 * @param[in]  string       String to quote, has to be \\0 terminated.
 * @param[in]  exceptions   Optional exceptions for the escaping.
 *
 * @return Freshly allocated, quoted string. Free with g_free.
 */
gchar *
sql_ascii_escape_and_quote (const char *string, const char *exceptions)
{
  gchar *escaped_string;
  gchar *quoted_string;

  assert (string);

  if (string == NULL)
    return NULL;

  escaped_string = strescape_check_utf8 (string, exceptions);
  quoted_string = sql_quote (escaped_string);
  g_free (escaped_string);

  return quoted_string;
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
 * @brief Perform an SQL statement.
 *
 * If syntax set to 1, the sql template is expected to be in prepared
 * statement syntax and the parameters must be passed as sql_param_t
 * pointers with a NULL sentinel at the end.
 *
 * Otherwise the template should be a printf syntax format string with the
 * parameter values passed in directly.
 *
 * @see sql_param_t for more info about passing the parameters when
 *      using prepared statement syntax.
 *
 * @param[in]  syntax Expected syntax: 0 printf, 1 prepared statement.
 * @param[in]  sql    SQL statement template / format string.
 * @param[in]  args   Arguments to bind to template / format string.
 *
 * @return 0 success, 1 gave up (even when retry given),
 *         2 reserved (lock unavailable), 3 unique constraint violation,
 *         4 deadlock, -1 error.
 */
static int
sqlv (int syntax, const char *sql, va_list args)
{
  while (1)
    {
      int ret;
      sql_cancel_context_t *context;
      sql_stmt_t *stmt;
      va_list args_copy;

      /* Prepare statement.
       * Copy args for this because a va_list can only be used once.
       */
      va_copy (args_copy, args);
      if (syntax)
        sql_prepare_ps_internal (1, sql, args_copy, &stmt);
      else
        sql_prepare_internal (1, sql, args_copy, &stmt);
      va_end (args_copy);

      /* Run statement. */

      while ((ret = sql_exec_internal (stmt)) == SQL_EXEC_ROW)
        ;
      context = sql_cancel_context ();
      if (ret == SQL_EXEC_CANCELED)
        {
          if (context)
            {
              sql_finalize (stmt);
              context->handler (context->data);
              abort ();
            }
          sql_finalize (stmt);
          return -1;
        }
      if (ret == SQL_EXEC_ERROR)
        g_warning ("%s: sql_exec_internal failed", __func__);
      sql_finalize (stmt);
      if (ret == SQL_EXEC_RETRY)
        continue;
      if (ret == SQL_EXEC_GIVEUP)
        return 1;
      if (ret == SQL_EXEC_LOCK_UNAVAILABLE)
        return -1;
      if (ret == SQL_EXEC_UNIQUE)
        return 3;
      if (ret == SQL_EXEC_DEADLOCK)
        return 4;
      assert (ret == SQL_EXEC_ERROR || ret == SQL_EXEC_COMPLETE);
      return ret;
    }
}

/**
 * @brief Perform an SQL statement, retrying if database is busy or locked.
 *
 * If syntax set to 1, the sql template is expected to be in prepared
 * statement syntax and the parameters must be passed as sql_param_t
 * pointers with a NULL sentinel at the end.
 *
 * Otherwise the template should be a printf syntax format string with the
 * parameter values passed in directly.
 *
 * @see sql_param_t for more info about passing the parameters when
 *      using prepared statement syntax.
 *
 * @param[in]  syntax Expected syntax: 0 printf, 1 prepared statement
 * @param[in]  sql    SQL statement template / format string.
 * @param[in]  args   Arguments to bind to template / format string.
 */
static void
sql_internal (int syntax, const char *sql, va_list args)
{
  unsigned int deadlock_amount = 0;
  while (1)
    {
      int ret;

      ret = sqlv (syntax, sql, args);
      if (ret == 1)
        /* Gave up with statement reset. */
        continue;
      else if (ret == 4)
        {
          if (deadlock_amount++ > DEADLOCK_THRESHOLD)
            {
              g_warning ("%s: %d deadlocks detected, waiting and retrying %s",
                         __func__, deadlock_amount, sql);
            }
          gvm_usleep (DEADLOCK_SLEEP);
          continue;
        }
      else if (ret)
        abort ();
      break;
    }
}

/**
 * @brief Perform an SQL statement, retrying if database is busy or locked.
 *
 * @param[in]  sql    Format string for SQL statement.
 * @param[in]  ...    Arguments for format string.
 */
void
sql (const char *sql, ...)
{
  va_list args;
  va_start (args, sql);
  sql_internal (FALSE, sql, args);
  va_end (args);
}

/**
 * @brief Perform an SQL statement, retrying if database is busy or locked.
 *
 * The list of parameter values must be passed as pointers to
 *  sql_param_t structs and include a NULL sentinel at the end.
 *
 * @see sql_param_t for more info about passing the parameters.
 *
 * @param[in]  sql    SQL statement template in prepared statement syntax.
 * @param[in]  ...    Statement parameters, terminated with NULL sentinel.
 */
void
sql_ps (const char *sql, ...)
{
  va_list args;
  va_start (args, sql);
  sql_internal (TRUE, sql, args);
  va_end (args);
}

/**
 * @brief Cancels the current SQL statement.
 *
 * @return 0 on success, -1 on error.
 */
int
sql_cancel ()
{
  g_debug ("%s: cancelling current SQL statement", __func__);
  return sql_cancel_internal ();
}

/**
 * @brief Set a handler for unwinding an expected query cancellation.
 *
 * The handler must not return.  It is intended for same-thread non-local
 * unwinding from a request that will close its connection and terminate.
 *
 * @param[in]  handler  Cancellation handler.
 * @param[in]  data     Data passed to the handler.
 */
void
sql_cancel_handler_set (sql_cancel_handler_t handler, void *data)
{
  sql_cancel_context_t *context;

  assert (handler);
  context = g_new (sql_cancel_context_t, 1);
  context->handler = handler;
  context->data = data;
  context->pid = getpid ();
  g_private_replace (&cancel_context, context);
}

/**
 * @brief Clear the query cancellation handler.
 */
void
sql_cancel_handler_clear ()
{
  g_private_replace (&cancel_context, NULL);
}

/**
 * @brief Perform an SQL statement, retrying if database is busy or locked.
 *
 * Return on error, instead of aborting.
 *
 * If syntax set to 1, the sql template is expected to be in prepared
 * statement syntax and the parameters must be passed as sql_param_t
 * pointers with a NULL sentinel at the end.
 *
 * Otherwise the template should be a printf syntax format string with the
 * parameter values passed in directly.
 *
 * @see sql_param_t for more info about passing the parameters when
 *      using prepared statement syntax.
 *
 * @param[in]  syntax Expected syntax: 0 printf, 1 prepared statement
 * @param[in]  sql    SQL statement template / format string.
 * @param[in]  args   Arguments to bind to template / format string.
 *
 * @return 0 success, 2 reserved (lock unavailable),
 *         3 unique constraint violation, -1 error.
 */
static int
sql_error_internal (int syntax, const char *sql, va_list args)
{
  int ret;

  while (1)
    {
      ret = sqlv (syntax, sql, args);
      if (ret == 1)
        /* Gave up with statement reset. */
        continue;
      if (ret == -4)
        return 3;
      break;
    }

  return ret;
}

/**
 * @brief Perform an SQL statement, retrying if database is busy or locked.
 *
 * Return on error, instead of aborting.
 *
 * @param[in]  sql    Format string for SQL statement.
 * @param[in]  ...    Arguments for format string.
 *
 * @return 0 success, 2 reserved (lock unavailable),
 *         3 unique constraint violation, -1 error.
 */
int
sql_error (const char *sql, ...)
{
  int ret;
  va_list args;
  va_start (args, sql);
  ret = sql_error_internal (FALSE, sql, args);
  va_end (args);
  return ret;
}

/**
 * @brief Perform an SQL statement, retrying if database is busy or locked.
 *
 * Return on error, instead of aborting.
 *
 * The list of parameter values must be passed as pointers to
 *  sql_param_t structs and include a NULL sentinel at the end.
 *
 * @see sql_param_t for more info about passing the parameters.
 *
 * @param[in]  sql    SQL statement template in prepared statement syntax.
 * @param[in]  ...    Statement parameters, terminated with NULL sentinel.
 *
 * @return 0 success, 2 reserved (lock unavailable),
 *         3 unique constraint violation, -1 error.
 */
int
sql_error_ps (const char *sql, ...)
{
  int ret;
  va_list args;
  va_start (args, sql);
  ret = sql_error_internal (TRUE, sql, args);
  va_end (args);
  return ret;
}

/**
 * @brief Perform an SQL statement, giving up if database is busy or locked.
 *
 * If syntax set to 1, the sql template is expected to be in prepared
 * statement syntax and the parameters must be passed as sql_param_t
 * pointers with a NULL sentinel at the end.
 *
 * Otherwise the template should be a printf syntax format string with the
 * parameter values passed in directly.
 *
 * @see sql_param_t for more info about passing the parameters when
 *      using prepared statement syntax.
 *
 * @param[in]  syntax Expected syntax: 0 printf, 1 prepared statement
 * @param[in]  sql    SQL statement template / format string.
 * @param[in]  args   Arguments to bind to template / format string.
 *
 * @return 0 success, 1 gave up,
 *         2 reserved (lock unavailable), 3 unique constraint violation,
 *         -1 error.
 */
static int
sql_giveup_internal (int syntax, const char *sql, va_list args)
{
  int ret;
  ret = sqlv (syntax, sql, args);
  return ret;
}

/**
 * @brief Perform an SQL statement, giving up if database is busy or locked.
 *
 * @param[in]  sql    Format string for SQL statement.
 * @param[in]  ...    Arguments for format string.
 *
 * @return 0 success, 1 gave up,
 *         2 reserved (lock unavailable), 3 unique constraint violation,
 *         -1 error.
 */
int
sql_giveup (const char *sql, ...)
{
  int ret;
  va_list args;
  va_start (args, sql);
  ret = sql_giveup_internal (FALSE, sql, args);
  va_end (args);
  return ret;
}

/**
 * @brief Perform an SQL statement, giving up if database is busy or locked.
 *
 * The list of parameter values must be passed as pointers to
 *  sql_param_t structs and include a NULL sentinel at the end.
 *
 * @see sql_param_t for more info about passing the parameters.
 *
 * @param[in]  sql    SQL statement template in prepared statement syntax.
 * @param[in]  ...    Statement parameters, terminated with NULL sentinel.
 *
 * @return 0 success, 1 gave up,
 *         2 reserved (lock unavailable), 3 unique constraint violation,
 *         -1 error.
 */
int
sql_giveup_ps (const char *sql, ...)
{
  int ret;
  va_list args;
  va_start (args, sql);
  ret = sql_giveup_internal (TRUE, sql, args);
  va_end (args);
  return ret;
}

/**
 * @brief Prepare and execute an SQL statement.
 *
 * If syntax set to 1, the sql template is expected to be in prepared
 * statement syntax and the parameters must be passed as sql_param_t
 * pointers with a NULL sentinel at the end.
 *
 * Otherwise the template should be a printf syntax format string with the
 * parameter values passed in directly.
 *
 * @see sql_param_t for more info about passing the parameters when
 *      using prepared statement syntax.
 *
 * @param[in]   syntax       Expected syntax: 0 printf, 1 prepared statement
 * @param[in]   sql          SQL statement template / format string.
 * @param[in]   args         Arguments to bind to template / format string.
 * @param[out]  stmt_return  Return from statement.
 *
 * @return 0 success, 1 too few rows, -1 error.
 */
int
sql_x (int syntax, const char *sql, va_list args, sql_stmt_t **stmt_return)
{
  int ret;
  sql_cancel_context_t *context;
  unsigned int deadlock_amount = 0;

  assert (stmt_return);

  while (1)
    {
      /* Prepare statement.
       * Copy args for this because a va_list can only be used once.
       */
      va_list args_copy;
      va_copy (args_copy, args);
      if (syntax)
        sql_prepare_ps_internal (1, sql, args_copy, stmt_return);
      else
        sql_prepare_internal (1, sql, args_copy, stmt_return);
      va_end (args_copy);

      /* Run statement. */

      ret = sql_exec_internal (*stmt_return);
      if (ret == SQL_EXEC_CANCELED)
        {
          context = sql_cancel_context ();
          if (context)
            {
              sql_finalize (*stmt_return);
              context->handler (context->data);
              abort ();
            }
          return -1;
        }
      if (ret == SQL_EXEC_ERROR || ret == SQL_EXEC_UNIQUE)
        {
          g_warning ("%s: sql_exec_internal failed", __func__);
          return -1;
        }
      if (ret == SQL_EXEC_COMPLETE)
        /* Too few rows. */
        return 1;
      if (ret == SQL_EXEC_LOCK_UNAVAILABLE || ret == SQL_EXEC_GIVEUP
          || ret == SQL_EXEC_RETRY)
        {
          /* Busy or locked, with statement reset.  Or schema changed. */
          sql_finalize (*stmt_return);
          continue;
        }
      if (ret == SQL_EXEC_DEADLOCK)
        {
          if (deadlock_amount++ > DEADLOCK_THRESHOLD)
            {
              g_warning ("%s: %d deadlocks detected, waiting and retrying %s",
                         __func__, deadlock_amount, sql);
            }
          gvm_usleep (DEADLOCK_SLEEP);
          continue;
        }
      break;
    }
  assert (ret == SQL_EXEC_ROW);
  g_debug ("   sql_x end (%s)", sql);
  return 0;
}

/**
 * @brief Get the first column of first row from a SQL query, as a double.
 *
 * If syntax set to 1, the sql template is expected to be in prepared
 * statement syntax and the parameters must be passed as sql_param_t
 * pointers with a NULL sentinel at the end.
 *
 * Otherwise the template should be a printf syntax format string with the
 * parameter values passed in directly.
 *
 * @see sql_param_t for more info about passing the parameters when
 *      using prepared statement syntax.
 *
 * @warning Aborts on invalid queries.
 *
 * @warning Aborts when the query returns fewer rows than \p row.  The
 *          caller must ensure that the query will return sufficient rows.
 *
 * @param[in]  syntax Expected syntax: 0 printf, 1 prepared statement
 * @param[in]  sql    SQL statement template / format string.
 * @param[in]  args   Arguments to bind to template / format string.
 *
 * @return Result of the query as an integer.
 */
double
sql_double_internal (int syntax, const char *sql, va_list args)
{
  sql_stmt_t *stmt;
  double ret;

  int sql_x_ret;
  sql_x_ret = sql_x (syntax, sql, args, &stmt);
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
 * @brief Get the first column of first row from a SQL query, as a double.
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
sql_double (const char *sql, ...)
{
  va_list args;
  double ret;

  va_start (args, sql);
  ret = sql_double_internal (FALSE, sql, args);
  va_end (args);
  return ret;
}

/**
 * @brief Get the first column of first row from a SQL query, as a double.
 *
 * The list of parameter values must be passed as pointers to
 *  sql_param_t structs and include a NULL sentinel at the end.
 *
 * @see sql_param_t for more info about passing the parameters.
 *
 * @warning Aborts on invalid queries.
 *
 * @warning Aborts when the query returns fewer rows than \p row.  The
 *          caller must ensure that the query will return sufficient rows.
 *
 * @param[in]  sql    SQL statement template in prepared statement syntax.
 * @param[in]  ...    Statement parameters, terminated with NULL sentinel.
 *
 * @return Result of the query as an integer.
 */
double
sql_double_ps (const char *sql, ...)
{
  va_list args;
  double ret;

  va_start (args, sql);
  ret = sql_double_internal (TRUE, sql, args);
  va_end (args);
  return ret;
}

/**
 * @brief Get the first column of first row from a SQL query, as an int.
 *
 * If syntax set to 1, the sql template is expected to be in prepared
 * statement syntax and the parameters must be passed as sql_param_t
 * pointers with a NULL sentinel at the end.
 *
 * Otherwise the template should be a printf syntax format string with the
 * parameter values passed in directly.
 *
 * @see sql_param_t for more info about passing the parameters when
 *      using prepared statement syntax.
 *
 * @warning Aborts on invalid queries.
 *
 * @warning Aborts when the query returns fewer rows than \p row.  The
 *          caller must ensure that the query will return sufficient rows.
 *
 * @param[in]  syntax Expected syntax: 0 printf, 1 prepared statement
 * @param[in]  sql    SQL statement template / format string.
 * @param[in]  args   Arguments to bind to template / format string.
 *
 * @return Result of the query as an integer.
 */
static int
sql_int_internal (int syntax, const char *sql, va_list args)
{
  sql_stmt_t *stmt;
  int ret;

  int sql_x_ret;
  sql_x_ret = sql_x (syntax, sql, args, &stmt);
  if (sql_x_ret)
    {
      sql_finalize (stmt);
      abort ();
    }
  ret = sql_column_int (stmt, 0);
  sql_finalize (stmt);
  return ret;
}

/**
 * @brief Get the first column of first row from a SQL query, as an int.
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
sql_int (const char *sql, ...)
{
  va_list args;
  int ret;

  va_start (args, sql);
  ret = sql_int_internal (FALSE, sql, args);
  va_end (args);
  return ret;
}

/**
 * @brief Get the first column of first row from a SQL query, as an int.
 *
 * The list of parameter values must be passed as pointers to
 *  sql_param_t structs and include a NULL sentinel at the end.
 *
 * @see sql_param_t for more info about passing the parameters.
 *
 * @warning Aborts on invalid queries.
 *
 * @warning Aborts when the query returns fewer rows than \p row.  The
 *          caller must ensure that the query will return sufficient rows.
 *
 * @param[in]  sql    SQL statement template in prepared statement syntax.
 * @param[in]  ...    Statement parameters, terminated with NULL sentinel.
 *
 * @return Result of the query as an integer.
 */
int
sql_int_ps (const char *sql, ...)
{
  va_list args;
  int ret;

  va_start (args, sql);
  ret = sql_int_internal (TRUE, sql, args);
  va_end (args);
  return ret;
}

/**
 * @brief Get the first column of first row from a SQL query, as a string.
 *
 * If syntax set to 1, the sql template is expected to be in prepared
 * statement syntax and the parameters must be passed as sql_param_t
 * pointers with a NULL sentinel at the end.
 *
 * Otherwise the template should be a printf syntax format string with the
 * parameter values passed in directly.
 *
 * @see sql_param_t for more info about passing the parameters when
 *      using prepared statement syntax.
 *
 * @param[in]  syntax Expected syntax: 0 printf, 1 prepared statement
 * @param[in]  sql    SQL statement template / format string.
 * @param[in]  args   Arguments to bind to template / format string.
 *
 * @return Freshly allocated string containing the result, NULL otherwise.
 *         NULL means that either the selected value was NULL or there were
 *         no rows in the result.
 */
char *
sql_string_internal (int syntax, const char *sql, va_list args)
{
  sql_stmt_t *stmt;
  const char *ret2;
  char *ret;
  int sql_x_ret;

  sql_x_ret = sql_x (syntax, sql, args, &stmt);
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
 * @brief Get a the first value from a SQL query, as an string.
 *
 * @param[in]  sql    Format string for SQL query.
 * @param[in]  ...    Arguments for format string.
 *
 * @return Freshly allocated string containing the result, NULL otherwise.
 *         NULL means that either the selected value was NULL or there were
 *         no rows in the result.
 */
char *
sql_string (const char *sql, ...)
{
  va_list args;
  char *ret;

  va_start (args, sql);
  ret = sql_string_internal (FALSE, sql, args);
  va_end (args);
  return ret;
}

/**
 * @brief Get the first column of first row from a SQL query, as a string.
 *
 * The list of parameter values must be passed as pointers to
 *  sql_param_t structs and include a NULL sentinel at the end.
 *
 * @see sql_param_t for more info about passing the parameters.
 *
 * @param[in]  sql    SQL statement template in prepared statement syntax.
 * @param[in]  ...    Statement parameters, terminated with NULL sentinel.
 *
 * @return Freshly allocated string containing the result, NULL otherwise.
 *         NULL means that either the selected value was NULL or there were
 *         no rows in the result.
 */
char *
sql_string_ps (const char *sql, ...)
{
  va_list args;
  char *ret;

  va_start (args, sql);
  ret = sql_string_internal (TRUE, sql, args);
  va_end (args);
  return ret;
}

/**
 * @brief Get the first column of first row from a SQL query, as an int64.
 *
 * If syntax set to 1, the sql template is expected to be in prepared
 * statement syntax and the parameters must be passed as sql_param_t
 * pointers with a NULL sentinel at the end.
 *
 * Otherwise the template should be a printf syntax format string with the
 * parameter values passed in directly.
 *
 * @see sql_param_t for more info about passing the parameters when
 *      using prepared statement syntax.
 *
 * @param[in]  syntax Expected syntax: 0 printf, 1 prepared statement
 * @param[in]  ret    Return value.
 * @param[in]  sql    SQL statement template / format string.
 * @param[in]  args   Arguments to bind to template / format string.
 *
 * @return 0 success, 1 too few rows, -1 error.
 */
static int
sql_int64_internal (int syntax, long long int *ret, const char *sql,
                    va_list args)
{
  sql_stmt_t *stmt;
  int sql_x_ret;

  sql_x_ret = sql_x (syntax, sql, args, &stmt);
  switch (sql_x_ret)
    {
    case 0:
      break;
    case 1:
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
  *ret = sql_column_int64 (stmt, 0);
  sql_finalize (stmt);
  return 0;
}

/**
 * @brief Get the first column of first row from a SQL query, as an int64.
 *
 * @param[in]  ret    Return value.
 * @param[in]  sql    Format string for SQL query.
 * @param[in]  ...    Arguments for format string.
 *
 * @return 0 success, 1 too few rows, -1 error.
 */
int
sql_int64 (long long int *ret, const char *sql, ...)
{
  va_list args;
  int ret2;

  va_start (args, sql);
  ret2 = sql_int64_internal (FALSE, ret, sql, args);
  va_end (args);
  return ret2;
}

/**
 * @brief Get the first column of first row from a SQL query, as an int64.
 *
 * The list of parameter values must be passed as pointers to
 *  sql_param_t structs and include a NULL sentinel at the end.
 *
 * @see sql_param_t for more info about passing the parameters.
 *
 * @param[in]  ret    Return value.
 * @param[in]  sql    SQL statement template in prepared statement syntax.
 * @param[in]  ...    Statement parameters, terminated with NULL sentinel.
 *
 * @return 0 success, 1 too few rows, -1 error.
 */
int
sql_int64_ps (long long int *ret, const char *sql, ...)
{
  va_list args;
  int ret2;

  va_start (args, sql);
  ret2 = sql_int64_internal (TRUE, ret, sql, args);
  va_end (args);
  return ret2;
}

/**
 * @brief Get the first column of first row from a SQL query, as an int64.
 *
 * Return 0 on error.
 *
 * If syntax set to 1, the sql template is expected to be in prepared
 * statement syntax and the parameters must be passed as sql_param_t
 * pointers with a NULL sentinel at the end.
 *
 * Otherwise the template should be a printf syntax format string with the
 * parameter values passed in directly.
 *
 * @see sql_param_t for more info about passing the parameters when
 *      using prepared statement syntax.
 *
 * @param[in]  syntax Expected syntax: 0 printf, 1 prepared statement
 * @param[in]  sql    SQL statement template / format string.
 * @param[in]  args   Arguments to bind to template / format string.
 *
 * @return Column value.  0 if no row.
 */
static long long int
sql_int64_0_internal (int syntax, const char *sql, va_list args)
{
  sql_stmt_t *stmt;
  int sql_x_ret;
  long long int ret;

  sql_x_ret = sql_x (syntax, sql, args, &stmt);
  if (sql_x_ret)
    {
      sql_finalize (stmt);
      return 0;
    }
  ret = sql_column_int64 (stmt, 0);
  sql_finalize (stmt);
  return ret;
}

/**
 * @brief Get the first column of first row from a SQL query, as an int64.
 *
 * Return 0 on error.
 *
 * @param[in]  sql    Format string for SQL query.
 * @param[in]  ...    Arguments for format string.
 *
 * @return Column value.  0 if no row.
 */
long long int
sql_int64_0 (const char *sql, ...)
{
  va_list args;
  long long int ret;

  va_start (args, sql);
  ret = sql_int64_0_internal (FALSE, sql, args);
  va_end (args);
  return ret;
}

/**
 * @brief Get the first column of first row from a SQL query, as an int64.
 *
 * Return 0 on error.
 *
 * The list of parameter values must be passed as pointers to
 *  sql_param_t structs and include a NULL sentinel at the end.
 *
 * @see sql_param_t for more info about passing the parameters.
 *
 * @param[in]  sql    SQL statement template in prepared statement syntax.
 * @param[in]  ...    Statement parameters, terminated with NULL sentinel.
 *
 * @return Column value.  0 if no row.
 */
long long int
sql_int64_0_ps (const char *sql, ...)
{
  va_list args;
  long long int ret;

  va_start (args, sql);
  ret = sql_int64_0_internal (TRUE, sql, args);
  va_end (args);
  return ret;
}


/* Iterators. */

/**
 * @brief Initialise an iterator.
 *
 * If syntax set to 1, the sql template is expected to be in prepared
 * statement syntax and the parameters must be passed as sql_param_t
 * pointers with a NULL sentinel at the end.
 *
 * Otherwise the template should be a printf syntax format string with the
 * parameter values passed in directly.
 *
 * @see sql_param_t for more info about passing the parameters when
 *      using prepared statement syntax.
 *
 * @param[in]  syntax    Expected syntax: 0 printf, 1 prepared statement
 * @param[in]  iterator  Iterator.
 * @param[in]  sql       SQL statement template / format string.
 * @param[in]  args      Arguments to bind to template / format string.
 */
static void
init_iterator_internal (int syntax, iterator_t *iterator, const char *sql,
                        va_list args)
{
  sql_stmt_t *stmt;

  iterator->done = FALSE;
  iterator->crypt_ctx = NULL;

  if (syntax)
    sql_prepare_ps_internal (1, sql, args, &stmt);
  else
    sql_prepare_internal (1, sql, args, &stmt);

  iterator->stmt = stmt;
}

/**
 * @brief Initialise an iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  sql       Format string for SQL.
 */
void
init_iterator (iterator_t *iterator, const char *sql, ...)
{
  va_list args;
  va_start (args, sql);
  init_iterator_internal (FALSE, iterator, sql, args);
  va_end (args);
}

/**
 * @brief Initialise an iterator using prepared statement syntax.
 *
 * The list of parameter values must be passed as pointers to
 *  sql_param_t structs and include a NULL sentinel at the end.
 *
 * @see sql_param_t for more info about passing the parameters.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  sql       SQL template using prepared statement syntex.
 * @param[in]  ...       Statement parameters, terminated with NULL sentinel.
 */
void
init_ps_iterator (iterator_t *iterator, const char *sql, ...)
{
  va_list args;
  va_start (args, sql);
  init_iterator_internal (TRUE, iterator, sql, args);
  va_end (args);
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
iterator_double (iterator_t *iterator, int col)
{
  if (iterator->done)
    abort ();
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
iterator_int (iterator_t *iterator, int col)
{
  if (iterator->done)
    abort ();
  return sql_column_int (iterator->stmt, col);
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
iterator_int64 (iterator_t *iterator, int col)
{
  if (iterator->done)
    abort ();
  return sql_column_int64 (iterator->stmt, col);
}

/**
 * @brief Get a string column from an iterator.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  col       Column offset.
 *
 * @return Value of given column.
 */
const char *
iterator_string (iterator_t *iterator, int col)
{
  if (iterator->done)
    abort ();
  return sql_column_text (iterator->stmt, col);
}

/**
 * @brief Get a string column from an iterator.
 *
 * Note that sql_column_array gets the array as text and parses that text
 * into an array, but it does not consider escaping so it probably will
 * not work with strings that can contain commas, '{'s or '}'s.
 *
 * @param[in]  iterator  Iterator.
 * @param[in]  col       Column offset.
 *
 * @return Value of given column.
 */
gchar **
iterator_array (iterator_t *iterator, int col)
{
  if (iterator->done)
    abort ();
  return sql_column_array (iterator->stmt, col);
}

/**
 * @brief Cleanup an iterator.
 *
 * @param[in]  iterator  Iterator.
 */
void
cleanup_iterator (iterator_t *iterator)
{
  if (iterator == NULL)
    {
      g_warning ("%s: null iterator pointer", __func__);
      return;
    }

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
next (iterator_t *iterator)
{
  int ret;
  sql_cancel_context_t *context;

  if (iterator->done)
    return FALSE;

  if (iterator->crypt_ctx)
    lsc_crypt_flush (iterator->crypt_ctx);
  while (1)
    {
      ret = sql_exec_internal (iterator->stmt);
      if (ret == SQL_EXEC_COMPLETE)
        {
          iterator->done = TRUE;
          return FALSE;
        }
      if (ret == SQL_EXEC_CANCELED)
        {
          cleanup_iterator (iterator);
          context = sql_cancel_context ();
          if (context)
            {
              context->handler (context->data);
              abort ();
            }
          abort ();
        }
      if (ret == SQL_EXEC_ERROR || ret == SQL_EXEC_UNIQUE)
        {
          g_warning ("%s: sql_exec_internal failed", __func__);
          abort ();
        }
      if (ret == SQL_EXEC_LOCK_UNAVAILABLE || ret == SQL_EXEC_GIVEUP)
        {
          /* Busy or locked, with statement reset.  Just try step again like
           * we used to do in sql_exec_internal. */
          g_warning ("%s: stepping after reset", __func__);
          continue;
        }
      break;
    }
  assert (ret == SQL_EXEC_ROW);
  return TRUE;
}
