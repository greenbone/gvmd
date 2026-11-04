/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "sql.h"

#include <cgreen/cgreen.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

Describe (sql);

static jmp_buf cancel_environment;
static int cancel_handler_calls;
static gboolean force_exec_status;
static sql_exec_status_t forced_exec_status;

sql_exec_status_t
__real_sql_exec_internal (sql_stmt_t *stmt);

sql_exec_status_t
__wrap_sql_exec_internal (sql_stmt_t *stmt)
{
  if (force_exec_status)
    return forced_exec_status;
  return __real_sql_exec_internal (stmt);
}

static void
jump_on_cancel (void *data)
{
  int *calls = data;

  (*calls)++;
  longjmp (cancel_environment, 1);
}

static void
exit_on_cancel (void *data)
{
  (void) data;
  _exit (77);
}

BeforeEach (sql)
{
  cancel_handler_calls = 0;
  force_exec_status = FALSE;
  sql_cancel_handler_clear ();
}

AfterEach (sql)
{
  sql_cancel_handler_clear ();
  force_exec_status = FALSE;
}

Ensure (sql, classifies_postgresql_query_canceled)
{
  assert_that (sql_pg_error_status ("57014"), is_equal_to (SQL_EXEC_CANCELED));
  assert_that (sql_pg_error_status ("42601"), is_equal_to (SQL_EXEC_ERROR));
  assert_that (sql_pg_error_status (NULL), is_equal_to (SQL_EXEC_ERROR));
}

Ensure (sql, canceled_scalar_unwinds_active_request)
{
  forced_exec_status = SQL_EXEC_CANCELED;
  force_exec_status = TRUE;

  if (setjmp (cancel_environment) == 0)
    {
      sql_cancel_handler_set (jump_on_cancel, &cancel_handler_calls);
      (void) sql_int ("SELECT 1;");
      assert_that (1, is_equal_to (0));
    }

  sql_cancel_handler_clear ();
  assert_that (cancel_handler_calls, is_equal_to (1));
}

Ensure (sql, canceled_iterator_unwinds_active_request)
{
  iterator_t iterator;

  forced_exec_status = SQL_EXEC_CANCELED;
  force_exec_status = TRUE;
  init_iterator (&iterator, "SELECT 1;");

  if (setjmp (cancel_environment) == 0)
    {
      sql_cancel_handler_set (jump_on_cancel, &cancel_handler_calls);
      (void) next (&iterator);
      assert_that (1, is_equal_to (0));
    }

  sql_cancel_handler_clear ();
  assert_that (cancel_handler_calls, is_equal_to (1));
}

Ensure (sql, canceled_helpers_keep_legacy_errors_without_boundary)
{
  long long value = 42;

  forced_exec_status = SQL_EXEC_CANCELED;
  force_exec_status = TRUE;

  assert_that (sql_error ("SELECT 1;"), is_equal_to (-1));
  assert_that (sql_giveup ("SELECT 1;"), is_equal_to (-1));
  assert_that (sql_int64 (&value, "SELECT 1;"), is_equal_to (-1));
  assert_that (value, is_equal_to (42));
  assert_that (cancel_handler_calls, is_equal_to (0));
}

Ensure (sql, request_boundary_is_not_active_in_forked_child)
{
  int status;
  pid_t pid;

  sql_cancel_handler_set (exit_on_cancel, NULL);
  pid = fork ();
  assert_that (pid, is_not_equal_to (-1));
  if (pid == 0)
    {
      int ret;

      forced_exec_status = SQL_EXEC_CANCELED;
      force_exec_status = TRUE;
      ret = sql_error ("SELECT 1;");
      _exit (ret == -1 ? 0 : 1);
    }

  assert_that (waitpid (pid, &status, 0), is_equal_to (pid));
  assert_that (WIFEXITED (status), is_true);
  assert_that (WEXITSTATUS (status), is_equal_to (0));
}

Ensure (sql, unrelated_scalar_error_still_aborts)
{
  int status;
  pid_t pid;

  pid = fork ();
  assert_that (pid, is_not_equal_to (-1));
  if (pid == 0)
    {
      struct rlimit core_limit = {0, 0};

      setrlimit (RLIMIT_CORE, &core_limit);
      close (STDERR_FILENO);
      forced_exec_status = SQL_EXEC_ERROR;
      force_exec_status = TRUE;
      (void) sql_int ("SELECT invalid;");
      _exit (0);
    }

  assert_that (waitpid (pid, &status, 0), is_equal_to (pid));
  assert_that (WIFSIGNALED (status), is_true);
  assert_that (WTERMSIG (status), is_equal_to (SIGABRT));
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, sql, classifies_postgresql_query_canceled);
  add_test_with_context (suite, sql, canceled_scalar_unwinds_active_request);
  add_test_with_context (suite, sql, canceled_iterator_unwinds_active_request);
  add_test_with_context (suite, sql,
                         canceled_helpers_keep_legacy_errors_without_boundary);
  add_test_with_context (suite, sql,
                         request_boundary_is_not_active_in_forked_child);
  add_test_with_context (suite, sql, unrelated_scalar_error_still_aborts);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
