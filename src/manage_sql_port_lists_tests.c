
/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_port_lists.c"

#include <cgreen/cgreen.h>

Describe (manage_sql_port_lists);

static int sql_int64_ps_result;
static int rollback_count;

BeforeEach (manage_sql_port_lists)
{
  current_credentials.uuid = g_strdup ("test-user");
  sql_int64_ps_result = 1;
  rollback_count = 0;
}

AfterEach (manage_sql_port_lists)
{
  g_clear_pointer (&current_credentials.uuid, g_free);
}

int
__wrap_acl_user_may (const char *permission)
{
  (void) permission;
  return 1;
}

void
__wrap_sql_begin_immediate ()
{
}

void
__wrap_sql_rollback ()
{
  rollback_count++;
}

gchar *
__wrap_sql_quote (const char *string)
{
  return g_strdup (string);
}

int
__wrap_sql_int (const char *sql, ...)
{
  (void) sql;
  return 0;
}

int
__wrap_sql_int64_ps (long long int *ret, const char *sql, ...)
{
  (void) ret;
  (void) sql;
  return sql_int64_ps_result;
}

Ensure (manage_sql_port_lists, delete_port_range_returns_not_found)
{
  assert_that (delete_port_range ("nonexistent-port-range", 0),
               is_equal_to (2));
  assert_that (rollback_count, is_equal_to (1));
}

Ensure (manage_sql_port_lists, delete_port_range_returns_database_error)
{
  sql_int64_ps_result = -1;

  assert_that (delete_port_range ("test-port-range", 0),
               is_equal_to (-1));
  assert_that (rollback_count, is_equal_to (1));
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, manage_sql_port_lists,
                         delete_port_range_returns_not_found);
  add_test_with_context (suite, manage_sql_port_lists,
                         delete_port_range_returns_database_error);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
