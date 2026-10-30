/* Copyright (C) 2020-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql.c"

#include <cgreen/cgreen.h>
#include <sys/wait.h>
#include <unistd.h>

Describe (manage_sql);
static int fake_sql_open;
static int sql_close_calls;

int
__wrap_sql_is_open ()
{
  return fake_sql_open;
}

void
__wrap_sql_close ()
{
  fake_sql_open = 0;
  sql_close_calls++;
}

BeforeEach (manage_sql)
{
  fake_sql_open = 0;
  sql_close_calls = 0;
}
AfterEach (manage_sql) {}

static void
verify_canceled_worker_exit_cleanup ()
{
  cleanup_manage_process (TRUE);
  if (fake_sql_open || sql_close_calls != 1 || current_scanner_task != 0
      || global_current_report != 0)
    _exit (1);
}

Ensure (manage_sql, canceled_worker_exit_skips_request_task_cleanup)
{
  int status;
  pid_t pid;

  pid = fork ();
  assert_that (pid, is_not_equal_to (-1));
  if (pid == 0)
    {
      fake_sql_open = 1;
      current_scanner_task = 23;
      global_current_report = 42;

      if (atexit (verify_canceled_worker_exit_cleanup))
        _exit (2);
      cleanup_manage_process_canceled ();
      exit (EXIT_SUCCESS);
    }

  assert_that (waitpid (pid, &status, 0), is_equal_to (pid));
  assert_that (WIFEXITED (status), is_true);
  assert_that (WEXITSTATUS (status), is_equal_to (EXIT_SUCCESS));
}

/* truncate_text */

#define PASS(port) assert_that (validate_results_port (port), is_equal_to (0))
#define FAIL(port) assert_that (validate_results_port (port), is_equal_to (1))

Ensure (manage_sql, validate_results_port_validates)
{
  PASS ("cpe:/a:.joomclan:com_joomclip");
  PASS ("cpe:two");
  PASS ("general/tcp");
  PASS ("general/udp");
  PASS ("general/Host_Details");
  PASS ("20/udp");
  PASS ("20/UDP");
  PASS ("20/dccp");
  PASS ("1/tcp");
  PASS ("8080/tcp");
  PASS ("65535/tcp");
  PASS ("package");

  FAIL (NULL);
  FAIL ("cpe:/a:.joomclan:com_joomclip cpe:two");
  FAIL ("0/tcp");
  FAIL ("65536/tcp");
  FAIL ("20/tcp (IANA: ftp-data)");
  FAIL ("20/tcp,21/tcp");
  FAIL ("20/tcp;21/tcp");
  FAIL ("20/tcp 21/tcp");
  FAIL ("20-21/tcp");
  FAIL ("20/tcp-21/tcp");
  FAIL ("-1/tcp");
  FAIL ("ftp-data (20/tcp)");
  FAIL ("80");
  FAIL ("ftp-data");
  FAIL ("udp");
}

/* ensure_term_has_qod_and_overrides */

Ensure (manage_sql, ensure_term_has_qod_and_overrides_adds_defaults)
{
  gchar *term;

  // Test with NULL input
  term = ensure_term_has_qod_and_overrides (NULL);
  assert_that (term, contains_string ("min_qod="));
  assert_that (term, contains_string ("apply_overrides="));
  g_free (term);

  // Test with empty string
  term = ensure_term_has_qod_and_overrides (g_strdup (""));
  assert_that (term, contains_string ("min_qod="));
  assert_that (term, contains_string ("apply_overrides="));
  g_free (term);

  // Test with existing filter but no min_qod or apply_overrides
  term = ensure_term_has_qod_and_overrides (g_strdup ("severity>5"));
  assert_that (term, contains_string ("min_qod="));
  assert_that (term, contains_string ("apply_overrides="));
  assert_that (term, contains_string ("severity>5"));
  g_free (term);

  // Test with existing min_qod but no apply_overrides
  term = ensure_term_has_qod_and_overrides (g_strdup ("min_qod=50"));
  assert_that (term, contains_string ("min_qod=50"));
  assert_that (term, contains_string ("apply_overrides="));
  g_free (term);

  // Test with existing apply_overrides but no min_qod
  term = ensure_term_has_qod_and_overrides (g_strdup ("apply_overrides=1"));
  assert_that (term, contains_string ("apply_overrides=1"));
  assert_that (term, contains_string ("min_qod="));
  g_free (term);

  // Test with both min_qod and apply_overrides already present
  term = g_strdup ("min_qod=70 apply_overrides=0");
  term = ensure_term_has_qod_and_overrides (term);
  assert_that (term, contains_string ("min_qod=70"));
  assert_that (term, contains_string ("apply_overrides=0"));
  // Should not add defaults again
  assert_that (term, is_equal_to_string ("min_qod=70 apply_overrides=0"));
  g_free (term);
}

/* print_report_clean_filter */

static int
dummy_setting_value (const char *uuid, char **value)
{
  if (value == NULL || uuid == NULL)
    return -1;

  *value = g_strdup ("abc");
  return 0;
}

static int
dummy_setting_value_int (const char *uuid, int *value)
{
  if (value == NULL || uuid == NULL)
    return -1;

  *value = 10;
  return 0;
}

Ensure (manage_sql, print_report_clean_filter_handles_null_term)
{
  get_data_t get;
  gchar *term;

  init_manage_settings_funcs (dummy_setting_value, dummy_setting_value_int);

  // Test with NULL term and NULL get->filter
  get.filter = NULL;
  get.ignore_max_rows_per_page = 0;
  term = NULL;
  print_report_clean_filter (&term, &get);
  assert_that (term, is_not_equal_to (NULL));
  g_free (term);

  // Test with NULL term but valid get->filter
  get.filter = "severity>5";
  term = NULL;
  print_report_clean_filter (&term, &get);
  assert_that (term, is_not_equal_to (NULL));
  assert_that (term, contains_string ("severity>5"));
  g_free (term);
}

/* Test suite. */

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, manage_sql,
                         canceled_worker_exit_skips_request_task_cleanup);
  add_test_with_context (suite, manage_sql, validate_results_port_validates);
  add_test_with_context (suite, manage_sql,
                         ensure_term_has_qod_and_overrides_adds_defaults);
  add_test_with_context (suite, manage_sql,
                         print_report_clean_filter_handles_null_term);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
