/* Copyright (C) 2019-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "utils.c"

#include <cgreen/cgreen.h>

Describe (utils);
BeforeEach (utils) {}
AfterEach (utils) {}

/* gvm_usleep */

Ensure (utils, gvm_usleep_sleep_for_0)
{
  assert_that (gvm_usleep (0), is_equal_to (0));
}

Ensure (utils, gvm_usleep_sleep_for_1)
{
  assert_that (gvm_usleep (1), is_equal_to (0));
}

/* gvm_sleep */

Ensure (utils, gvm_sleep_sleep_for_0)
{
  assert_that (gvm_sleep (0), is_equal_to (0));
}

/* parse_iso_time_tz */

Ensure (utils, parse_iso_time_tz_with_offset)
{
  assert_that (parse_iso_time_tz ("2020-06-01T01:02:03+04:30",
                                  "Europe/Berlin"),
               is_equal_to (1590957123));

  assert_that (parse_iso_time_tz ("2020-06-01T01:02:03-0123",
                                  "Europe/Berlin"),
               is_equal_to (1590978303));
}

Ensure (utils, parse_iso_time_tz_with_z)
{
  assert_that (parse_iso_time_tz ("2020-06-01T01:02:03Z",
                                  "Europe/Berlin"),
               is_equal_to (1590973323));
}

Ensure (utils, parse_iso_time_tz_with_fallback_tz)
{
  assert_that (parse_iso_time_tz ("2020-06-01T01:02:03",
                                  "Australia/Sydney"),
               is_equal_to (1590937323));

  assert_that (parse_iso_time_tz ("2020-01-01T01:02:03",
                                  "Australia/Adelaide"),
               is_equal_to (1577802723));

  assert_that (parse_iso_time_tz ("2020-01-01T01:02:03",
                                  NULL),
               is_equal_to (1577840523));
}

Ensure (utils, parse_iso_time_tz_variants)
{
  assert_that (parse_iso_time_tz ("2020-06-01T01:02Z",
                                  "Europe/Berlin"),
               is_equal_to (1590973320));

  assert_that (parse_iso_time_tz ("2020-06-01 01:02:03.123+0000",
                                  "Australia/Sydney"),
               is_equal_to (1590973323));
}

/* Number of nanoseconds in a second. */
#define NANOSECONDS 1000000000

static long long
timespec_subtract (struct timespec *end, struct timespec *start)
{
  return (end->tv_sec * NANOSECONDS + start->tv_nsec)
         - (start->tv_sec * NANOSECONDS + start->tv_nsec);
}

Ensure (utils, gvm_sleep_sleep_for_1)
{
  struct timespec start, end;

  assert_that (clock_gettime (CLOCK_REALTIME, &start), is_equal_to (0));
  assert_that (gvm_sleep (1), is_equal_to (0));
  assert_that (clock_gettime (CLOCK_REALTIME, &end), is_equal_to (0));
  assert_that (timespec_subtract (&end, &start), is_greater_than (NANOSECONDS - 1));
}

Ensure (utils, strescape_check_utf_8_no_exceptions)
{
  const char *utf8_input = "Äöü\n123\\UTF-8\x04";
  const char *utf8_expected = "Äöü\\n123\\\\UTF-8\\004";
  const char *cp850_input = "\x8E\x94\x81\n123\\CP850\x04";
  const char *cp850_expected = "\\216\\224\\201\\n123\\\\CP850\\004";

  assert_that (g_utf8_validate (utf8_input, -1, NULL), is_true);
  gchar *output = strescape_check_utf8 (utf8_input, NULL);
  assert_that (output, is_equal_to_string (utf8_expected));
  g_free (output);

  assert_that (g_utf8_validate (cp850_input, -1, NULL), is_false);
  output = strescape_check_utf8 (cp850_input, NULL);
  assert_that (output, is_equal_to_string (cp850_expected));
  g_free (output);
}

Ensure (utils, strescape_check_utf_8_with_exceptions)
{
  const char *utf8_input = "Äöü\n123\\UTF-8\x04";
  const char *utf8_expected = "Äöü\n123\\\\UTF-8\\004";
  const char *cp850_input = "\x8E\x94\x81\n123\\CP850\x04";
  const char *cp850_expected = "\\216\\224\\201\n123\\\\CP850\\004";

  assert_that (g_utf8_validate (utf8_input, -1, NULL), is_true);
  gchar *output = strescape_check_utf8 (utf8_input, "\t\n\r");
  assert_that (output, is_equal_to_string (utf8_expected));
  g_free (output);

  assert_that (g_utf8_validate (cp850_input, -1, NULL), is_false);
  output = strescape_check_utf8 (cp850_input, "\t\n\r");
  assert_that (output, is_equal_to_string (cp850_expected));
  g_free (output);
}

Ensure (utils, path_is_in_directory_returns_true_if_path_is_in_dir)
{
  const gchar *directory = "/home/gvmd";
  const gchar *path1 = "/home/gvmd/abc/";
  const gchar *path2 = "/home/gvmd/abc/.././def";
  const gchar *path3 = "/home/gvmd";
  const gchar *path4 = "/home/gvmd/../gvmd/../gvmd/i_am_a_file.json";

  assert_that (path_is_in_directory (path1, directory), is_true);
  assert_that (path_is_in_directory (path2, directory), is_true);
  assert_that (path_is_in_directory (path3, directory), is_true);
  assert_that (path_is_in_directory (path4, directory), is_true);
}

Ensure (utils, path_is_in_directory_returns_false_if_path_is_not_in_dir)
{
  const gchar *directory = "/home/gvmd";
  const gchar *path1 = "/opt/gvmd";
  const gchar *path2 = "/home/gvmd/.././../var";
  const gchar *path3 = "/home/";
  const gchar *path4 = "/home/gvmd/../gvmd/../gvmd/../i_am_a_file.json";

  assert_that (path_is_in_directory (path1, directory), is_false);
  assert_that (path_is_in_directory (path2, directory), is_false);
  assert_that (path_is_in_directory (path3, directory), is_false);
  assert_that (path_is_in_directory (path4, directory), is_false);
}

/* Test suite. */

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, utils, gvm_usleep_sleep_for_0);
  add_test_with_context (suite, utils, gvm_usleep_sleep_for_1);

  add_test_with_context (suite, utils, gvm_sleep_sleep_for_0);
  add_test_with_context (suite, utils, gvm_sleep_sleep_for_1);

  add_test_with_context (suite, utils, parse_iso_time_tz_with_offset);
  add_test_with_context (suite, utils, parse_iso_time_tz_with_z);
  add_test_with_context (suite, utils, parse_iso_time_tz_with_fallback_tz);
  add_test_with_context (suite, utils, parse_iso_time_tz_variants);

  add_test_with_context (suite, utils, strescape_check_utf_8_no_exceptions);
  add_test_with_context (suite, utils, strescape_check_utf_8_with_exceptions);

  add_test_with_context (suite, utils,
                         path_is_in_directory_returns_true_if_path_is_in_dir);
  add_test_with_context (
    suite, utils, path_is_in_directory_returns_false_if_path_is_not_in_dir);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
