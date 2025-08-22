/* Copyright (C) 2019-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "manage_utils.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

Describe (manage_utils);
BeforeEach (manage_utils)
{
}
AfterEach (manage_utils)
{
}

/* add_months */

Ensure (manage_utils, add_months_0_months)
{
  assert_that (add_months (1572596056, 0), is_equal_to (1572596056));
}

Ensure (manage_utils, add_months_negative_months)
{
  assert_that (add_months (1554163199, -1), is_equal_to (1551484799));
  assert_that (add_months (1556755199, -2), is_equal_to (1551484799));
}

Ensure (manage_utils, add_months_positive_months)
{
  assert_that (add_months (1551484799, 1), is_equal_to (1554163199));
  assert_that (add_months (1551484799, 2), is_equal_to (1556755199));
}

/* icalendar_next_time_from_string */

#define EPOCH_2020JAN1_UTC 1577836800
#define EPOCH_2030JAN1_UTC 1893456000
#define EPOCH_2020JAN1_HAR 1577829600

static time_t
get_next_time (time_t first, time_t now, int period, int offset)
{
  time_t to_next;

  assert (offset > 0);

  to_next = ((now - first) + offset * period - 1);
  to_next -= to_next % period;

  return first + to_next;
}

static time_t
verify_next (time_t next, time_t first, time_t now, int period)
{
  /* There's a gap between getting now and getting next.  This means next
   * could be the first or second occurrence of the period after now. */

  return next == get_next_time (first, now, 2 * 60, 1)
         || next == get_next_time (first, now, 2 * 60, 2);
}

static GPtrArray *
make_str_array (const char **vals, size_t n)
{
  GPtrArray *a = g_ptr_array_new_with_free_func (g_free);
  for (size_t i = 0; i < n; ++i)
    {
      if (vals[i] == NULL)
        g_ptr_array_add (a, NULL);
      else
        g_ptr_array_add (a, g_strdup (vals[i]));
    }
  return a;
}

Ensure (manage_utils, icalendar_next_time_from_string_utc)
{
  time_t next, now;

  /* Start in past. */
  now = time (NULL);
  next = icalendar_next_time_from_string (
    "BEGIN:VCALENDAR\n"
    "VERSION:2.0\n"
    "BEGIN:VEVENT\n"
    "DTSTART:20200101T000000Z\n"
    "RRULE:FREQ=MINUTELY;INTERVAL=2\n"
    "DURATION:PT0S\n"
    "UID:a486116b-8058-4b1e-9fc5-0eeec5948792\n"
    "DTSTAMP:19700101T000000Z\n"
    "END:VEVENT\n"
    "END:VCALENDAR\n",
    now, "UTC", 0);
  assert_that (verify_next (next, EPOCH_2020JAN1_UTC, now, 2 * 60),
               is_equal_to (1));

  /* Start in future. */
  next = icalendar_next_time_from_string (
    "BEGIN:VCALENDAR\n"
    "VERSION:2.0\n"
    "BEGIN:VEVENT\n"
    "DTSTART:20300101T000000Z\n"
    "RRULE:FREQ=MINUTELY;INTERVAL=2\n"
    "DURATION:PT0S\n"
    "UID:a486116b-8058-4b1e-9fc5-0eeec5948792\n"
    "DTSTAMP:19700101T000000Z\n"
    "END:VEVENT\n"
    "END:VCALENDAR\n",
    now, "UTC", 0);
  assert_that (next, is_equal_to (EPOCH_2030JAN1_UTC));
}

Ensure (manage_utils, icalendar_next_time_from_string_tz)
{
  time_t next, now;

  now = time (NULL);

  next = icalendar_next_time_from_string (
    "BEGIN:VCALENDAR\n"
    "VERSION:2.0\n"
    /* Timezone definition. */
    "BEGIN:VTIMEZONE\n"
    "TZID:/freeassociation.sourceforge.net/Africa/Harare\n"
    "X-LIC-LOCATION:Africa/Harare\n"
    "BEGIN:STANDARD\n"
    "TZNAME:CAT\n"
    "DTSTART:19030301T000000\n"
    "TZOFFSETFROM:+021020\n"
    "TZOFFSETTO:+0200\n"
    "END:STANDARD\n"
    "END:VTIMEZONE\n"
    /* Event. */
    "BEGIN:VEVENT\n"
    "DTSTART;TZID=/freeassociation.sourceforge.net/Africa/Harare:\n"
    " 20200101T000000\n"
    "RRULE:FREQ=MINUTELY;INTERVAL=2\n"
    "DURATION:PT0S\n"
    "UID:a486116b-8058-4b1e-9fc5-0eeec5948792\n"
    "DTSTAMP:19700101T000000Z\n"
    "END:VEVENT\n"
    "END:VCALENDAR\n",
    now, "Africa/Harare", 0);

  assert_that (verify_next (next, EPOCH_2020JAN1_HAR, now, 2 * 60),
               is_equal_to (1));
}

/* Hosts test */

Ensure (manage_utils, clean_hosts_string_zeroes)
{
  gchar *clean_str;

  // Simple IP address
  clean_str = clean_hosts_string ("000.001.002.003");
  assert_that (clean_str, is_equal_to_string ("0.1.2.3"));
  g_free (clean_str);

  // Long form range
  clean_str = clean_hosts_string ("000.001.002.003-000.001.010.100");
  assert_that (clean_str, is_equal_to_string ("0.1.2.3-0.1.10.100"));
  g_free (clean_str);

  // Short form range
  clean_str = clean_hosts_string ("000.001.002.003-004");
  assert_that (clean_str, is_equal_to_string ("0.1.2.3-4"));
  g_free (clean_str);

  // CIDR notation range
  clean_str = clean_hosts_string ("000.001.002.003/004");
  assert_that (clean_str, is_equal_to_string ("0.1.2.3/4"));
  g_free (clean_str);

  // Hostname with multiple zeroes (should stay the same)
  clean_str = clean_hosts_string ("server001.example.com");
  assert_that (clean_str, is_equal_to_string ("server001.example.com"));
  g_free (clean_str);

  // List of addresses and ranges
  clean_str = clean_hosts_string ("000.001.002.003,  040.050.060.070-80,"
                                  " 123.012.001.001-123.012.001.010");
  assert_that (clean_str, is_equal_to_string ("0.1.2.3, 40.50.60.70-80,"
                                              " 123.12.1.1-123.12.1.10"));
  g_free (clean_str);
}

/* concat_error_messages tests */

Ensure (manage_utils, concat_error_messages_null_array_returns_null)
{
  gchar *s = concat_error_messages (NULL, NULL, "Validation failed for : ");
  assert_that (s, is_null);
}

Ensure (manage_utils, concat_error_messages_empty_array_returns_null)
{
  GPtrArray *arr = g_ptr_array_new_with_free_func (g_free);
  gchar *s = concat_error_messages (arr, NULL, "Validation failed for : ");
  assert_that (s, is_null);
  g_ptr_array_free (arr, TRUE);
}

Ensure (manage_utils, concat_error_messages_single_item_with_prefix)
{
  const char *vals[] = {"attempts must be >= 0"};
  GPtrArray *arr = make_str_array (vals, 1);

  gchar *s = concat_error_messages (arr, NULL, "Validation failed for : ");
  assert_that (
    s, is_equal_to_string ("Validation failed for : attempts must be >= 0"));

  g_free (s);
  g_ptr_array_free (arr, TRUE);
}

Ensure (manage_utils, concat_error_messages_multiple_default_sep_and_prefix)
{
  const char *vals[] = {"period_in_seconds required",
                        "bulk_size must be positive", "cron invalid"};
  GPtrArray *arr = make_str_array (vals, 3);

  gchar *s = concat_error_messages (arr, NULL, "Validation failed for : ");
  assert_that (s, is_equal_to_string (
                    "Validation failed for : period_in_seconds required; "
                    "bulk_size must be positive; cron invalid"));

  g_free (s);
  g_ptr_array_free (arr, TRUE);
}

Ensure (manage_utils, concat_error_messages_custom_separator)
{
  const char *vals[] = {"a", "b", "c"};
  GPtrArray *arr = make_str_array (vals, 3);

  gchar *s = concat_error_messages (arr, " | ", "Validation failed for : ");
  assert_that (s, is_equal_to_string ("Validation failed for : a | b | c"));

  g_free (s);
  g_ptr_array_free (arr, TRUE);
}

Ensure (manage_utils, concat_error_messages_skips_null_and_empty)
{
  const char *vals[] = {NULL, "", "first", "", "second", NULL};
  GPtrArray *arr = make_str_array (vals, sizeof (vals) / sizeof (vals[0]));

  gchar *s = concat_error_messages (arr, NULL, "Validation failed for : ");
  assert_that (s, is_equal_to_string ("Validation failed for : first; second"));

  g_free (s);
  g_ptr_array_free (arr, TRUE);
}

Ensure (manage_utils, concat_error_messages_all_null_or_empty_returns_null)
{
  const char *vals[] = {NULL, "", NULL, ""};
  GPtrArray *arr = make_str_array (vals, sizeof (vals) / sizeof (vals[0]));

  gchar *s = concat_error_messages (arr, NULL, "Validation failed for : ");
  assert_that (s, is_null);

  g_ptr_array_free (arr, TRUE);
}

Ensure (manage_utils, concat_error_messages_null_prefix_means_no_prefix)
{
  const char *vals[] = {"x", "y"};
  GPtrArray *arr = make_str_array (vals, 2);

  gchar *s = concat_error_messages (arr, NULL, NULL);
  assert_that (s, is_equal_to_string ("x; y"));

  g_free (s);
  g_ptr_array_free (arr, TRUE);
}

Ensure (manage_utils, concat_error_messages_empty_separator)
{
  const char *vals[] = {"aa", "bb", "cc"};
  GPtrArray *arr = make_str_array (vals, 3);

  gchar *s = concat_error_messages (arr, "", "P: ");
  assert_that (s, is_equal_to_string ("P: aabbcc"));

  g_free (s);
  g_ptr_array_free (arr, TRUE);
}

/* Test suite. */

int
main (int argc, char **argv)
{
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, manage_utils, add_months_0_months);
  add_test_with_context (suite, manage_utils, add_months_negative_months);
  add_test_with_context (suite, manage_utils, add_months_positive_months);

  add_test_with_context (suite, manage_utils,
                         icalendar_next_time_from_string_utc);
  add_test_with_context (suite, manage_utils,
                         icalendar_next_time_from_string_tz);

  add_test_with_context (suite, manage_utils, clean_hosts_string_zeroes);

  add_test_with_context (suite, manage_utils,
                         concat_error_messages_null_array_returns_null);
  add_test_with_context (suite, manage_utils,
                         concat_error_messages_empty_array_returns_null);
  add_test_with_context (suite, manage_utils,
                         concat_error_messages_single_item_with_prefix);
  add_test_with_context (suite, manage_utils,
                         concat_error_messages_multiple_default_sep_and_prefix);
  add_test_with_context (suite, manage_utils,
                         concat_error_messages_custom_separator);
  add_test_with_context (suite, manage_utils,
                         concat_error_messages_skips_null_and_empty);
  add_test_with_context (suite, manage_utils,
                         concat_error_messages_all_null_or_empty_returns_null);
  add_test_with_context (suite, manage_utils,
                         concat_error_messages_null_prefix_means_no_prefix);
  add_test_with_context (suite, manage_utils,
                         concat_error_messages_empty_separator);

  if (argc > 1)
    return run_single_test (suite, argv[1], create_text_reporter ());

  return run_test_suite (suite, create_text_reporter ());
}
