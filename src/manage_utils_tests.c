/* Copyright (C) 2019 Greenbone Networks GmbH
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
BeforeEach (manage_utils) {}
AfterEach (manage_utils) {}

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

Ensure (manage_utils, icalendar_next_time_from_string_utc)
{
  time_t next, now;

  /* Start in past. */
  now = time (NULL);
  next = icalendar_next_time_from_string
          ("BEGIN:VCALENDAR\n"
           "VERSION:2.0\n"
           "BEGIN:VEVENT\n"
           "DTSTART:20200101T000000Z\n"
           "RRULE:FREQ=MINUTELY;INTERVAL=2\n"
           "DURATION:PT0S\n"
           "UID:a486116b-8058-4b1e-9fc5-0eeec5948792\n"
           "DTSTAMP:19700101T000000Z\n"
           "END:VEVENT\n"
           "END:VCALENDAR\n",
           "UTC",
           0);
  assert_that (verify_next (next, EPOCH_2020JAN1_UTC, now, 2 * 60),
               is_equal_to (1));

  /* Start in future. */
  next = icalendar_next_time_from_string
          ("BEGIN:VCALENDAR\n"
           "VERSION:2.0\n"
           "BEGIN:VEVENT\n"
           "DTSTART:20300101T000000Z\n"
           "RRULE:FREQ=MINUTELY;INTERVAL=2\n"
           "DURATION:PT0S\n"
           "UID:a486116b-8058-4b1e-9fc5-0eeec5948792\n"
           "DTSTAMP:19700101T000000Z\n"
           "END:VEVENT\n"
           "END:VCALENDAR\n",
           "UTC",
           0);
  assert_that (next, is_equal_to (EPOCH_2030JAN1_UTC));
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

  add_test_with_context (suite, manage_utils, icalendar_next_time_from_string_utc);

  if (argc > 1)
    return run_single_test (suite, argv[1], create_text_reporter ());

  return run_test_suite (suite, create_text_reporter ());
}
