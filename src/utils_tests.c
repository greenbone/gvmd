/* Copyright (C) 2019 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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

/* Test suite. */

int
main (int argc, char **argv)
{
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, utils, gvm_usleep_sleep_for_0);
  add_test_with_context (suite, utils, gvm_usleep_sleep_for_1);

  add_test_with_context (suite, utils, gvm_sleep_sleep_for_0);
  add_test_with_context (suite, utils, gvm_sleep_sleep_for_1);

  if (argc > 1)
    return run_single_test (suite, argv[1], create_text_reporter ());

  return run_test_suite (suite, create_text_reporter ());
}
