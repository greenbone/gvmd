/* Copyright (C) 2019 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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

#include "manage_utils.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

Describe (manage_utils);
BeforeEach (manage_utils) {}
AfterEach (manage_utils) {}

/* time_offset */

Ensure (manage_utils, time_offset_returns_0_when_zone_is_null)
{
  assert_that (time_offset (NULL, 1559561396), is_equal_to (0));
}

Ensure (manage_utils, time_offset_returns_0_when_zone_is_utc)
{
  assert_that (time_offset ("UTC", 1559561396), is_equal_to (0));
}

Ensure (manage_utils, time_offset_returns_correct_value)
{
  assert_that (time_offset ("Africa/Johannesburg", 1559561396), is_equal_to (7200));
}

/* current_offset */

Ensure (manage_utils, current_offset_returns_correct_values)
{
  assert_that (time_offset (NULL, 1559561396), is_equal_to (0));
  assert_that (time_offset ("UTC", 1559561396), is_equal_to (0));
  assert_that (time_offset ("Africa/Johannesburg", 1559561396), is_equal_to (7200));
}

/* next_time */

time_t
__wrap_time (time_t *tloc)
{
  return mock ();
}

Ensure (manage_utils, next_time_returns_correct_value)
{
  always_expect (__wrap_time, will_return (1560176823));
  assert_that (next_time (1560176800, 40, 0, 0, "Africa/Johannesburg", 0),
               is_equal_to (1560176840));
}

/* Test suite. */

int
main (int argc, char **argv)
{
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, manage_utils, time_offset_returns_0_when_zone_is_null);
  add_test_with_context (suite, manage_utils, time_offset_returns_0_when_zone_is_utc);
  add_test_with_context (suite, manage_utils, time_offset_returns_correct_value);

  add_test_with_context (suite, manage_utils, current_offset_returns_correct_values);

  add_test_with_context (suite, manage_utils, next_time_returns_correct_value);

  if (argc > 1)
    return run_single_test (suite, argv[1], create_text_reporter ());

  return run_test_suite (suite, create_text_reporter ());
}
