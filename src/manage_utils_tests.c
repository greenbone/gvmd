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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

/* time_offset */

static void
time_offset_returns_0_when_zone_is_null (void **state)
{
  assert_int_equal (time_offset (NULL, 1559561396), 0);
}

static void
time_offset_returns_0_when_zone_is_utc (void **state)
{
  assert_int_equal (time_offset ("UTC", 1559561396), 0);
}

static void
time_offset_returns_correct_value (void **state)
{
  assert_int_equal (time_offset ("Africa/Johannesburg", 1559561396), 7200);
}

/* current_offset */

static void
current_offset_returns_correct_values (void **state)
{
  assert_int_equal (time_offset (NULL, 1559561396), 0);
  assert_int_equal (time_offset ("UTC", 1559561396), 0);
  assert_int_equal (time_offset ("Africa/Johannesburg", 1559561396), 7200);
}

/* Test suite. */

int
main (int argc, char **argv)
{
  const struct CMUnitTest tests[] = { cmocka_unit_test (time_offset_returns_0_when_zone_is_null),
                                      cmocka_unit_test (time_offset_returns_0_when_zone_is_utc),
                                      cmocka_unit_test (time_offset_returns_correct_value),
                                      cmocka_unit_test (current_offset_returns_correct_values) };

  return cmocka_run_group_tests (tests, NULL, NULL);
}
