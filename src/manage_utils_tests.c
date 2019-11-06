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

/* Test suite. */

int
main (int argc, char **argv)
{
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, manage_utils, add_months_0_months);
  add_test_with_context (suite, manage_utils, add_months_negative_months);
  add_test_with_context (suite, manage_utils, add_months_positive_months);

  if (argc > 1)
    return run_single_test (suite, argv[1], create_text_reporter ());

  return run_test_suite (suite, create_text_reporter ());
}
