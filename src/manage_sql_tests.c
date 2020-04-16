/* Copyright (C) 2020 Greenbone Networks GmbH
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

#include "manage_sql.c"

#include <cgreen/cgreen.h>

Describe (manage_sql);
BeforeEach (manage_sql) {}
AfterEach (manage_sql) {}

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

/* Test suite. */

int
main (int argc, char **argv)
{
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, manage_sql, validate_results_port_validates);

  if (argc > 1)
    return run_single_test (suite, argv[1], create_text_reporter ());

  return run_test_suite (suite, create_text_reporter ());
}
