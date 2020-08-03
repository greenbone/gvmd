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

#define CMP(one, two, ret) assert_that (streq_ignore_ws (one, two), is_equal_to (ret))

#define EQ2(one, two) CMP(one, two, 1); CMP(two, one, 1)
#define EQ(string) CMP(string, string, 1)

Ensure (manage_sql, streq_ignore_ws_finds_equal)
{
  EQ ("abc");
  EQ (" abc");
  EQ ("abc ");
  EQ ("ab c");
  EQ ("");
  EQ (".");
  EQ (" abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-=_)(*&^%$#@!~\"':}{<>?");
  EQ ("three little words");
}

Ensure (manage_sql, streq_ignore_ws_finds_equal_despite_ws)
{
  EQ2 ("abc", " abc");
  EQ2 ("abc", "abc ");
  EQ2 ("abc", "ab c");
  EQ2 ("abc", " a b    c ");

  EQ2 ("abc", "\nabc");
  EQ2 ("abc", "abc\n");
  EQ2 ("abc", "ab\nc");
  EQ2 ("abc", "\na\nb\n\n\n\nc\n");

  EQ2 ("abc", "\tabc");
  EQ2 ("abc", "abc\t");
  EQ2 ("abc", "ab\tc");
  EQ2 ("abc", "\ta\tb\t\t\t\tc\t");

  EQ2 ("abcd", "\ta\nb \t\nc  \t\t\n\nd\t\n ");

  EQ2 ("", " ");
  EQ2 ("", "\t");
  EQ2 ("", "\n");
  EQ2 ("", "  ");
  EQ2 ("", "\t\t");
  EQ2 ("", "\n\n");
  EQ2 ("", " \n\t  \n\n\t\t");

  EQ2 (" \n\t  \n\n\t\t", " \n\t  \n\n\t\t");
}

#define DIFF(one, two) CMP(one, two, 0); CMP(two, one, 0)

Ensure (manage_sql, streq_ignore_ws_finds_diff)
{
  DIFF ("abc", "abcd");
  DIFF ("abc", "dabc");
  DIFF ("abc", "abdc");
  DIFF ("abc", "xyz");
  DIFF ("abc", "");
  DIFF ("abc", ".");
  DIFF ("abc", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-=_)(*&^%$#@!~\"':}{<>?");
}

Ensure (manage_sql, streq_ignore_ws_finds_diff_incl_ws)
{
  DIFF ("zabc", " abc");
  DIFF ("zabc", "abc ");
  DIFF ("zabc", "ab c");
  DIFF ("zabc", " a b    c ");

  DIFF ("zabc", "\nabc");
  DIFF ("zabc", "abc\n");
  DIFF ("zabc", "ab\nc");
  DIFF ("zabc", "\na\nb\n\n\n\nc\n");

  DIFF ("zabc", "\tabc");
  DIFF ("zabc", "abc\t");
  DIFF ("zabc", "ab\tc");
  DIFF ("zabc", "\ta\tb\t\t\t\tc\t");

  DIFF ("zabcd", "\ta\nb \t\nc  \t\t\n\nd\t\n ");

  DIFF ("a", " ");
  DIFF ("a", "\t");
  DIFF ("a", "\n");
  DIFF ("a", "  ");
  DIFF ("a", "\t\t");
  DIFF ("a", "\n\n");
  DIFF ("a", " \n\t  \n\n\t\t");

  DIFF ("a \n\t  \n\n\t\t", " \n\t  \n\n\t\t");
  DIFF (" \n\t  \na\n\t\t", " \n\t  \n\n\t\t");
  DIFF (" \n\t  \n\n\t\ta", " \n\t  \n\n\t\t");
}

Ensure (manage_sql, streq_ignore_ws_handles_null)
{
  EQ (NULL);
  DIFF ("abc", NULL);
}

/* Test suite. */

int
main (int argc, char **argv)
{
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, manage_sql, validate_results_port_validates);

  add_test_with_context (suite, manage_sql, streq_ignore_ws_finds_equal);
  add_test_with_context (suite, manage_sql, streq_ignore_ws_finds_equal_despite_ws);
  add_test_with_context (suite, manage_sql, streq_ignore_ws_finds_diff);
  add_test_with_context (suite, manage_sql, streq_ignore_ws_finds_diff_incl_ws);
  add_test_with_context (suite, manage_sql, streq_ignore_ws_handles_null);

  if (argc > 1)
    return run_single_test (suite, argv[1], create_text_reporter ());

  return run_test_suite (suite, create_text_reporter ());
}
