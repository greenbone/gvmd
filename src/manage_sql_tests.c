/* Copyright (C) 2020-2022 Greenbone AG
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

/* Test suite. */

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, manage_sql, validate_results_port_validates);
  add_test_with_context (suite, manage_sql,
                         ensure_term_has_qod_and_overrides_adds_defaults);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
