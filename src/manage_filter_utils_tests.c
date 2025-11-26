/* Copyright (C) 2025 Greenbone AG
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

#include "manage_filter_utils.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

Describe (manage_filter_utils);
BeforeEach (manage_filter_utils)
{
}
AfterEach (manage_filter_utils)
{
}

/* keyword_relation_symbol */

Ensure (manage_filter_utils, keyword_relation_symbol_approx)
{
  assert_that (keyword_relation_symbol (KEYWORD_RELATION_APPROX),
               is_equal_to_string ("~"));
}

Ensure (manage_filter_utils, keyword_relation_symbol_column_above)
{
  assert_that (keyword_relation_symbol (KEYWORD_RELATION_COLUMN_ABOVE),
               is_equal_to_string (">"));
}

Ensure (manage_filter_utils, keyword_relation_symbol_column_approx)
{
  assert_that (keyword_relation_symbol (KEYWORD_RELATION_COLUMN_APPROX),
               is_equal_to_string ("~"));
}

Ensure (manage_filter_utils, keyword_relation_symbol_column_equal)
{
  assert_that (keyword_relation_symbol (KEYWORD_RELATION_COLUMN_EQUAL),
               is_equal_to_string ("="));
}

Ensure (manage_filter_utils, keyword_relation_symbol_column_below)
{
  assert_that (keyword_relation_symbol (KEYWORD_RELATION_COLUMN_BELOW),
               is_equal_to_string ("<"));
}

Ensure (manage_filter_utils, keyword_relation_symbol_column_regexp)
{
  assert_that (keyword_relation_symbol (KEYWORD_RELATION_COLUMN_REGEXP),
               is_equal_to_string (":"));
}

Ensure (manage_filter_utils, keyword_relation_symbol_default)
{
  assert_that (keyword_relation_symbol (999),
               is_equal_to_string (""));
}

/* keyword_special */

Ensure (manage_filter_utils, keyword_special_null_keyword)
{
  keyword_t keyword = {0};
  assert_that (keyword_special (&keyword), is_equal_to (0));
}

Ensure (manage_filter_utils, keyword_special_and)
{
  keyword_t keyword = {0};
  keyword.string = g_strdup ("and");
  assert_that (keyword_special (&keyword), is_equal_to (1));
  g_free (keyword.string);
}

Ensure (manage_filter_utils, keyword_special_or)
{
  keyword_t keyword = {0};
  keyword.string = g_strdup ("or");
  assert_that (keyword_special (&keyword), is_equal_to (1));
  g_free (keyword.string);
}

Ensure (manage_filter_utils, keyword_special_not)
{
  keyword_t keyword = {0};
  keyword.string = g_strdup ("not");
  assert_that (keyword_special (&keyword), is_equal_to (1));
  g_free (keyword.string);
}

Ensure (manage_filter_utils, keyword_special_re)
{
  keyword_t keyword = {0};
  keyword.string = g_strdup ("re");
  assert_that (keyword_special (&keyword), is_equal_to (1));
  g_free (keyword.string);
}

Ensure (manage_filter_utils, keyword_special_regexp)
{
  keyword_t keyword = {0};
  keyword.string = g_strdup ("regexp");
  assert_that (keyword_special (&keyword), is_equal_to (1));
  g_free (keyword.string);
}

Ensure (manage_filter_utils, keyword_special_non_special)
{
  keyword_t keyword = {0};
  keyword.string = g_strdup ("name");
  assert_that (keyword_special (&keyword), is_equal_to (0));
  g_free (keyword.string);
}

/* filter_term_value */

Ensure (manage_filter_utils, filter_term_value_null_term)
{
  gchar *value = filter_term_value (NULL, "name");
  assert_that (value, is_null);
}

Ensure (manage_filter_utils, filter_term_value_simple)
{
  gchar *value = filter_term_value ("name=example rows=5", "name");
  assert_that (value, is_equal_to_string ("example"));
  g_free (value);
}

Ensure (manage_filter_utils, filter_term_value_with_underscore)
{
  gchar *value = filter_term_value ("_owner=admin rows=5", "owner");
  assert_that (value, is_equal_to_string ("admin"));
  g_free (value);
}

Ensure (manage_filter_utils, filter_term_value_not_found)
{
  gchar *value = filter_term_value ("name=example rows=5", "severity");
  assert_that (value, is_null);
}

/* Test suite. */

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, manage_filter_utils,
                         keyword_relation_symbol_approx);
  add_test_with_context (suite, manage_filter_utils,
                         keyword_relation_symbol_column_above);
  add_test_with_context (suite, manage_filter_utils,
                         keyword_relation_symbol_column_approx);
  add_test_with_context (suite, manage_filter_utils,
                         keyword_relation_symbol_column_equal);
  add_test_with_context (suite, manage_filter_utils,
                         keyword_relation_symbol_column_below);
  add_test_with_context (suite, manage_filter_utils,
                         keyword_relation_symbol_column_regexp);
  add_test_with_context (suite, manage_filter_utils,
                         keyword_relation_symbol_default);

  add_test_with_context (suite, manage_filter_utils,
                         keyword_special_null_keyword);
  add_test_with_context (suite, manage_filter_utils,
                         keyword_special_and);
  add_test_with_context (suite, manage_filter_utils,
                         keyword_special_or);
  add_test_with_context (suite, manage_filter_utils,
                         keyword_special_not);
  add_test_with_context (suite, manage_filter_utils,
                         keyword_special_re);
  add_test_with_context (suite, manage_filter_utils,
                         keyword_special_regexp);
  add_test_with_context (suite, manage_filter_utils,
                         keyword_special_non_special);

  add_test_with_context (suite, manage_filter_utils,
                         filter_term_value_null_term);
  add_test_with_context (suite, manage_filter_utils,
                         filter_term_value_simple);
  add_test_with_context (suite, manage_filter_utils,
                         filter_term_value_with_underscore);
  add_test_with_context (suite, manage_filter_utils,
                         filter_term_value_not_found);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
