/* Copyright (C) 2019-2022 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_preferences.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

Describe (manage_preferences);
BeforeEach (manage_preferences)
{
}
AfterEach (manage_preferences)
{
}

Ensure (manage_preferences, preference_free_frees_hr_name)
{
  gchar *hr_name;
  preference_t *pref;

  hr_name = g_strdup ("human readable name");

  pref = preference_new (g_strdup ("1"), g_strdup ("name"),
                         g_strdup ("entry"), g_strdup ("value"),
                         g_strdup ("nvt"), g_strdup ("1.2.3"),
                         NULL, g_strdup ("default"),
                         hr_name, TRUE);
  preference_free (pref);
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, manage_preferences,
                         preference_free_frees_hr_name);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
