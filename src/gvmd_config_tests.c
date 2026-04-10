/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */


#include <cgreen/cgreen.h>
#include "gvmd_config.h"

Describe (gvmd_config);

BeforeEach (gvmd_config)
{
  unsetenv ("GVMD_ENABLE_AGENTS");
  unsetenv ("GVMD_JWT_ACCESS_DURATION");
}

AfterEach (gvmd_config)
{
}

static char *
write_test_config (const char *content)
{
  char *path = g_strdup ("runtime_flags_test.conf");
  FILE *f = fopen (path, "w");

  assert_true (f != NULL);
  fputs (content, f);
  fclose (f);

  return path;
}

Ensure (gvmd_config, can_handle_missing_config)
{
  const char *path = "non-existent.conf";
  remove (path);

  assert_that (load_gvmd_config (path), is_equal_to (-1));
  assert_that (get_gvmd_config(), is_null);
}

Ensure (gvmd_config, can_read_boolean_values)
{
  const char *conf =
    "[features]\n"
    "enable_agents = false\n"
    "enable_openvasd = true\n";
  char *path = write_test_config (conf);
  GKeyFile *kf;
  gboolean conf_has_value, conf_value;

  assert_that (load_gvmd_config (path), is_equal_to (0));
  kf = get_gvmd_config ();
  assert_that (kf, is_not_null);

  conf_has_value = TRUE;
  conf_value = TRUE;
  gvmd_config_get_boolean (kf, "invalid_group", "enable_openvasd",
                           &conf_has_value, &conf_value);
  assert_that (conf_has_value, is_false);
  assert_that (conf_value, is_false);

  conf_has_value = FALSE;
  conf_value = TRUE;
  gvmd_config_get_boolean (kf, "features", "enable_agents",
                           &conf_has_value, &conf_value);
  assert_that (conf_has_value, is_true);
  assert_that (conf_value, is_false);

  conf_has_value = FALSE;
  conf_value = FALSE;
  gvmd_config_get_boolean (kf, "features", "enable_openvasd",
                           &conf_has_value, &conf_value);
  assert_that (conf_has_value, is_true);
  assert_that (conf_value, is_true);

  remove (path);
  g_free (path);
}

Ensure (gvmd_config, can_read_integer_values)
{
  const char *conf =
    "[authentication]\n"
    "jwt_access_duration = 30\n"
    "invalid_value = xyz\n";
  char *path = write_test_config (conf);
  GKeyFile *kf;
  gboolean conf_has_value, conf_value;

  assert_that (load_gvmd_config (path), is_equal_to (0));
  kf = get_gvmd_config ();

  conf_has_value = FALSE;
  conf_value = 0;
  gvmd_config_get_int (kf, "authentication", "jwt_access_duration",
                       &conf_has_value, &conf_value);
  assert_that (conf_has_value, is_true);
  assert_that (conf_value, is_equal_to (30));

  conf_has_value = FALSE;
  conf_value = 123;
  gvmd_config_get_int (kf, "authentication", "invalid_value",
                       &conf_has_value, &conf_value);
  assert_that (conf_has_value, is_false);
  assert_that (conf_value, is_equal_to (0));

  conf_has_value = FALSE;
  conf_value = 123;
  gvmd_config_get_int (kf, "authentication", "invalid_value",
                       &conf_has_value, &conf_value);
  assert_that (conf_has_value, is_false);
  assert_that (conf_value, is_equal_to (0));

  remove (path);
  g_free (path);
}

Ensure (gvmd_config, can_resolve_boolean_values)
{
  int value = 123;

  gvmd_config_resolve_boolean ("GVMD_ENABLE_AGENTS", 0, 0, &value);
  assert_that (value, is_equal_to (123));

  gvmd_config_resolve_boolean ("GVMD_ENABLE_AGENTS", 1, 0, &value);
  assert_that (value, is_equal_to (0));

  gvmd_config_resolve_boolean ("GVMD_ENABLE_AGENTS", 1, 1, &value);
  assert_that (value, is_equal_to (1));

  setenv ("GVMD_ENABLE_AGENTS", "no", 1);
  value = 123;
  gvmd_config_resolve_boolean ("GVMD_ENABLE_AGENTS", 0, 1, &value);
  assert_that (value, is_equal_to (0));

  gvmd_config_resolve_boolean ("GVMD_ENABLE_AGENTS", 1, 0, &value);
  assert_that (value, is_equal_to (0));

  gvmd_config_resolve_boolean ("GVMD_ENABLE_AGENTS", 1, 1, &value);
  assert_that (value, is_equal_to (0));

  setenv ("GVMD_ENABLE_AGENTS", "yes", 1);
  value = 123;
  gvmd_config_resolve_boolean ("GVMD_ENABLE_AGENTS", 0, 0, &value);
  assert_that (value, is_equal_to (1));

  gvmd_config_resolve_boolean ("GVMD_ENABLE_AGENTS", 1, 0, &value);
  assert_that (value, is_equal_to (1));

  gvmd_config_resolve_boolean ("GVMD_ENABLE_AGENTS", 1, 1, &value);
  assert_that (value, is_equal_to (1));
}

Ensure (gvmd_config, can_resolve_integer_values)
{
  int value = 123;

  gvmd_config_resolve_int ("GVMD_JWT_ACCESS_DURATION", 0, 0, &value);
  assert_that (value, is_equal_to (123));

  gvmd_config_resolve_int ("GVMD_JWT_ACCESS_DURATION", 1, 0, &value);
  assert_that (value, is_equal_to (0));

  gvmd_config_resolve_int ("GVMD_JWT_ACCESS_DURATION", 1, 10, &value);
  assert_that (value, is_equal_to (10));

  setenv ("GVMD_JWT_ACCESS_DURATION", "invalid 456", 1);
  value = 123;
  gvmd_config_resolve_int ("GVMD_JWT_ACCESS_DURATION", 0, 1, &value);
  assert_that (value, is_equal_to (123));

  gvmd_config_resolve_int ("GVMD_JWT_ACCESS_DURATION", 1, 0, &value);
  assert_that (value, is_equal_to (0));

  gvmd_config_resolve_int ("GVMD_JWT_ACCESS_DURATION", 1, 10, &value);
  assert_that (value, is_equal_to (10));

  setenv ("GVMD_JWT_ACCESS_DURATION", "456 invalid", 1);
  value = 123;
  gvmd_config_resolve_int ("GVMD_JWT_ACCESS_DURATION", 0, 1, &value);
  assert_that (value, is_equal_to (123));

  setenv ("GVMD_JWT_ACCESS_DURATION", "20", 1);
  value = 123;
  gvmd_config_resolve_int ("GVMD_JWT_ACCESS_DURATION", 0, 1, &value);
  assert_that (value, is_equal_to (20));

  gvmd_config_resolve_int ("GVMD_JWT_ACCESS_DURATION", 1, 0, &value);
  assert_that (value, is_equal_to (20));

  gvmd_config_resolve_int ("GVMD_JWT_ACCESS_DURATION", 1, 10, &value);
  assert_that (value, is_equal_to (20));

  setenv ("GVMD_JWT_ACCESS_DURATION", " \t20 \t ", 1);
  value = 123;
  gvmd_config_resolve_int ("GVMD_JWT_ACCESS_DURATION", 0, 1, &value);
  assert_that (value, is_equal_to (20));
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, gvmd_config,
                         can_handle_missing_config);
  add_test_with_context (suite, gvmd_config,
                         can_read_boolean_values);
  add_test_with_context (suite, gvmd_config,
                         can_resolve_boolean_values);
  add_test_with_context (suite, gvmd_config,
                         can_read_integer_values);
  add_test_with_context (suite, gvmd_config,
                         can_resolve_integer_values);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;

}
