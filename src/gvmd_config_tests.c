/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */


#include <cgreen/cgreen.h>
#include "gvmd_config.h"

static GKeyFile *string_config;
static gchar *previous_string_env;
static guint string_warning_handler;
static guint string_warning_count;
static gchar *last_string_warning;

static void
capture_string_warning (const gchar *domain, GLogLevelFlags level,
                        const gchar *message, gpointer data)
{
  if (g_str_has_prefix (message, "gvmd_get_env_or_config_string:"))
    {
      string_warning_count++;
      g_free (last_string_warning);
      last_string_warning = g_strdup (message);
    }
  else
    g_log_default_handler (domain, level, message, data);
}

Describe (gvmd_config);

BeforeEach (gvmd_config)
{
  unsetenv ("GVMD_ENABLE_AGENTS");
  unsetenv ("GVMD_JWT_ACCESS_DURATION");
  previous_string_env = g_strdup (g_getenv ("GVMD_TEST_CONFIG_STRING"));
  g_unsetenv ("GVMD_TEST_CONFIG_STRING");
  string_config = g_key_file_new ();
  string_warning_count = 0;
  string_warning_handler = g_log_set_handler (
    "md manage", G_LOG_LEVEL_WARNING, capture_string_warning, NULL);
}

AfterEach (gvmd_config)
{
  g_key_file_unref (string_config);
  g_log_remove_handler ("md manage", string_warning_handler);
  g_clear_pointer (&last_string_warning, g_free);
  if (previous_string_env)
    g_setenv ("GVMD_TEST_CONFIG_STRING", previous_string_env, TRUE);
  else
    g_unsetenv ("GVMD_TEST_CONFIG_STRING");
  g_clear_pointer (&previous_string_env, g_free);
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

Ensure (gvmd_config, can_read_strings_including_empty_and_decoded_values)
{
  gchar *value;

  g_key_file_set_value (string_config, "strings", "value", "file\\svalue\\n");
  value = gvmd_get_env_or_config_string (
    "GVMD_TEST_CONFIG_STRING", string_config, "strings", "value");
  assert_that (value, is_equal_to_string ("file value\n"));
  g_free (value);

  g_key_file_set_string (string_config, "strings", "value", "");
  value = gvmd_get_env_or_config_string (
    "GVMD_TEST_CONFIG_STRING", string_config, "strings", "value");
  assert_that (value, is_equal_to_string (""));
  g_free (value);
  assert_that (string_warning_count, is_equal_to (0));
}

Ensure (gvmd_config, missing_strings_are_silent)
{
  assert_that (gvmd_get_env_or_config_string (
    "GVMD_TEST_CONFIG_STRING", NULL, "strings", "value"), is_null);
  assert_that (gvmd_get_env_or_config_string (
    "GVMD_TEST_CONFIG_STRING", string_config, "strings", "value"), is_null);
  g_key_file_set_string (string_config, "strings", "other", "present");
  assert_that (gvmd_get_env_or_config_string (
    "GVMD_TEST_CONFIG_STRING", string_config, "strings", "value"), is_null);
  assert_that (string_warning_count, is_equal_to (0));
}

Ensure (gvmd_config, unreadable_strings_warn_without_exposing_values)
{
  const gchar *invalid[] = { "hidden-secret\\q", "hidden-secret\377" };

  for (guint i = 0; i < G_N_ELEMENTS (invalid); i++)
    {
      g_key_file_set_value (string_config, "strings", "value", invalid[i]);
      assert_that (gvmd_get_env_or_config_string (
        "GVMD_TEST_CONFIG_STRING", string_config, "strings", "value"),
        is_null);
      assert_that (string_warning_count, is_equal_to (i + 1));
      assert_that (last_string_warning, is_equal_to_string (
        "gvmd_get_env_or_config_string: strings.value: could not read string"));
    }
}

Ensure (gvmd_config, environment_strings_override_even_when_empty)
{
  const gchar *overrides[] = { "env\\q", "", " \t\n " };
  gchar *value;

  g_key_file_set_value (string_config, "strings", "value", "hidden-secret\\q");
  for (guint i = 0; i < G_N_ELEMENTS (overrides); i++)
    {
      g_setenv ("GVMD_TEST_CONFIG_STRING", overrides[i], TRUE);
      value = gvmd_get_env_or_config_string (
        "GVMD_TEST_CONFIG_STRING", string_config, "strings", "value");
      assert_that (value, is_equal_to_string (overrides[i]));
      g_free (value);
      value = gvmd_get_env_or_config_string (
        "GVMD_TEST_CONFIG_STRING", NULL, "strings", "value");
      assert_that (value, is_equal_to_string (overrides[i]));
      g_free (value);
    }
  assert_that (string_warning_count, is_equal_to (0));
}

Ensure (gvmd_config, full_string_getter_distinguishes_read_errors_from_absence)
{
  gboolean read_error = TRUE;
  gchar *value;
  const gchar *invalid[] = { "hidden-secret\\q", "hidden-secret\377" };
  const gchar *overrides[] = { "env", "", " \t " };

  assert_that (gvmd_get_env_or_config_string_full (
    "GVMD_TEST_CONFIG_STRING", NULL, "strings", "value", &read_error), is_null);
  assert_that (read_error, is_equal_to (FALSE));
  read_error = TRUE;
  assert_that (gvmd_get_env_or_config_string_full (
    "GVMD_TEST_CONFIG_STRING", string_config, "strings", "value", &read_error),
    is_null);
  assert_that (read_error, is_equal_to (FALSE));
  g_key_file_set_string (string_config, "strings", "other", "present");
  read_error = TRUE;
  assert_that (gvmd_get_env_or_config_string_full (
    "GVMD_TEST_CONFIG_STRING", string_config, "strings", "value", &read_error),
    is_null);
  assert_that (read_error, is_equal_to (FALSE));
  assert_that (string_warning_count, is_equal_to (0));

  for (guint i = 0; i < G_N_ELEMENTS (invalid); i++)
    {
      g_key_file_set_value (string_config, "strings", "value", invalid[i]);
      read_error = FALSE;
      assert_that (gvmd_get_env_or_config_string_full (
        "GVMD_TEST_CONFIG_STRING", string_config, "strings", "value", &read_error),
        is_null);
      assert_that (read_error, is_equal_to (TRUE));
      assert_that (string_warning_count, is_equal_to (i + 1));
      assert_that (last_string_warning, is_equal_to_string (
        "gvmd_get_env_or_config_string: strings.value: could not read string"));
    }

  for (guint i = 0; i < G_N_ELEMENTS (overrides); i++)
    {
      g_setenv ("GVMD_TEST_CONFIG_STRING", overrides[i], TRUE);
      read_error = TRUE;
      value = gvmd_get_env_or_config_string_full (
        "GVMD_TEST_CONFIG_STRING", string_config, "strings", "value", &read_error);
      assert_that (value, is_equal_to_string (overrides[i]));
      assert_that (read_error, is_equal_to (FALSE));
      g_free (value);
    }
  assert_that (string_warning_count, is_equal_to (G_N_ELEMENTS (invalid)));

  g_unsetenv ("GVMD_TEST_CONFIG_STRING");
  g_key_file_set_value (string_config, "strings", "value", "file\\svalue\\n");
  read_error = TRUE;
  value = gvmd_get_env_or_config_string_full (
    "GVMD_TEST_CONFIG_STRING", string_config, "strings", "value", &read_error);
  assert_that (value, is_equal_to_string ("file value\n"));
  assert_that (read_error, is_equal_to (FALSE));
  g_free (value);
  g_key_file_set_string (string_config, "strings", "value", "");
  read_error = TRUE;
  value = gvmd_get_env_or_config_string_full (
    "GVMD_TEST_CONFIG_STRING", string_config, "strings", "value", &read_error);
  assert_that (value, is_equal_to_string (""));
  assert_that (read_error, is_equal_to (FALSE));
  g_free (value);
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, gvmd_config,
                         full_string_getter_distinguishes_read_errors_from_absence);
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
  add_test_with_context (suite, gvmd_config,
                         can_read_strings_including_empty_and_decoded_values);
  add_test_with_context (suite, gvmd_config,
                         missing_strings_are_silent);
  add_test_with_context (suite, gvmd_config,
                         unreadable_strings_warn_without_exposing_values);
  add_test_with_context (suite, gvmd_config,
                         environment_strings_override_even_when_empty);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;

}
