/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */


#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

#include <glib.h>
#include <stdlib.h>
#include <string.h>


#ifndef GVM_SYSCONF_DIR
# define GVM_SYSCONF_DIR "/tmp"
#endif

#include "manage_runtime_flags.c"

Describe (manage_runtime_flags);

BeforeEach (manage_runtime_flags)
{
  unsetenv ("GVMD_ENABLE_AGENTS");
  unsetenv ("GVMD_ENABLE_CONTAINER_SCANNING");
  unsetenv ("GVMD_ENABLE_OPENVASD");
  unsetenv ("GVMD_ENABLE_CREDENTIAL_STORES");
  unsetenv ("GVMD_ENABLE_VT_METADATA");
}

AfterEach (manage_runtime_flags)
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

Ensure (manage_runtime_flags, default_flags_no_config_no_env)
{
  const char *nonexistent = "this_file_should_not_exist.conf";
  remove (nonexistent);

  runtime_flags_init (nonexistent);

#if ENABLE_AGENTS
  assert_that (feature_compiled_in (FEATURE_ID_AGENTS), is_equal_to (1));
  assert_that (feature_enabled (FEATURE_ID_AGENTS), is_equal_to (0));
#else
  assert_that (feature_compiled_in (FEATURE_ID_AGENTS), is_equal_to (0));
  assert_that (feature_enabled (FEATURE_ID_AGENTS), is_equal_to (0));
#endif

#if ENABLE_CONTAINER_SCANNING
  assert_that (feature_compiled_in (FEATURE_ID_CONTAINER_SCANNING),
               is_equal_to (1));
  assert_that (feature_enabled (FEATURE_ID_CONTAINER_SCANNING),
               is_equal_to (0));
#else
  assert_that (feature_compiled_in (FEATURE_ID_CONTAINER_SCANNING),
               is_equal_to (0));
  assert_that (feature_enabled (FEATURE_ID_CONTAINER_SCANNING),
               is_equal_to (0));
#endif

#if OPENVASD
  assert_that (feature_compiled_in (FEATURE_ID_OPENVASD_SCANNER),
               is_equal_to (1));
  assert_that (feature_enabled (FEATURE_ID_OPENVASD_SCANNER), is_equal_to (0));
#else
  assert_that (feature_compiled_in (FEATURE_ID_OPENVASD_SCANNER),
               is_equal_to (0));
  assert_that (feature_enabled (FEATURE_ID_OPENVASD_SCANNER), is_equal_to (0));
#endif

#if ENABLE_CREDENTIAL_STORES
  assert_that (feature_compiled_in (FEATURE_ID_CREDENTIAL_STORES),
               is_equal_to (1));
  assert_that (feature_enabled (FEATURE_ID_CREDENTIAL_STORES), is_equal_to (0));
#else
  assert_that (feature_compiled_in (FEATURE_ID_CREDENTIAL_STORES),
               is_equal_to (0));
  assert_that (feature_enabled (FEATURE_ID_CREDENTIAL_STORES), is_equal_to (0));
#endif

  assert_that (feature_compiled_in (FEATURE_ID_VT_METADATA), is_equal_to (1));
  assert_that (feature_enabled (FEATURE_ID_VT_METADATA), is_equal_to (0));
}

Ensure (manage_runtime_flags, config_enables_agents_when_compiled_in)
{
  const char *conf =
    "[features]\n"
    "enable_agents = true\n";

  char *path = write_test_config (conf);

  runtime_flags_init (path);

#if ENABLE_AGENTS
  assert_that (feature_compiled_in (FEATURE_ID_AGENTS), is_equal_to (1));
  assert_that (feature_enabled (FEATURE_ID_AGENTS), is_equal_to (1));
#else
  assert_that (feature_compiled_in (FEATURE_ID_AGENTS), is_equal_to (0));
  assert_that (feature_enabled (FEATURE_ID_AGENTS), is_equal_to (0));
#endif

  remove (path);
  g_free (path);
}

Ensure (manage_runtime_flags, config_disables_agents_when_compiled_in)
{
  const char *conf =
    "[features]\n"
    "enable_agents = false\n";

  char *path = write_test_config (conf);

  runtime_flags_init (path);

#if ENABLE_AGENTS
  assert_that (feature_compiled_in (FEATURE_ID_AGENTS), is_equal_to (1));
  assert_that (feature_enabled (FEATURE_ID_AGENTS), is_equal_to (0));
#else
  assert_that (feature_compiled_in (FEATURE_ID_AGENTS), is_equal_to (0));
  assert_that (feature_enabled (FEATURE_ID_AGENTS), is_equal_to (0));
#endif

  remove (path);
  g_free (path);
}

Ensure (manage_runtime_flags, env_overrides_config_for_agents)
{
  const char *conf =
    "[features]\n"
    "enable_agents = false\n";

  char *path = write_test_config (conf);

  setenv ("GVMD_ENABLE_AGENTS", "1", 1);

  runtime_flags_init (path);

#if ENABLE_AGENTS
  assert_that (feature_compiled_in (FEATURE_ID_AGENTS), is_equal_to (1));
  assert_that (feature_enabled (FEATURE_ID_AGENTS), is_equal_to (1));
#else
  assert_that (feature_compiled_in (FEATURE_ID_AGENTS), is_equal_to (0));
  assert_that (feature_enabled (FEATURE_ID_AGENTS), is_equal_to (0));
#endif

  remove (path);
  g_free (path);
}

Ensure (manage_runtime_flags, invalid_env_falls_back_to_config)
{
  const char *conf =
    "[features]\n"
    "enable_agents = true\n";

  char *path = write_test_config (conf);

  setenv ("GVMD_ENABLE_AGENTS", "test", 1);

  runtime_flags_init (path);

#if ENABLE_AGENTS
  assert_that (feature_compiled_in (FEATURE_ID_AGENTS), is_equal_to (1));
  assert_that (feature_enabled (FEATURE_ID_AGENTS), is_equal_to (1));
#else
  assert_that (feature_compiled_in (FEATURE_ID_AGENTS), is_equal_to (0));
  assert_that (feature_enabled (FEATURE_ID_AGENTS), is_equal_to (0));
#endif

  remove (path);
  g_free (path);
}

Ensure (manage_runtime_flags, compiled_out_feature_ignores_env_and_config)
{
  const char *conf =
    "[features]\n"
    "enable_agents = true\n";

  char *path = write_test_config (conf);

  setenv ("GVMD_ENABLE_AGENTS", "1", 1);

  runtime_flags_init (path);

#if ENABLE_AGENTS
  assert_that (feature_compiled_in (FEATURE_ID_AGENTS), is_equal_to (1));
#else
  assert_that (feature_compiled_in (FEATURE_ID_AGENTS), is_equal_to (0));
  assert_that (feature_enabled (FEATURE_ID_AGENTS), is_equal_to (0));
#endif

  remove (path);
  g_free (path);
}

Ensure (manage_runtime_flags,
        runtime_append_disabled_commands_disables_agents_when_disabled)
{
  const char *conf =
    "[features]\n"
    "enable_agents = false\n";
  char *path = write_test_config (conf);

  runtime_flags_init (path);

#if ENABLE_AGENTS

  GString *buf = g_string_new (NULL);
  runtime_append_disabled_commands (buf);

  assert_that (buf->len, is_greater_than (0));
  assert_that (strstr (buf->str, "get_agents"), is_not_equal_to (NULL));
  assert_that (strstr (buf->str, "modify_agent"), is_not_equal_to (NULL));

  g_string_free (buf, TRUE);
  remove (path);
  g_free (path);
#else
  GString *buf = g_string_new (NULL);
  runtime_append_disabled_commands (buf);
  g_string_free (buf, TRUE);
#endif
}

Ensure (manage_runtime_flags,
        runtime_append_disabled_commands_does_not_disable_enabled_agents)
{
  const char *conf =
    "[features]\n"
    "enable_agents = true\n";

  char *path = write_test_config (conf);
  runtime_flags_init (path);

#if ENABLE_AGENTS

  GString *buf = g_string_new (NULL);
  runtime_append_disabled_commands (buf);

  if (buf->len > 0)
    {
      assert_that (strstr (buf->str, "get_agents"), is_equal_to (NULL));
      assert_that (strstr (buf->str, "modify_agent"), is_equal_to (NULL));
    }

  g_string_free (buf, TRUE);
  remove (path);
  g_free (path);
#else
  GString *buf = g_string_new (NULL);
  runtime_append_disabled_commands (buf);
  g_string_free (buf, TRUE);
#endif
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, manage_runtime_flags,
                         default_flags_no_config_no_env);
  add_test_with_context (suite, manage_runtime_flags,
                         config_enables_agents_when_compiled_in);
  add_test_with_context (suite, manage_runtime_flags,
                         config_disables_agents_when_compiled_in);
  add_test_with_context (suite, manage_runtime_flags,
                         env_overrides_config_for_agents);
  add_test_with_context (suite, manage_runtime_flags,
                         invalid_env_falls_back_to_config);
  add_test_with_context (suite, manage_runtime_flags,
                         compiled_out_feature_ignores_env_and_config);
  add_test_with_context (
    suite, manage_runtime_flags,
    runtime_append_disabled_commands_disables_agents_when_disabled);
  add_test_with_context (
    suite, manage_runtime_flags,
    runtime_append_disabled_commands_does_not_disable_enabled_agents);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}