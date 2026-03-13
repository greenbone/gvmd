/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */


#include <cgreen/cgreen.h>
#include "gvmd_config.h"

Describe (gvmd_config);

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

Ensure (gvmd_config, can_read_and_write_config)
{
  const char *conf =
    "[features]\n"
    "enable_agents = true\n"
    "[auth]\n"
    "jwt_secret_type = shared\n";
  char *path = write_test_config (conf);
  GKeyFile *kf;

  assert_that (get_gvmd_config(), is_null);

  assert_that (load_gvmd_config (path), is_equal_to (0));
  kf = get_gvmd_config ();
  assert_that (kf, is_not_null);

  remove (path);
  g_free (path);
}

Ensure (gvmd_config, load_fails_if_file_is_missing)
{
  const char *path = "non-existent.conf";
  remove (path);

  assert_that (load_gvmd_config (path), is_equal_to (-1));
  assert_that (get_gvmd_config(), is_null);
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, gvmd_config,
                         can_read_and_write_config);
  add_test_with_context (suite, gvmd_config,
                         load_fails_if_file_is_missing);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;

}