/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_agent_installers.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

Describe (manage_agent_installers);
BeforeEach (manage_agent_installers) {}
AfterEach (manage_agent_installers) {}

#define VALID_DATA "This should be valid...."
#define TOO_LONG_DATA "This text is longer than expected!"
#define INVALID_DATA "This shouldn't be valid!"
#define VALID_DATA_HASH \
  "sha256:4ae8f10c9e9551173520b7a675e9caba163007edf04dbbd06022bf61ad3fe4fb"

/* add_months */

Ensure (manage_agent_installers, accepts_valid_installer_file)
{
  GError *error = NULL;
  char *tmp_dir = g_strdup ("/tmp/manage_agent_installers_test_XXXXXX");
  gchar *full_path, *message;

  if (mkdtemp (tmp_dir) == NULL)
    fail_test ("could not init temp dir");
  agent_installer_feed_path = tmp_dir;

  full_path = g_build_filename (tmp_dir, "test.txt", NULL);
  message = NULL;
  g_file_set_contents (full_path, VALID_DATA, strlen (VALID_DATA), &error);

  assert_true (agent_installer_file_is_valid ("test.txt",
                                              VALID_DATA_HASH,
                                              &message));
  assert_string_equal (message, "valid");

  g_free (message);
  gvm_file_remove_recurse (tmp_dir);
  g_free (tmp_dir);
  g_free (full_path);
}

Ensure (manage_agent_installers, rejects_invalid_installer_file)
{
  GError *error = NULL;
  char *tmp_dir = g_strdup ("/tmp/manage_agent_installers_test_XXXXXX");
  gchar *full_path, *message;

  if (mkdtemp (tmp_dir) == NULL)
    fail_test ("could not init temp dir");
  agent_installer_feed_path = tmp_dir;
  
  full_path = g_build_filename (tmp_dir, "test.txt", NULL);
  message = NULL;
  g_file_set_contents (full_path, INVALID_DATA, strlen (INVALID_DATA), &error);

  assert_false (agent_installer_file_is_valid ("test.txt",
                                               VALID_DATA_HASH,
                                               &message));
  assert_string_equal (message, "file validation failed: hash does not match");

  g_free (message);
  gvm_file_remove_recurse (tmp_dir);
  g_free (full_path);
  g_free (tmp_dir);
}

Ensure (manage_agent_installers, rejects_invalid_installer_paths)
{
  GError *error = NULL;
  char *tmp_dir = g_strdup ("/tmp/manage_agent_installers_test_XXXXXX");
  gchar *full_path, *message;

  if (mkdtemp (tmp_dir) == NULL)
    fail_test ("could not init temp dir");
  agent_installer_feed_path = tmp_dir;

  full_path = g_build_filename (tmp_dir, "test.txt", NULL);
  message = NULL;
  g_file_set_contents (full_path, VALID_DATA, strlen (VALID_DATA), &error);

  assert_false (agent_installer_file_is_valid ("../abc/test.txt",
                                               VALID_DATA_HASH,
                                               &message));
  assert_string_equal (message,
                       "invalid installer path: '../abc/test.txt'"
                       " is outside feed directory");
  g_free (message);
  message = NULL;

  assert_false (agent_installer_file_is_valid ("does-not-exist.txt",
                                               VALID_DATA_HASH,
                                               &message));
  assert_string_equal (message,
                       "error opening installer file:"
                       " No such file or directory");

  g_free (message);
  gvm_file_remove_recurse (tmp_dir);
  g_free (full_path);
  g_free (tmp_dir);
}

Ensure (manage_agent_installers, rejects_invalid_checksum)
{
  GError *error = NULL;
  char *tmp_dir = g_strdup ("/tmp/manage_agent_installers_test_XXXXXX");
  gchar *full_path, *message;

  if (mkdtemp (tmp_dir) == NULL)
    fail_test ("could not init temp dir");
  agent_installer_feed_path = tmp_dir;

  full_path = g_build_filename (tmp_dir, "test.txt", NULL);
  message = NULL;
  g_file_set_contents (full_path, VALID_DATA, strlen (VALID_DATA), &error);

  assert_false (agent_installer_file_is_valid ("test.txt",
                                               "not-a-valid-checksum",
                                               &message));
  assert_string_equal (message,
                       "error in expected checksum: invalid hash syntax");

  g_free (message);
  gvm_file_remove_recurse (tmp_dir);
  g_free (full_path);
  g_free (tmp_dir);
}

Ensure (manage_agent_installers, rejects_too_long_file)
{
  GError *error = NULL;
  char *tmp_dir = g_strdup ("/tmp/manage_agent_installers_test_XXXXXX");
  gchar *full_path, *message;

  if (mkdtemp (tmp_dir) == NULL)
    fail_test ("could not init temp dir");
  agent_installer_feed_path = tmp_dir;

  full_path = g_build_filename (tmp_dir, "test.txt", NULL);
  message = NULL;
  g_file_set_contents (full_path, TOO_LONG_DATA, strlen (TOO_LONG_DATA),
                       &error);

  assert_false (agent_installer_file_is_valid ("test.txt",
                                               VALID_DATA_HASH,
                                               &message));
  assert_string_equal (message,
                       "file validation failed: hash does not match");

  g_free (message);
  gvm_file_remove_recurse (tmp_dir);
  g_free (full_path);
  g_free (tmp_dir);
}

/* Test suite. */

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, manage_agent_installers,
                         accepts_valid_installer_file);
  add_test_with_context (suite, manage_agent_installers,
                         rejects_invalid_installer_file);
  add_test_with_context (suite, manage_agent_installers,
                         rejects_invalid_installer_paths);
  add_test_with_context (suite, manage_agent_installers,
                         rejects_invalid_checksum);
  add_test_with_context (suite, manage_agent_installers,
                         rejects_too_long_file);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
