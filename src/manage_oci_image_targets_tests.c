
/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_oci_image_targets.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

Describe (manage_oci_image_targets);
BeforeEach (manage_oci_image_targets) {}
AfterEach (manage_oci_image_targets) {}

Ensure (manage_oci_image_targets, accepts_registry_repo_image_tag)
{
  gchar *given;
  given = g_strdup ("oci://myregistry.com/myrepo/myimage:tag");

  assert_that (valid_oci_url(given), is_equal_to (0));
  g_free (given);
}

Ensure (manage_oci_image_targets, accepts_registry_nested_repo_image_tag)
{
  gchar *given;
  given = g_strdup ("oci://myregistry.com/myrepo/myrepo2/myimage:tag");

  assert_that (valid_oci_url(given), is_equal_to (0));
  g_free (given);
}

Ensure (manage_oci_image_targets, accepts_registry_repo_image)
{
  gchar *given;
  given = g_strdup ("oci://myregistry.com/myrepo/myimage");

  assert_that (valid_oci_url(given), is_equal_to (0));
  g_free (given);
}

Ensure (manage_oci_image_targets, accepts_registry_port_repo_image)
{
  gchar *given;
  given = g_strdup ("oci://myregistry.com:12345/myrepo/myimage");

  assert_that (valid_oci_url(given), is_equal_to (0));
  g_free (given);
}

Ensure (manage_oci_image_targets, accepts_registry_repo)
{
  gchar *given;
  given = g_strdup ("oci://myregistry.com:12345/myrepo");

  assert_that (valid_oci_url(given), is_equal_to (0));
  g_free (given);
}

Ensure (manage_oci_image_targets, accepts_registry_port)
{
  gchar *given;
  given = g_strdup ("oci://myregistry.com:12345");

  assert_that (valid_oci_url(given), is_equal_to (0));
  g_free (given);
}

Ensure (manage_oci_image_targets, rejects_invalid_port)
{
  gchar *given;
  given = g_strdup ("oci://myregistry.com:123456");

  assert_that (valid_oci_url(given), is_equal_to (-1));
  g_free (given);
}

Ensure (manage_oci_image_targets, accepts_registry_as_ipv4)
{
  gchar *given;
  given = g_strdup ("oci://192.168.0.4:12345");

  assert_that (valid_oci_url(given), is_equal_to (0));
  g_free (given);
}

Ensure (manage_oci_image_targets, accepts_registry_as_ipv6)
{
  gchar *given;
  given = g_strdup ("oci://0001:1:1:1::1/myregistry.com");

  assert_that (valid_oci_url(given), is_equal_to (0));
  g_free (given);
}

Ensure (manage_oci_image_targets, accepts_registry_as_ipv6_with_brackets)
{
  gchar *given;
  given = g_strdup ("oci://[0001:1:1:1::1]/myregistry.com");

  assert_that (valid_oci_url(given), is_equal_to (0));
  g_free (given);
}

Ensure (manage_oci_image_targets, accepts_registry_as_ipv6_with_port)
{
  gchar *given;
  given = g_strdup ("oci://[0001:1:1:1::1]:12345/myregistry.com");

  assert_that (valid_oci_url(given), is_equal_to (0));
  g_free (given);
}

Ensure (manage_oci_image_targets, rejects_invalid_ipv6)
{
  gchar *given;
  given = g_strdup ("oci://[]:12345/myregistry.com");

  assert_that (valid_oci_url(given), is_equal_to (-1));
  g_free (given);
}

/* Test suite. */

int
main (int argc, char **argv)
{
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, manage_oci_image_targets,
                                accepts_registry_repo_image_tag);

  add_test_with_context (suite, manage_oci_image_targets,
                                accepts_registry_nested_repo_image_tag);

  add_test_with_context (suite, manage_oci_image_targets,
                                accepts_registry_repo_image);

  add_test_with_context (suite, manage_oci_image_targets,
                                accepts_registry_port_repo_image);

  add_test_with_context (suite, manage_oci_image_targets,
                                accepts_registry_repo);

  add_test_with_context (suite, manage_oci_image_targets,
                                accepts_registry_port);

  add_test_with_context (suite, manage_oci_image_targets, 
                                rejects_invalid_port);

  add_test_with_context (suite, manage_oci_image_targets,
                                accepts_registry_as_ipv4);

  add_test_with_context (suite, manage_oci_image_targets,
                                accepts_registry_as_ipv6);

  add_test_with_context (suite, manage_oci_image_targets,
                                accepts_registry_as_ipv6_with_brackets);

  add_test_with_context (suite, manage_oci_image_targets,
                                accepts_registry_as_ipv6_with_port);

  add_test_with_context (suite, manage_oci_image_targets,
                                rejects_invalid_ipv6);

  if (argc > 1)
    return run_single_test (suite, argv[1], create_text_reporter ());

  return run_test_suite (suite, create_text_reporter ());
}
