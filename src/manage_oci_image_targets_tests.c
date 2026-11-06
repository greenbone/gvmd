
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

Ensure (manage_oci_image_targets, accepts_only_registry)
{
  gchar *given;
  given = g_strdup ("oci://myregistry.com");

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

Ensure (manage_oci_image_targets, rejects_empty_image_ref_url_after_prefix)
{
  gchar *given;
  given = g_strdup ("oci://");

  assert_that (valid_oci_url(given), is_equal_to (-1));
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

Ensure (manage_oci_image_targets,
        valid_oci_image_digest_accepts_sha256_hex)
{
  gchar *digest = g_strdup ("sha256:"
                           "0123456789abcdef0123456789abcdef"
                           "0123456789abcdef0123456789abcdef");

  assert_that (is_valid_oci_image_digest (digest), is_equal_to (1));
  g_free (digest);
}

Ensure (manage_oci_image_targets,
        valid_oci_image_digest_rejects_invalid_values)
{
  assert_that (is_valid_oci_image_digest (NULL), is_equal_to (0));
  assert_that (is_valid_oci_image_digest (""), is_equal_to (0));
  assert_that (is_valid_oci_image_digest ("sha256:abc"), is_equal_to (0));
  assert_that (is_valid_oci_image_digest ("sha256:"
                                          "0123456789abcdef0123456789abcdef"
                                          "0123456789abcdef0123456789ABCDEF"),
                                          is_equal_to (0));
  assert_that (is_valid_oci_image_digest ("sha512:"
                                          "0123456789abcdef0123456789abcdef"
                                          "0123456789abcdef0123456789abcdef"),
                                          is_equal_to (0));
}

Ensure (manage_oci_image_targets,
        manage_count_oci_image_digests_counts_valid_entries)
{
  gchar *digests = g_strdup ("sha256:"
                            "0123456789abcdef0123456789abcdef"
                            "0123456789abcdef0123456789abcdef,"
                            "sha256:"
                            "fedcba9876543210fedcba9876543210"
                            "fedcba9876543210fedcba9876543210");

  assert_that (manage_count_oci_image_digests (digests), is_equal_to (2));
  g_free (digests);
}

Ensure (manage_oci_image_targets,
        manage_count_oci_image_digests_counts_unique_entries)
{
  gchar *digests = g_strdup ("sha256:"
                            "0123456789abcdef0123456789abcdef"
                            "0123456789abcdef0123456789abcdef,"
                            "sha256:"
                            "0123456789abcdef0123456789abcdef"
                            "0123456789abcdef0123456789abcdef");

  assert_that (manage_count_oci_image_digests (digests), is_equal_to (1));
  g_free (digests);
}

Ensure (manage_oci_image_targets,
        manage_count_oci_image_digests_ignores_empty_entries)
{
  gchar *digests = g_strdup (""
                            "sha256:"
                            "0123456789abcdef0123456789abcdef"
                            "0123456789abcdef0123456789abcdef,"
                            ","
                            "sha256:"
                            "fedcba9876543210fedcba9876543210"
                            "fedcba9876543210fedcba9876543210"
                            ",");

  assert_that (manage_count_oci_image_digests (digests), is_equal_to (2));
  g_free (digests);
}

Ensure (manage_oci_image_targets,
        manage_count_oci_image_digests_rejects_invalid_digest)
{
  gchar *digests = g_strdup ("sha256:"
                            "0123456789abcdef0123456789abcdef"
                            "0123456789abcdef0123456789abcdef,"
                            "sha256:abc");

  assert_that (manage_count_oci_image_digests (digests), is_equal_to (-1));
  g_free (digests);
}

Ensure (manage_oci_image_targets,
        manage_count_oci_image_digests_handles_empty_input)
{
  assert_that (manage_count_oci_image_digests (NULL), is_equal_to (0));
  assert_that (manage_count_oci_image_digests (""), is_equal_to (0));
  assert_that (manage_count_oci_image_digests (" , "), is_equal_to (0));
}

Ensure (manage_oci_image_targets,
        count_effective_oci_image_references_handles_for_null_input)
{
  assert_that (count_effective_oci_image_references (NULL, NULL),
               is_equal_to (-1));
}

Ensure (manage_oci_image_targets,
        count_effective_oci_image_references_counts_unique_values)
{
  gchar *image_references =
    g_strdup ("oci://registry.example.com/app:tag1,"
              "oci://registry.example.com/app:tag2,"
              "oci://registry.example.com/app:tag1");

  assert_that (count_effective_oci_image_references (image_references, NULL),
               is_equal_to (2));

  g_free (image_references);
}

Ensure (manage_oci_image_targets,
        count_effective_oci_image_references_ignores_whitespace_and_excludes)
{
  gchar *image_references =
    g_strdup ("  oci://registry.example.com/app:tag1 ,"
              " oci://registry.example.com/app:tag2 ,"
              " oci://registry.example.com/app:tag3 ,"
              " oci://registry.example.com/app:tag1  ");
  gchar *exclude_images =
    g_strdup ("oci://registry.example.com/app:tag2,"
              " oci://registry.example.com/app:tag4 ,"
              " ");

  assert_that (count_effective_oci_image_references (image_references,
                                                    exclude_images),
               is_equal_to (2));

  g_free (image_references);
  g_free (exclude_images);
}

Ensure (manage_oci_image_targets,
        count_effective_oci_image_references_handles_empty_exclude_list)
{
  gchar *image_references =
    g_strdup ("oci://registry.example.com/app:tag1,"
              "oci://registry.example.com/app:tag2");

  assert_that (count_effective_oci_image_references (image_references, ""),
               is_equal_to (2));

  g_free (image_references);
}

/* Test suite. */

int
main (int argc, char **argv)
{
  int ret;
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
                                rejects_empty_image_ref_url_after_prefix);

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

  add_test_with_context (suite, manage_oci_image_targets,
                                accepts_only_registry);

  add_test_with_context (suite, manage_oci_image_targets,
                                valid_oci_image_digest_accepts_sha256_hex);

  add_test_with_context (suite, manage_oci_image_targets,
                                valid_oci_image_digest_rejects_invalid_values);

  add_test_with_context (suite, manage_oci_image_targets,
                                manage_count_oci_image_digests_counts_valid_entries);

  add_test_with_context (suite, manage_oci_image_targets,
                                manage_count_oci_image_digests_counts_unique_entries);

  add_test_with_context (suite, manage_oci_image_targets,
                                manage_count_oci_image_digests_ignores_empty_entries);

  add_test_with_context (suite, manage_oci_image_targets,
                                manage_count_oci_image_digests_rejects_invalid_digest);

  add_test_with_context (suite, manage_oci_image_targets,
                                manage_count_oci_image_digests_handles_empty_input);

  add_test_with_context (suite, manage_oci_image_targets,
                                count_effective_oci_image_references_handles_for_null_input);

  add_test_with_context (suite, manage_oci_image_targets,
                                count_effective_oci_image_references_counts_unique_values);

  add_test_with_context (suite, manage_oci_image_targets,
                                count_effective_oci_image_references_ignores_whitespace_and_excludes);

  add_test_with_context (suite, manage_oci_image_targets,
                                count_effective_oci_image_references_handles_empty_exclude_list);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
