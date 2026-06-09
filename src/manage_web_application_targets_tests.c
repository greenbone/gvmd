/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#define ENABLE_WEB_APPLICATION_SCANNING 1

#include "manage_web_application_targets.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

Describe (manage_web_application_targets);
BeforeEach (manage_web_application_targets) {}
AfterEach (manage_web_application_targets) {}

Ensure (manage_web_application_targets, allocates_web_application_target_data)
{
  web_application_target_data_t data;

  data = web_application_target_data_new ();

  assert_that (data, is_not_null);
  assert_that (data->row_id, is_equal_to (0));
  assert_that (data->uuid, is_null);
  assert_that (data->name, is_null);
  assert_that (data->comment, is_null);
  assert_that (data->urls, is_null);
  assert_that (data->exclude_urls, is_null);
  assert_that (data->credential_uuid, is_null);

  web_application_target_data_free (data);
}

Ensure (manage_web_application_targets, frees_null_web_application_target_data)
{
  web_application_target_data_free (NULL);
}

Ensure (manage_web_application_targets, accepts_http_url)
{
  gchar *given;

  given = g_strdup ("http://example.com");

  assert_that (valid_web_application_url (given), is_equal_to (0));

  g_free (given);
}

Ensure (manage_web_application_targets, accepts_https_url)
{
  gchar *given;

  given = g_strdup ("https://example.com");

  assert_that (valid_web_application_url (given), is_equal_to (0));

  g_free (given);
}

Ensure (manage_web_application_targets, accepts_https_url_with_path)
{
  gchar *given;

  given = g_strdup ("https://example.com/app/login");

  assert_that (valid_web_application_url (given), is_equal_to (0));

  g_free (given);
}

Ensure (manage_web_application_targets, accepts_https_url_with_query)
{
  gchar *given;

  given = g_strdup ("https://example.com/app/search?q=test");

  assert_that (valid_web_application_url (given), is_equal_to (0));

  g_free (given);
}

Ensure (manage_web_application_targets, accepts_https_url_with_fragment)
{
  gchar *given;

  given = g_strdup ("https://example.com/app#section");

  assert_that (valid_web_application_url (given), is_equal_to (0));

  g_free (given);
}

Ensure (manage_web_application_targets, accepts_localhost_url)
{
  gchar *given;

  given = g_strdup ("http://localhost:8080");

  assert_that (valid_web_application_url (given), is_equal_to (0));

  g_free (given);
}

Ensure (manage_web_application_targets, accepts_ipv4_url)
{
  gchar *given;

  given = g_strdup ("http://192.168.0.10:8080");

  assert_that (valid_web_application_url (given), is_equal_to (0));

  g_free (given);
}

Ensure (manage_web_application_targets, accepts_ipv6_url_with_brackets)
{
  gchar *given;

  given = g_strdup ("http://[2001:db8::1]:8080");

  assert_that (valid_web_application_url (given), is_equal_to (0));

  g_free (given);
}

Ensure (manage_web_application_targets, rejects_null_url)
{
  assert_that (valid_web_application_url (NULL), is_equal_to (-1));
}

Ensure (manage_web_application_targets, rejects_empty_url)
{
  gchar *given;

  given = g_strdup ("");

  assert_that (valid_web_application_url (given), is_equal_to (-1));

  g_free (given);
}

Ensure (manage_web_application_targets, rejects_url_without_scheme)
{
  gchar *given;

  given = g_strdup ("example.com");

  assert_that (valid_web_application_url (given), is_equal_to (-1));

  g_free (given);
}

Ensure (manage_web_application_targets, rejects_ftp_url)
{
  gchar *given;

  given = g_strdup ("ftp://example.com");

  assert_that (valid_web_application_url (given), is_equal_to (-1));

  g_free (given);
}

Ensure (manage_web_application_targets, rejects_url_without_host)
{
  gchar *given;

  given = g_strdup ("https://");

  assert_that (valid_web_application_url (given), is_equal_to (-1));

  g_free (given);
}

Ensure (manage_web_application_targets, rejects_invalid_port)
{
  gchar *given;

  given = g_strdup ("https://example.com:99999");

  assert_that (valid_web_application_url (given), is_equal_to (-1));

  g_free (given);
}

Ensure (manage_web_application_targets, clean_urls_trims_spaces)
{
  gchar *cleaned;

  cleaned = clean_urls (" https://example.com , https://example.org ");

  assert_that (cleaned,
               is_equal_to_string ("https://example.com,https://example.org"));

  g_free (cleaned);
}

Ensure (manage_web_application_targets, clean_urls_converts_newlines_to_commas)
{
  gchar *cleaned;

  cleaned = clean_urls ("https://example.com\nhttps://example.org");

  assert_that (cleaned,
               is_equal_to_string ("https://example.com,https://example.org"));

  g_free (cleaned);
}

Ensure (manage_web_application_targets, clean_urls_removes_empty_entries)
{
  gchar *cleaned;

  cleaned = clean_urls ("https://example.com,, ,https://example.org,");

  assert_that (cleaned,
               is_equal_to_string ("https://example.com,https://example.org"));

  g_free (cleaned);
}

Ensure (manage_web_application_targets, clean_urls_removes_duplicates)
{
  gchar *cleaned;

  cleaned = clean_urls ("https://example.com,https://example.com,https://example.org");

  assert_that (cleaned,
               is_equal_to_string ("https://example.com,https://example.org"));

  g_free (cleaned);
}

Ensure (manage_web_application_targets, clean_urls_returns_null_for_null_input)
{
  gchar *cleaned;

  cleaned = clean_urls (NULL);

  assert_that (cleaned, is_null);
}

Ensure (manage_web_application_targets, clean_urls_returns_null_for_empty_input)
{
  gchar *cleaned;

  cleaned = clean_urls ("");

  assert_that (cleaned, is_null);
}

Ensure (manage_web_application_targets, clean_urls_returns_empty_string_for_only_separators)
{
  gchar *cleaned;

  cleaned = clean_urls (",, ,\n,");

  assert_that (cleaned, is_equal_to_string (""));

  g_free (cleaned);
}

Ensure (manage_web_application_targets, validates_single_url)
{
  gchar *error_message = NULL;

  assert_that (validate_web_application_urls ("https://example.com",
                                              &error_message),
               is_equal_to (TRUE));
  assert_that (error_message, is_null);
}

Ensure (manage_web_application_targets, validates_multiple_urls)
{
  gchar *error_message = NULL;

  assert_that (validate_web_application_urls
                 ("https://example.com,http://example.org:8080",
                  &error_message),
               is_equal_to (TRUE));
  assert_that (error_message, is_null);
}

Ensure (manage_web_application_targets, rejects_null_urls_list)
{
  gchar *error_message = NULL;

  assert_that (validate_web_application_urls (NULL, &error_message),
               is_equal_to (FALSE));
  assert_that (error_message, is_null);
}

Ensure (manage_web_application_targets, rejects_empty_entry_in_urls_list)
{
  gchar *error_message = NULL;

  assert_that (validate_web_application_urls ("https://example.com,",
                                              &error_message),
               is_equal_to (FALSE));
  assert_that (error_message, is_equal_to_string ("URL cannot be empty"));

  g_free (error_message);
}

Ensure (manage_web_application_targets, rejects_invalid_url_in_urls_list)
{
  gchar *error_message = NULL;

  assert_that (validate_web_application_urls
                 ("https://example.com,ftp://example.org",
                  &error_message),
               is_equal_to (FALSE));
  assert_that (error_message,
               is_equal_to_string ("Invalid web application URL"));

  g_free (error_message);
}

/* Test suite. */

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, manage_web_application_targets,
                         allocates_web_application_target_data);

  add_test_with_context (suite, manage_web_application_targets,
                         frees_null_web_application_target_data);

  add_test_with_context (suite, manage_web_application_targets,
                         accepts_http_url);

  add_test_with_context (suite, manage_web_application_targets,
                         accepts_https_url);

  add_test_with_context (suite, manage_web_application_targets,
                         accepts_https_url_with_path);

  add_test_with_context (suite, manage_web_application_targets,
                         accepts_https_url_with_query);

  add_test_with_context (suite, manage_web_application_targets,
                         accepts_https_url_with_fragment);

  add_test_with_context (suite, manage_web_application_targets,
                         accepts_localhost_url);

  add_test_with_context (suite, manage_web_application_targets,
                         accepts_ipv4_url);

  add_test_with_context (suite, manage_web_application_targets,
                         accepts_ipv6_url_with_brackets);

  add_test_with_context (suite, manage_web_application_targets,
                         rejects_null_url);

  add_test_with_context (suite, manage_web_application_targets,
                         rejects_empty_url);

  add_test_with_context (suite, manage_web_application_targets,
                         rejects_url_without_scheme);

  add_test_with_context (suite, manage_web_application_targets,
                         rejects_ftp_url);

  add_test_with_context (suite, manage_web_application_targets,
                         rejects_url_without_host);

  add_test_with_context (suite, manage_web_application_targets,
                         rejects_invalid_port);

  add_test_with_context (suite, manage_web_application_targets,
                         clean_urls_trims_spaces);

  add_test_with_context (suite, manage_web_application_targets,
                         clean_urls_converts_newlines_to_commas);

  add_test_with_context (suite, manage_web_application_targets,
                         clean_urls_removes_empty_entries);

  add_test_with_context (suite, manage_web_application_targets,
                         clean_urls_removes_duplicates);

  add_test_with_context (suite, manage_web_application_targets,
                         clean_urls_returns_null_for_null_input);

  add_test_with_context (suite, manage_web_application_targets,
                         clean_urls_returns_null_for_empty_input);

  add_test_with_context (suite, manage_web_application_targets,
                         clean_urls_returns_empty_string_for_only_separators);

  add_test_with_context (suite, manage_web_application_targets,
                         validates_single_url);

  add_test_with_context (suite, manage_web_application_targets,
                         validates_multiple_urls);

  add_test_with_context (suite, manage_web_application_targets,
                         rejects_null_urls_list);

  add_test_with_context (suite, manage_web_application_targets,
                         rejects_empty_entry_in_urls_list);

  add_test_with_context (suite, manage_web_application_targets,
                         rejects_invalid_url_in_urls_list);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
