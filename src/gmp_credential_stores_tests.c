/* Copyright (C) 2025 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gmp_credential_stores.c"

#include <cgreen/cgreen.h>
#include <gvm/util/xmlutils.h>

Describe (gmp_credential_stores);
BeforeEach (gmp_credential_stores) {}
AfterEach (gmp_credential_stores) {}

/* Helper to capture client output into a GString for assertions. */

static GString *captured_output;

static int
capture_writer (const char *data, void *user_data)
{
  g_string_append (captured_output, data);
  return 0;
}

/* Mock functions to avoid actual database access. */

static int mock_acl_user_may_result = 1;  // Default: permission granted
static int mock_find_resource_result = 0; // Default: resource found

void
__wrap_sql_begin_immediate ()
{
  // Mock implementation - no database transaction started
}

void
__wrap_sql_rollback ()
{
  // Mock implementation - no database rollback
}

int
__wrap_acl_user_may (const char *action)
{
  return mock_acl_user_may_result;
}

int
__wrap_find_resource_with_permission (const char *resource_type,
                                      const char *resource_id,
                                      credential_store_t *credential_store,
                                      const char *permission,
                                      int trash)
{
  if (mock_find_resource_result == 0)
    {
      *credential_store = 1;
      return 0; // Success
    }
  return mock_find_resource_result; // Return the error code
}

char *
__wrap_sql_string (char* sql, ...)
{
  return g_strdup ("Example string from __wrap_sql_string");
}


/* modify_credential_store_run */

Ensure (gmp_credential_stores,
        modify_credential_store_run_sends_invalid_host_message)
{
  gmp_parser_t parser;
  GError *error = NULL;
  entity_t entity;
  const char *xml =
    "<modify_credential_store credential_store_id=\"12345\">"
    "  <host></host>"
    "</modify_credential_store>";

  captured_output = g_string_new ("");

  /* Set up parser with our capture writer. */
  memset (&parser, 0, sizeof (parser));
  parser.client_writer = capture_writer;
  parser.client_writer_data = NULL;

  modify_credential_store_data.context = g_malloc0 (sizeof (context_data_t));

  /* Parse the XML string into an entity. */
  if (parse_entity (xml, &entity))
    {
      g_string_free (captured_output, TRUE);
      modify_credential_store_reset ();
      g_free (modify_credential_store_data.context);
      fail_test ("Failed to parse XML");
    }

  modify_credential_store_data.context->first = g_slist_prepend (NULL, entity);
  modify_credential_store_data.context->done = 1;

  /* Set up mocks for invalid host scenario */
  mock_acl_user_may_result = 1; // Permission granted
  mock_find_resource_result = 0; // Resource found

  modify_credential_store_run (&parser, &error);

  /* Assert that the response contains the expected error status and text. */
  assert_that (captured_output->str, contains_string ("status=\"400\""));
  assert_that (captured_output->str, contains_string ("Invalid host: host must not be empty"));

  /* Cleanup. */
  g_string_free (captured_output, TRUE);
  modify_credential_store_reset ();
}

/* Test suite. */

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, gmp_credential_stores,
                         modify_credential_store_run_sends_invalid_host_message);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
