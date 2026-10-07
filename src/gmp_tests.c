/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gmp.c"

#include <cgreen/cgreen.h>

Describe (gmp);
BeforeEach (gmp) {}
AfterEach (gmp) {}

static int
dummy_client_writer (const char *message, void *data)
{
  return 0;
}

Ensure (gmp, create_report_config_restores_authenticated_state)
{
  gmp_parser_t gmp_parser = { 0 };
  GError *error = NULL;

  gmp_parser.client_writer = dummy_client_writer;
  client_state = CLIENT_CREATE_REPORT_CONFIG;
  create_report_config_start (&gmp_parser, NULL, NULL);

  gmp_xml_handle_end_element (NULL, "create_report_config", &gmp_parser,
                              &error);

  assert_that (error, is_null);
  assert_that (client_state, is_equal_to (CLIENT_AUTHENTIC));
}

Ensure (gmp, modify_report_config_restores_authenticated_state)
{
  gmp_parser_t gmp_parser = { 0 };
  GError *error = NULL;

  gmp_parser.client_writer = dummy_client_writer;
  client_state = CLIENT_MODIFY_REPORT_CONFIG;
  modify_report_config_start (&gmp_parser, NULL, NULL);

  gmp_xml_handle_end_element (NULL, "modify_report_config", &gmp_parser,
                              &error);

  assert_that (error, is_null);
  assert_that (client_state, is_equal_to (CLIENT_AUTHENTIC));
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context
    (suite, gmp, create_report_config_restores_authenticated_state);
  add_test_with_context
    (suite, gmp, modify_report_config_restores_authenticated_state);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
