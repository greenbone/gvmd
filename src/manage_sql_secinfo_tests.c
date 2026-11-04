/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_secinfo.c"

#include <cgreen/cgreen.h>

Describe (manage_sql_secinfo);
BeforeEach (manage_sql_secinfo) {}
AfterEach (manage_sql_secinfo) {}

long long int __wrap_sql_int64_0 (const char *sql, ...);

long long int
__wrap_sql_int64_0 (const char *sql, ...)
{
  return 1;
}

static cJSON *
parse_cve_with_spanish_description ()
{
  return cJSON_Parse ("{\"cve\":{"
                      "\"id\":\"CVE-2026-1\","
                      "\"published\":\"2026-01-01T00:00:00Z\","
                      "\"lastModified\":\"2026-01-01T00:00:00Z\","
                      "\"metrics\":{},"
                      "\"descriptions\":[{\"lang\":\"es\",\"value\":\"x\"}],"
                      "\"configurations\":[],"
                      "\"references\":[]}}");
}

Ensure (manage_sql_secinfo,
        handle_json_cve_item_inserts_handles_missing_description)
{
  cJSON *vuln_item;

  vuln_item = parse_cve_with_spanish_description ();
  assert_that (vuln_item, is_not_null);

  assert_that (handle_json_cve_item_inserts (vuln_item), is_equal_to (0));

  cJSON_Delete (vuln_item);
}

Ensure (manage_sql_secinfo,
        get_cve_json_fields_initialises_description_value)
{
  cJSON *vuln_item;
  gchar *cve_id, *vector, *description_value;
  time_t published_time, modified_time;
  double score_dbl;
  cJSON *configurations_array, *references_array;
  gchar *escaped_description;

  vuln_item = parse_cve_with_spanish_description ();
  assert_that (vuln_item, is_not_null);

  assert_that (get_cve_json_fields (vuln_item,
                                    &cve_id,
                                    &published_time,
                                    &modified_time,
                                    &vector,
                                    &score_dbl,
                                    &description_value,
                                    &configurations_array,
                                    &references_array),
               is_equal_to (0));

  escaped_description = sql_copy_escape (description_value);
  g_free (escaped_description);

  cJSON_Delete (vuln_item);
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context
    (suite, manage_sql_secinfo,
     handle_json_cve_item_inserts_handles_missing_description);
  add_test_with_context
    (suite, manage_sql_secinfo,
     get_cve_json_fields_initialises_description_value);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
