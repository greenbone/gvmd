/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_sql_secinfo.c"

#include <cgreen/cgreen.h>
#include <stdarg.h>
#include <string.h>

static long saved_root_id, saved_node_id;
static cJSON *test_item;
static db_copy_buffer_t copy_buffer;
static gboolean copy_buffer_initialized;

Describe (manage_sql_secinfo);
BeforeEach (manage_sql_secinfo)
{
  saved_root_id = saved_node_id = -1;
  secinfo_fast_init = 0;
  test_item = NULL;
  copy_buffer_initialized = FALSE;
}
AfterEach (manage_sql_secinfo)
{
  cJSON_Delete (test_item);
  if (copy_buffer_initialized)
    db_copy_buffer_cleanup (&copy_buffer);
}

long long int
__wrap_sql_int64_0 (const char *sql, ...);

long long int
__wrap_sql_int64_0 (const char *sql, ...)
{
  return 1;
}

void
__wrap_sql (const char *format, ...);

void
__wrap_sql (const char *format, ...)
{
  if (strstr (format, "UPDATE scap2.cpe_match_nodes"))
    {
      va_list args;
      va_start (args, format);
      saved_root_id = va_arg (args, long);
      saved_node_id = va_arg (args, long);
      va_end (args);
    }
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
  int result;
  test_item = parse_cve_with_spanish_description ();

  result = handle_json_cve_item_inserts (test_item);

  assert_that (test_item, is_not_null);
  assert_that (result, is_equal_to (0));
}

Ensure (manage_sql_secinfo, get_cve_json_fields_initialises_description_value)
{
  gchar *cve_id, *vector, *description_value = "not initialized";
  time_t published_time, modified_time;
  double score_dbl;
  cJSON *configurations_array, *references_array;
  int result;
  test_item = parse_cve_with_spanish_description ();

  result = get_cve_json_fields (
    test_item, &cve_id, &published_time, &modified_time, &vector, &score_dbl,
    &description_value, &configurations_array, &references_array);

  assert_that (test_item, is_not_null);
  assert_that (result, is_equal_to (0));
  assert_that (description_value, is_null);
}

Ensure (manage_sql_secinfo, normal_import_assigns_missing_root_id)
{
  resource_t node_id = 0, root_id = -1;
  int result;

  result = handle_cve_configuration_node (7, "OR", 0, &node_id, &root_id, NULL);

  assert_that (result, is_equal_to (0));
  assert_that (root_id, is_equal_to (node_id));
  assert_that (saved_root_id, is_equal_to (node_id));
  assert_that (saved_node_id, is_equal_to (node_id));
}

Ensure (manage_sql_secinfo, normal_import_preserves_existing_root_id)
{
  resource_t node_id = 0, root_id = 42;
  int result;

  result = handle_cve_configuration_node (7, "OR", 0, &node_id, &root_id, NULL);

  assert_that (result, is_equal_to (0));
  assert_that (root_id, is_equal_to (42));
  assert_that (saved_root_id, is_equal_to (42));
}

Ensure (manage_sql_secinfo, fast_import_assigns_missing_root_id)
{
  resource_t node_id = 0, root_id = -1;
  int result;
  secinfo_fast_init = 1;
  db_copy_buffer_init (&copy_buffer, 1024, "COPY unused FROM STDIN");
  copy_buffer_initialized = TRUE;

  result = handle_cve_configuration_node (7, "OR", 0, &node_id, &root_id,
                                          &copy_buffer);

  assert_that (result, is_equal_to (0));
  assert_that (root_id, is_equal_to (node_id));
  assert_that (copy_buffer.data->str, is_equal_to_string ("1\t1\t7\tOR\t0\n"));
}

Ensure (manage_sql_secinfo, accepts_single_node_without_operator)
{
  cJSON *nodes;
  char *operator;
  int negate = -1, result;
  test_item = cJSON_Parse ("{\"nodes\":[{}]}");

  result = get_cve_configuration_fields (test_item, "CVE-2026-1", &nodes,
                                         &operator, & negate);

  assert_that (result, is_equal_to (0));
  assert_that (operator, is_null);
  assert_that (negate, is_equal_to (0));
}

Ensure (manage_sql_secinfo, accepts_multiple_nodes_with_operator)
{
  cJSON *nodes;
  char *operator;
  int negate, result;
  test_item = cJSON_Parse ("{\"operator\":\"AND\",\"nodes\":[{},{}]}");

  result = get_cve_configuration_fields (test_item, "CVE-2026-1", &nodes,
                                         &operator, & negate);

  assert_that (result, is_equal_to (0));
  assert_that (operator, is_equal_to_string ("AND"));
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite = create_test_suite ();

  add_test_with_context (
    suite, manage_sql_secinfo,
    handle_json_cve_item_inserts_handles_missing_description);
  add_test_with_context (suite, manage_sql_secinfo,
                         get_cve_json_fields_initialises_description_value);
  add_test_with_context (suite, manage_sql_secinfo,
                         normal_import_assigns_missing_root_id);
  add_test_with_context (suite, manage_sql_secinfo,
                         normal_import_preserves_existing_root_id);
  add_test_with_context (suite, manage_sql_secinfo,
                         fast_import_assigns_missing_root_id);
  add_test_with_context (suite, manage_sql_secinfo,
                         accepts_single_node_without_operator);
  add_test_with_context (suite, manage_sql_secinfo,
                         accepts_multiple_nodes_with_operator);
  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());
  destroy_test_suite (suite);
  return ret;
}
