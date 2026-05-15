/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "manage_scanner_relays.c"

#include <cgreen/cgreen.h>

#include <glib/gstdio.h>
#include <string.h>
#include <unistd.h>

Describe (manage_scanner_relays);
BeforeEach (manage_scanner_relays)
{
  set_relays_path (NULL);
}
AfterEach (manage_scanner_relays)
{
  set_relays_path (NULL);
}

static cJSON *
parse_json (const char *json)
{
  return cJSON_ParseWithLength (json, strlen (json));
}

static int
write_temp_relays_file (const char *content, gchar **path_out)
{
  GError *error = NULL;
  int fd;

  fd = g_file_open_tmp ("gvmd-test-relays-XXXXXX", path_out, &error);
  if (fd == -1)
    {
      g_warning ("%s: could not create temp file: %s", __func__,
                 error->message);
      g_error_free (error);
      return -1;
    }
  close (fd);

  if (!g_file_set_contents (*path_out, content, -1, &error))
    {
      g_warning ("%s: could not write temp file: %s", __func__,
                 error->message);
      g_error_free (error);
      g_unlink (*path_out);
      g_free (*path_out);
      *path_out = NULL;
      return -1;
    }
  return 0;
}


/* set_relays_path */

Ensure (manage_scanner_relays, set_relays_path_null_disables)
{
  set_relays_path (NULL);
  assert_that (get_relays_path (), is_null);
  assert_that (relays_managed_externally (), is_false);
}

Ensure (manage_scanner_relays, set_relays_path_empty_disables)
{
  set_relays_path ("");
  assert_that (get_relays_path (), is_null);
  assert_that (relays_managed_externally (), is_false);
}

Ensure (manage_scanner_relays, set_relays_path_sets_path)
{
  set_relays_path ("/tmp/test.json");
  assert_that (get_relays_path (), is_equal_to_string ("/tmp/test.json"));
  assert_that (relays_managed_externally (), is_true);
}

Ensure (manage_scanner_relays, set_relays_path_overwrites_previous)
{
  set_relays_path ("/tmp/first.json");
  set_relays_path ("/tmp/second.json");
  assert_that (get_relays_path (), is_equal_to_string ("/tmp/second.json"));
}


/* scanner_type_matches_relay */

Ensure (manage_scanner_relays, scanner_type_matches_relay_osp_matches_osp)
{
  assert_that (scanner_type_matches_relay (SCANNER_TYPE_OSP_SENSOR, "osp"),
               is_true);
}

Ensure (manage_scanner_relays,
        scanner_type_matches_relay_osp_case_insensitive)
{
  assert_that (scanner_type_matches_relay (SCANNER_TYPE_OSP_SENSOR, "OSP"),
               is_true);
  assert_that (scanner_type_matches_relay (SCANNER_TYPE_OSP_SENSOR, "Osp"),
               is_true);
}

Ensure (manage_scanner_relays,
        scanner_type_matches_relay_osp_matches_null)
{
  assert_that (scanner_type_matches_relay (SCANNER_TYPE_OSP_SENSOR, NULL),
               is_true);
}

Ensure (manage_scanner_relays,
        scanner_type_matches_relay_osp_rejects_other)
{
  assert_that (scanner_type_matches_relay (SCANNER_TYPE_OSP_SENSOR, "openvasd"),
               is_false);
  assert_that (scanner_type_matches_relay (SCANNER_TYPE_OSP_SENSOR,
                                           "agent-control"),
               is_false);
  assert_that (scanner_type_matches_relay (SCANNER_TYPE_OSP_SENSOR, ""),
               is_false);
}

Ensure (manage_scanner_relays,
        scanner_type_matches_relay_openvasd_matches_openvasd)
{
  assert_that (scanner_type_matches_relay (SCANNER_TYPE_OPENVASD_SENSOR,
                                           "openvasd"),
               is_true);
  assert_that (scanner_type_matches_relay (SCANNER_TYPE_OPENVASD_SENSOR,
                                           NULL),
               is_true);
}

Ensure (manage_scanner_relays,
        scanner_type_matches_relay_agent_control_matches_agent_control)
{
  assert_that (scanner_type_matches_relay
                (SCANNER_TYPE_AGENT_CONTROLLER_SENSOR, "agent-control"),
               is_true);
  assert_that (scanner_type_matches_relay
                (SCANNER_TYPE_AGENT_CONTROLLER_SENSOR, NULL),
               is_true);
}

Ensure (manage_scanner_relays,
        scanner_type_matches_relay_unknown_type_returns_false)
{
  assert_that (scanner_type_matches_relay (999, "osp"), is_false);
  assert_that (scanner_type_matches_relay (999, NULL), is_false);
}


/* extract_relays_fields_from_root_cjson */

Ensure (manage_scanner_relays,
        extract_relays_fields_from_root_cjson_null_input)
{
  assert_that (extract_relays_fields_from_root_cjson (NULL, NULL),
               is_equal_to (-1));
}

Ensure (manage_scanner_relays,
        extract_relays_fields_from_root_cjson_not_object)
{
  cJSON *root = parse_json ("\"not an object\"");

  assert_that (extract_relays_fields_from_root_cjson (root, NULL),
               is_equal_to (-1));
  cJSON_Delete (root);
}

Ensure (manage_scanner_relays,
        extract_relays_fields_from_root_cjson_missing_relays_key)
{
  cJSON *root = parse_json ("{\"something\": \"else\"}");

  assert_that (extract_relays_fields_from_root_cjson (root, NULL),
               is_equal_to (-1));
  cJSON_Delete (root);
}

Ensure (manage_scanner_relays,
        extract_relays_fields_from_root_cjson_relays_not_array)
{
  cJSON *root = parse_json ("{\"relays\": \"not-an-array\"}");

  assert_that (extract_relays_fields_from_root_cjson (root, NULL),
               is_equal_to (-1));
  cJSON_Delete (root);
}

Ensure (manage_scanner_relays,
        extract_relays_fields_from_root_cjson_valid_empty_relays)
{
  cJSON *root = parse_json ("{\"relays\": []}");
  cJSON *relays_out = NULL;

  assert_that (extract_relays_fields_from_root_cjson (root, &relays_out),
               is_equal_to (0));
  assert_that (relays_out, is_non_null);
  assert_that (cJSON_GetArraySize (relays_out), is_equal_to (0));
  cJSON_Delete (root);
}

Ensure (manage_scanner_relays,
        extract_relays_fields_from_root_cjson_relays_out_null)
{
  cJSON *root = parse_json ("{\"relays\": []}");

  assert_that (extract_relays_fields_from_root_cjson (root, NULL),
               is_equal_to (0));
  cJSON_Delete (root);
}


/* extract_relay_fields_from_json_item */

Ensure (manage_scanner_relays,
        extract_relay_fields_from_json_item_null_output)
{
  assert_that (extract_relay_fields_from_json_item (NULL, NULL),
               is_equal_to (-1));
}

Ensure (manage_scanner_relays,
        extract_relay_fields_from_json_item_null_input)
{
  relays_list_item_t parsed;

  assert_that (extract_relay_fields_from_json_item (NULL, &parsed),
               is_equal_to (-1));
}

Ensure (manage_scanner_relays,
        extract_relay_fields_from_json_item_all_fields)
{
  cJSON *item = parse_json ("{"
                            "\"original_host\": \"10.0.0.1\","
                            "\"original_port\": 9390,"
                            "\"relay_host\": \"relay.example.com\","
                            "\"relay_port\": 443,"
                            "\"scanner_type\": \"osp\""
                            "}");
  relays_list_item_t parsed;

  assert_that (extract_relay_fields_from_json_item (item, &parsed),
               is_equal_to (0));
  assert_that (parsed.original_host, is_equal_to_string ("10.0.0.1"));
  assert_that (parsed.original_port, is_equal_to (9390));
  assert_that (parsed.relay_host, is_equal_to_string ("relay.example.com"));
  assert_that (parsed.relay_port, is_equal_to (443));
  assert_that (parsed.scanner_type, is_equal_to_string ("osp"));
  cJSON_Delete (item);
}

Ensure (manage_scanner_relays,
        extract_relay_fields_from_json_item_missing_original_host)
{
  cJSON *item = parse_json ("{"
    "\"relay_host\": \"relay.example.com\","
    "\"scanner_type\": \"osp\""
  "}");
  relays_list_item_t parsed;

  assert_that (extract_relay_fields_from_json_item (item, &parsed),
               is_equal_to (-1));
  cJSON_Delete (item);
}

Ensure (manage_scanner_relays,
        extract_relay_fields_from_json_item_missing_relay_host)
{
  cJSON *item = parse_json ("{"
    "\"original_host\": \"10.0.0.1\","
    "\"scanner_type\": \"osp\""
  "}");
  relays_list_item_t parsed;

  assert_that (extract_relay_fields_from_json_item (item, &parsed),
               is_equal_to (-1));
  cJSON_Delete (item);
}

Ensure (manage_scanner_relays,
        extract_relay_fields_from_json_item_missing_scanner_type)
{
  cJSON *item = parse_json ("{"
    "\"original_host\": \"10.0.0.1\","
    "\"relay_host\": \"relay.example.com\""
  "}");
  relays_list_item_t parsed;

  assert_that (extract_relay_fields_from_json_item (item, &parsed),
               is_equal_to (-1));
  cJSON_Delete (item);
}

Ensure (manage_scanner_relays,
        extract_relay_fields_from_json_item_optional_fields_default)
{
  cJSON *item = parse_json ("{"
                            "\"original_host\": \"10.0.0.1\","
                            "\"relay_host\": \"relay.example.com\","
                            "\"scanner_type\": \"osp\""
                            "}");
  relays_list_item_t parsed;

  assert_that (extract_relay_fields_from_json_item (item, &parsed),
               is_equal_to (0));
  assert_that (parsed.original_host, is_equal_to_string ("10.0.0.1"));
  assert_that (parsed.original_port, is_equal_to (0));
  assert_that (parsed.relay_host, is_equal_to_string ("relay.example.com"));
  assert_that (parsed.relay_port, is_equal_to (0));
  assert_that (parsed.scanner_type, is_equal_to_string ("osp"));
  cJSON_Delete (item);
}


/* get_single_relay_from_file */

Ensure (manage_scanner_relays,
        get_single_relay_from_file_null_relay_host)
{
  int port = 42;

  assert_that (get_single_relay_from_file (SCANNER_TYPE_OSP_SENSOR,
                                           "10.0.0.1", 0, NULL, &port),
               is_equal_to (-1));
}

Ensure (manage_scanner_relays,
        get_single_relay_from_file_null_relay_port)
{
  char *host = NULL;

  assert_that (get_single_relay_from_file (SCANNER_TYPE_OSP_SENSOR,
                                           "10.0.0.1", 0, &host, NULL),
               is_equal_to (-1));
}

Ensure (manage_scanner_relays,
        get_single_relay_from_file_no_relays_path_set)
{
  char *relay_host = NULL;
  int relay_port = 0;

  set_relays_path (NULL);
  assert_that (get_single_relay_from_file (SCANNER_TYPE_OSP_SENSOR,
                                           "10.0.0.1", 0,
                                           &relay_host, &relay_port),
               is_equal_to (-1));
  assert_that (relay_host, is_null);
  assert_that (relay_port, is_equal_to (0));
}

Ensure (manage_scanner_relays,
        get_single_relay_from_file_file_not_found)
{
  char *relay_host = NULL;
  int relay_port = 0;

  set_relays_path ("/tmp/gvmd-test-nonexistent-relays.json");
  assert_that (get_single_relay_from_file (SCANNER_TYPE_OSP_SENSOR,
                                           "10.0.0.1", 0,
                                           &relay_host, &relay_port),
               is_equal_to (-1));
  assert_that (relay_host, is_null);
  assert_that (relay_port, is_equal_to (0));
}

Ensure (manage_scanner_relays,
        get_single_relay_from_file_invalid_json)
{
  gchar *path = NULL;
  char *relay_host = NULL;
  int relay_port = 0;

  assert_that (write_temp_relays_file ("not valid json", &path),
               is_equal_to (0));
  set_relays_path (path);
  assert_that (get_single_relay_from_file (SCANNER_TYPE_OSP_SENSOR,
                                           "10.0.0.1", 0,
                                           &relay_host, &relay_port),
               is_equal_to (-1));
  assert_that (relay_host, is_null);
  g_unlink (path);
  g_free (path);
}

Ensure (manage_scanner_relays,
        get_single_relay_from_file_matches_by_host_and_type)
{
  gchar *path = NULL;
  char *relay_host = NULL;
  int relay_port = 0;
  const char *json = "{"
    "\"relays\": [{"
    "  \"original_host\": \"10.0.0.1\","
    "  \"scanner_type\": \"osp\","
    "  \"relay_host\": \"relay.example.com\","
    "  \"relay_port\": 443"
    "}]"
  "}";

  assert_that (write_temp_relays_file (json, &path), is_equal_to (0));
  set_relays_path (path);
  assert_that (get_single_relay_from_file (SCANNER_TYPE_OSP_SENSOR,
                                           "10.0.0.1", 0,
                                           &relay_host, &relay_port),
               is_equal_to (0));
  assert_that (relay_host, is_equal_to_string ("relay.example.com"));
  assert_that (relay_port, is_equal_to (443));
  g_free (relay_host);
  g_unlink (path);
  g_free (path);
}

Ensure (manage_scanner_relays,
        get_single_relay_from_file_matches_by_host_type_and_port)
{
  gchar *path = NULL;
  char *relay_host = NULL;
  int relay_port = 0;
  const char *json = "{"
    "\"relays\": [{"
    "  \"original_host\": \"10.0.0.1\","
    "  \"original_port\": 9390,"
    "  \"scanner_type\": \"osp\","
    "  \"relay_host\": \"relay.example.com\","
    "  \"relay_port\": 443"
    "}]"
  "}";

  assert_that (write_temp_relays_file (json, &path), is_equal_to (0));
  set_relays_path (path);
  assert_that (get_single_relay_from_file (SCANNER_TYPE_OSP_SENSOR,
                                           "10.0.0.1", 9390,
                                           &relay_host, &relay_port),
               is_equal_to (0));
  assert_that (relay_host, is_equal_to_string ("relay.example.com"));
  assert_that (relay_port, is_equal_to (443));
  g_free (relay_host);
  g_unlink (path);
  g_free (path);
}

Ensure (manage_scanner_relays,
        get_single_relay_from_file_no_match_different_host)
{
  gchar *path = NULL;
  char *relay_host = NULL;
  int relay_port = 0;
  const char *json = "{"
    "\"relays\": [{"
    "  \"original_host\": \"10.0.0.1\","
    "  \"scanner_type\": \"osp\","
    "  \"relay_host\": \"relay.example.com\","
    "  \"relay_port\": 443"
    "}]"
  "}";

  assert_that (write_temp_relays_file (json, &path), is_equal_to (0));
  set_relays_path (path);
  assert_that (get_single_relay_from_file (SCANNER_TYPE_OSP_SENSOR,
                                           "10.0.0.2", 0,
                                           &relay_host, &relay_port),
               is_equal_to (0));
  assert_that (relay_host, is_null);
  assert_that (relay_port, is_equal_to (0));
  g_unlink (path);
  g_free (path);
}

Ensure (manage_scanner_relays,
        get_single_relay_from_file_no_match_different_type)
{
  gchar *path = NULL;
  char *relay_host = NULL;
  int relay_port = 0;
  const char *json = "{"
    "\"relays\": [{"
    "  \"original_host\": \"10.0.0.1\","
    "  \"scanner_type\": \"osp\","
    "  \"relay_host\": \"relay.example.com\","
    "  \"relay_port\": 443"
    "}]"
  "}";

  assert_that (write_temp_relays_file (json, &path), is_equal_to (0));
  set_relays_path (path);
  assert_that (get_single_relay_from_file (SCANNER_TYPE_OPENVASD_SENSOR,
                                           "10.0.0.1", 0,
                                           &relay_host, &relay_port),
               is_equal_to (0));
  assert_that (relay_host, is_null);
  g_unlink (path);
  g_free (path);
}

Ensure (manage_scanner_relays,
        get_single_relay_from_file_no_match_different_port)
{
  gchar *path = NULL;
  char *relay_host = NULL;
  int relay_port = 0;
  const char *json = "{"
    "\"relays\": [{"
    "  \"original_host\": \"10.0.0.1\","
    "  \"original_port\": 9390,"
    "  \"scanner_type\": \"osp\","
    "  \"relay_host\": \"relay.example.com\","
    "  \"relay_port\": 443"
    "}]"
  "}";

  assert_that (write_temp_relays_file (json, &path), is_equal_to (0));
  set_relays_path (path);
  assert_that (get_single_relay_from_file (SCANNER_TYPE_OSP_SENSOR,
                                           "10.0.0.1", 9391,
                                           &relay_host, &relay_port),
               is_equal_to (0));
  assert_that (relay_host, is_null);
  g_unlink (path);
  g_free (path);
}

Ensure (manage_scanner_relays,
        get_single_relay_from_file_last_match_wins)
{
  gchar *path = NULL;
  char *relay_host = NULL;
  int relay_port = 0;
  const char *json = "{"
    "\"relays\": ["
    "  {"
    "    \"original_host\": \"10.0.0.1\","
    "    \"scanner_type\": \"osp\","
    "    \"relay_host\": \"first.example.com\","
    "    \"relay_port\": 111"
    "  },"
    "  {"
    "    \"original_host\": \"10.0.0.1\","
    "    \"scanner_type\": \"osp\","
    "    \"relay_host\": \"second.example.com\","
    "    \"relay_port\": 222"
    "  }"
    "]"
  "}";

  assert_that (write_temp_relays_file (json, &path), is_equal_to (0));
  set_relays_path (path);
  assert_that (get_single_relay_from_file (SCANNER_TYPE_OSP_SENSOR,
                                           "10.0.0.1", 0,
                                           &relay_host, &relay_port),
               is_equal_to (0));
  assert_that (relay_host, is_equal_to_string ("second.example.com"));
  assert_that (relay_port, is_equal_to (222));
  g_free (relay_host);
  g_unlink (path);
  g_free (path);
}

Ensure (manage_scanner_relays,
        get_single_relay_from_file_empty_relays_array)
{
  gchar *path = NULL;
  char *relay_host = NULL;
  int relay_port = 0;
  const char *json = "{ \"relays\": [] }";

  assert_that (write_temp_relays_file (json, &path), is_equal_to (0));
  set_relays_path (path);
  assert_that (get_single_relay_from_file (SCANNER_TYPE_OSP_SENSOR,
                                           "10.0.0.1", 0,
                                           &relay_host, &relay_port),
               is_equal_to (0));
  assert_that (relay_host, is_null);
  assert_that (relay_port, is_equal_to (0));
  g_unlink (path);
  g_free (path);
}


/* Test suite. */

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, manage_scanner_relays,
                         set_relays_path_null_disables);
  add_test_with_context (suite, manage_scanner_relays,
                         set_relays_path_empty_disables);
  add_test_with_context (suite, manage_scanner_relays,
                         set_relays_path_sets_path);
  add_test_with_context (suite, manage_scanner_relays,
                         set_relays_path_overwrites_previous);

  add_test_with_context (suite, manage_scanner_relays,
                         scanner_type_matches_relay_osp_matches_osp);
  add_test_with_context (suite, manage_scanner_relays,
                         scanner_type_matches_relay_osp_case_insensitive);
  add_test_with_context (suite, manage_scanner_relays,
                         scanner_type_matches_relay_osp_matches_null);
  add_test_with_context (suite, manage_scanner_relays,
                         scanner_type_matches_relay_osp_rejects_other);
  add_test_with_context (suite, manage_scanner_relays,
                         scanner_type_matches_relay_openvasd_matches_openvasd);
  add_test_with_context (suite, manage_scanner_relays,
                         scanner_type_matches_relay_agent_control_matches_agent_control);
  add_test_with_context (suite, manage_scanner_relays,
                         scanner_type_matches_relay_unknown_type_returns_false);

  add_test_with_context (suite, manage_scanner_relays,
                         extract_relays_fields_from_root_cjson_null_input);
  add_test_with_context (suite, manage_scanner_relays,
                         extract_relays_fields_from_root_cjson_not_object);
  add_test_with_context (suite, manage_scanner_relays,
                         extract_relays_fields_from_root_cjson_missing_relays_key);
  add_test_with_context (suite, manage_scanner_relays,
                         extract_relays_fields_from_root_cjson_relays_not_array);
  add_test_with_context (suite, manage_scanner_relays,
                         extract_relays_fields_from_root_cjson_valid_empty_relays);
  add_test_with_context (suite, manage_scanner_relays,
                         extract_relays_fields_from_root_cjson_relays_out_null);

  add_test_with_context (suite, manage_scanner_relays,
                         extract_relay_fields_from_json_item_null_output);
  add_test_with_context (suite, manage_scanner_relays,
                         extract_relay_fields_from_json_item_null_input);
  add_test_with_context (suite, manage_scanner_relays,
                         extract_relay_fields_from_json_item_all_fields);
  add_test_with_context (suite, manage_scanner_relays,
                         extract_relay_fields_from_json_item_missing_original_host);
  add_test_with_context (suite, manage_scanner_relays,
                         extract_relay_fields_from_json_item_missing_relay_host);
  add_test_with_context (suite, manage_scanner_relays,
                         extract_relay_fields_from_json_item_missing_scanner_type);
  add_test_with_context (suite, manage_scanner_relays,
                         extract_relay_fields_from_json_item_optional_fields_default);

  add_test_with_context (suite, manage_scanner_relays,
                         get_single_relay_from_file_null_relay_host);
  add_test_with_context (suite, manage_scanner_relays,
                         get_single_relay_from_file_null_relay_port);
  add_test_with_context (suite, manage_scanner_relays,
                         get_single_relay_from_file_no_relays_path_set);
  add_test_with_context (suite, manage_scanner_relays,
                         get_single_relay_from_file_file_not_found);
  add_test_with_context (suite, manage_scanner_relays,
                         get_single_relay_from_file_invalid_json);
  add_test_with_context (suite, manage_scanner_relays,
                         get_single_relay_from_file_matches_by_host_and_type);
  add_test_with_context (suite, manage_scanner_relays,
                         get_single_relay_from_file_matches_by_host_type_and_port);
  add_test_with_context (suite, manage_scanner_relays,
                         get_single_relay_from_file_no_match_different_host);
  add_test_with_context (suite, manage_scanner_relays,
                         get_single_relay_from_file_no_match_different_type);
  add_test_with_context (suite, manage_scanner_relays,
                         get_single_relay_from_file_no_match_different_port);
  add_test_with_context (suite, manage_scanner_relays,
                         get_single_relay_from_file_last_match_wins);
  add_test_with_context (suite, manage_scanner_relays,
                         get_single_relay_from_file_empty_relays_array);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
