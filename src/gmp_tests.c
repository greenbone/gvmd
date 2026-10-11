/* Copyright (C) 2026 Greenbone AG
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

#include "gmp.c"

#include <cgreen/cgreen.h>
#include <glib/gstdio.h>
#include <unistd.h>

Describe (gmp);

static const gchar *report_export_uuid = "a3d1e516-d3e7-4f2a-b45f-b7be6f4b2f71";
static const gchar *report_uuid_value = "13a70b2e-c4d4-43ae-9492-6d2a09d1f2ca";
static const gchar *report_format_uuid_value =
  "5057e5cc-b825-11e4-9d0e-28d24461215b";
static const guchar report_export_contents[] = {
  0x00, 0x01, 0x02, 0x7f, 0x80, 0xff, '<', '&', '>', '\n', 0x00};

static GString *captured_output;
static gchar *report_export_path;
static gboolean fail_on_response_close;
static int report_export_delete_count;
static gmp_client_delivery_callback_t pending_delivery_callback;
static void *pending_delivery_data;

BeforeEach (gmp)
{
  captured_output = g_string_new ("");
  report_export_path = NULL;
  fail_on_response_close = FALSE;
  report_export_delete_count = 0;
  pending_delivery_callback = NULL;
  pending_delivery_data = NULL;
}

AfterEach (gmp)
{
  if (pending_delivery_callback)
    pending_delivery_callback (FALSE, pending_delivery_data);
  if (report_export_path)
    g_unlink (report_export_path);
  g_free (report_export_path);
  g_string_free (captured_output, TRUE);
}

static int
dummy_client_writer (const char *message, void *data)
{
  return 0;
}

static int
capture_client_writer (const char *message, void *data)
{
  (void) data;

  if (fail_on_response_close
      && strstr (message, "</download_report_export_response>"))
    return 1;

  g_string_append (captured_output, message);
  return 0;
}

static void
register_client_delivery (gmp_client_delivery_callback_t callback,
                          void *callback_data, void *register_data)
{
  (void) register_data;

  assert_that (pending_delivery_callback, is_null);
  pending_delivery_callback = callback;
  pending_delivery_data = callback_data;
}

static void
complete_client_delivery (gboolean success)
{
  gmp_client_delivery_callback_t callback = pending_delivery_callback;
  void *callback_data = pending_delivery_data;

  pending_delivery_callback = NULL;
  pending_delivery_data = NULL;
  callback (success, callback_data);
}

int
__wrap_acl_user_may (const char *permission)
{
  (void) permission;
  return 0;
}

gboolean
__wrap_find_report_export_with_permission (const char *uuid,
                                           report_export_t *report_export,
                                           const char *permission)
{
  assert_that (uuid, is_equal_to_string (report_export_uuid));
  assert_that (permission, is_equal_to_string ("get_report_exports"));
  *report_export = 42;
  return FALSE;
}

int
__wrap_load_report_export_data (report_export_t report_export,
                                report_export_data_t data)
{
  assert_that (report_export, is_equal_to (42));

  data->row_id = report_export;
  data->uuid = g_strdup (report_export_uuid);
  data->report = 101;
  data->report_format = 102;
  data->export_type = REPORT_EXPORT_TYPE_SCAN;
  data->status = REPORT_EXPORT_STATUS_DONE;
  data->progress = REPORT_EXPORT_PROGRESS_COMPLETED;
  data->file_path = g_strdup (report_export_path);
  data->file_size = sizeof (report_export_contents);
  data->content_type = g_strdup ("application/octet-stream");
  data->extension = g_strdup ("bin");
  return 0;
}

char *
__wrap_report_uuid (report_t report)
{
  assert_that (report, is_equal_to (101));
  return g_strdup (report_uuid_value);
}

char *
__wrap_report_format_uuid (report_format_t report_format)
{
  assert_that (report_format, is_equal_to (102));
  return g_strdup (report_format_uuid_value);
}

int
__wrap_manage_delete_report_export (report_export_t report_export,
                                    const gchar *file_path)
{
  assert_that (report_export, is_equal_to (42));
  assert_that (file_path, is_equal_to_string (report_export_path));
  report_export_delete_count++;
  return g_unlink (file_path);
}

static void
create_report_export_file (void)
{
  gssize offset = 0;
  int fd;

  fd = g_file_open_tmp ("gvmd-report-export-XXXXXX", &report_export_path, NULL);
  assert_that (fd, is_greater_than (-1));

  while (offset < (gssize) sizeof (report_export_contents))
    {
      gssize written;

      written = write (fd, report_export_contents + offset,
                       sizeof (report_export_contents) - offset);
      assert_that (written, is_greater_than (0));
      offset += written;
    }

  assert_that (close (fd), is_equal_to (0));
}

static void
run_completed_report_export_download (gmp_parser_t *gmp_parser, GError **error)
{
  const gchar *attribute_names[] = {"report_export_id", NULL};
  const gchar *attribute_values[] = {report_export_uuid, NULL};

  client_state = CLIENT_AUTHENTIC;
  gmp_xml_handle_start_element (NULL, "download_report_export", attribute_names,
                                attribute_values, gmp_parser, error);
  gmp_xml_handle_end_element (NULL, "download_report_export", gmp_parser,
                              error);
}

static int
substring_count (const gchar *string, const gchar *substring)
{
  int count = 0;

  while ((string = strstr (string, substring)))
    {
      count++;
      string += strlen (substring);
    }

  return count;
}

Ensure (gmp, completed_download_report_export_is_exact_and_reusable)
{
  GMarkupParseContext *context;
  GMarkupParser validation_parser = {0};
  gmp_parser_t gmp_parser = {0};
  const gchar *content_start;
  const gchar *content_end;
  guchar *decoded;
  gsize decoded_size;
  gchar *encoded;
  GError *error = NULL;

  create_report_export_file ();
  gmp_parser.client_writer = capture_client_writer;
  gmp_parser.client_delivery_register = register_client_delivery;

  run_completed_report_export_download (&gmp_parser, &error);

  assert_that (error, is_null);
  assert_that (client_state, is_equal_to (CLIENT_AUTHENTIC));
  assert_that (
    substring_count (captured_output->str, "<download_report_export_response"),
    is_equal_to (1));
  assert_that (captured_output->str, contains_string ("status=\"200\""));
  assert_that (captured_output->str, contains_string ("<type>scan</type>"));
  assert_that (captured_output->str, contains_string ("<status>done</status>"));
  assert_that (captured_output->str,
               contains_string ("<progress>completed</progress>"));
  assert_that (captured_output->str,
               contains_string ("<file_size>11</file_size>"));
  assert_that (captured_output->str,
               contains_string ("<content_type>application/octet-stream"
                                "</content_type>"));
  assert_that (captured_output->str,
               contains_string ("<extension>bin</extension>"));
  assert_that (captured_output->str, contains_string (report_uuid_value));
  assert_that (captured_output->str,
               contains_string (report_format_uuid_value));

  context = g_markup_parse_context_new (&validation_parser, 0, NULL, NULL);
  assert_that (g_markup_parse_context_parse (context, captured_output->str,
                                             captured_output->len, &error),
               is_true);
  assert_that (g_markup_parse_context_end_parse (context, &error), is_true);
  assert_that (error, is_null);
  g_markup_parse_context_free (context);

  content_start = strstr (captured_output->str, "<content>");
  assert_that (content_start, is_not_null);
  content_start += strlen ("<content>");
  content_end = strstr (content_start, "</content>");
  assert_that (content_end, is_not_null);
  encoded = g_strndup (content_start, content_end - content_start);
  decoded = g_base64_decode (encoded, &decoded_size);
  assert_that (decoded_size, is_equal_to (sizeof (report_export_contents)));
  assert_that (
    memcmp (decoded, report_export_contents, sizeof (report_export_contents)),
    is_equal_to (0));
  g_free (decoded);
  g_free (encoded);

  assert_that (pending_delivery_callback, is_not_null);
  assert_that (report_export_delete_count, is_equal_to (0));
  assert_that (g_file_test (report_export_path, G_FILE_TEST_EXISTS), is_true);

  gmp_xml_handle_start_element (NULL, "get_version", NULL, NULL, &gmp_parser,
                                &error);
  gmp_xml_handle_end_element (NULL, "get_version", &gmp_parser, &error);

  assert_that (error, is_null);
  assert_that (client_state, is_equal_to (CLIENT_AUTHENTIC));
  assert_that (captured_output->str,
               contains_string ("<get_version_response status=\"200\""));

  complete_client_delivery (TRUE);
  assert_that (report_export_delete_count, is_equal_to (1));
  assert_that (g_file_test (report_export_path, G_FILE_TEST_EXISTS), is_false);
}

Ensure (gmp, failed_download_report_export_delivery_is_not_consumed)
{
  gmp_parser_t gmp_parser = {0};
  GError *error = NULL;

  create_report_export_file ();
  fail_on_response_close = TRUE;
  gmp_parser.client_writer = capture_client_writer;
  gmp_parser.client_delivery_register = register_client_delivery;

  run_completed_report_export_download (&gmp_parser, &error);

  assert_that (error, is_not_null);
  assert_that (pending_delivery_callback, is_null);
  assert_that (report_export_delete_count, is_equal_to (0));
  assert_that (g_file_test (report_export_path, G_FILE_TEST_EXISTS), is_true);
  g_clear_error (&error);
}

Ensure (gmp, disconnected_download_report_export_delivery_is_not_consumed)
{
  gmp_parser_t gmp_parser = { 0 };
  GError *error = NULL;

  create_report_export_file ();
  gmp_parser.client_writer = capture_client_writer;
  gmp_parser.client_delivery_register = register_client_delivery;

  run_completed_report_export_download (&gmp_parser, &error);

  assert_that (error, is_null);
  assert_that (pending_delivery_callback, is_not_null);
  complete_client_delivery (FALSE);
  assert_that (report_export_delete_count, is_equal_to (0));
  assert_that (g_file_test (report_export_path, G_FILE_TEST_EXISTS), is_true);
}

static void
assert_report_export_command_restores_authenticated_state (const char *command)
{
  const gchar *attribute_names[] = { NULL };
  const gchar *attribute_values[] = { NULL };
  gmp_parser_t gmp_parser = { 0 };
  GError *error = NULL;

  gmp_parser.client_writer = dummy_client_writer;
  client_state = CLIENT_AUTHENTIC;

  gmp_xml_handle_start_element (NULL, command, attribute_names,
                                attribute_values, &gmp_parser, &error);
  gmp_xml_handle_end_element (NULL, command, &gmp_parser, &error);

  assert_that (error, is_null);
  assert_that (client_state, is_equal_to (CLIENT_AUTHENTIC));

  gmp_xml_handle_start_element (NULL, "get_version", NULL, NULL,
                                &gmp_parser, &error);

  assert_that (error, is_null);
  assert_that (client_state, is_equal_to (CLIENT_GET_VERSION_AUTHENTIC));
}

Ensure (gmp, cancel_report_export_restores_authenticated_state)
{
  assert_report_export_command_restores_authenticated_state
    ("cancel_report_export");
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

Ensure (gmp, download_report_export_restores_authenticated_state)
{
  assert_report_export_command_restores_authenticated_state
    ("download_report_export");
}

Ensure (gmp, export_audit_report_restores_authenticated_state)
{
  assert_report_export_command_restores_authenticated_state
    ("export_audit_report");
}

Ensure (gmp, export_delta_audit_report_restores_authenticated_state)
{
  assert_report_export_command_restores_authenticated_state
    ("export_delta_audit_report");
}

Ensure (gmp, export_delta_scan_report_restores_authenticated_state)
{
  assert_report_export_command_restores_authenticated_state
    ("export_delta_scan_report");
}

Ensure (gmp, export_scan_report_restores_authenticated_state)
{
  assert_report_export_command_restores_authenticated_state
    ("export_scan_report");
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

static void
assert_move_task_error_restores_authenticated_state (
  const gchar **attribute_names, const gchar **attribute_values)
{
  gmp_parser_t gmp_parser = { 0 };
  GError *error = NULL;

  gmp_parser.client_writer = dummy_client_writer;
  client_state = CLIENT_AUTHENTIC;

  gmp_xml_handle_start_element (NULL, "move_task", attribute_names,
                                attribute_values, &gmp_parser, &error);
  gmp_xml_handle_end_element (NULL, "move_task", &gmp_parser, &error);

  assert_that (error, is_null);
  assert_that (client_state, is_equal_to (CLIENT_AUTHENTIC));

  gmp_xml_handle_start_element (NULL, "get_version", NULL, NULL,
                                &gmp_parser, &error);

  assert_that (error, is_null);
  assert_that (client_state, is_equal_to (CLIENT_GET_VERSION_AUTHENTIC));
}

Ensure (gmp, move_task_without_task_id_restores_authenticated_state)
{
  const gchar *attribute_names[] = { "slave_id", NULL };
  const gchar *attribute_values[] = { "slave", NULL };

  assert_move_task_error_restores_authenticated_state (attribute_names,
                                                        attribute_values);
}

Ensure (gmp, move_task_without_slave_id_restores_authenticated_state)
{
  const gchar *attribute_names[] = { "task_id", NULL };
  const gchar *attribute_values[] = { "task", NULL };

  assert_move_task_error_restores_authenticated_state (attribute_names,
                                                        attribute_values);
}

Ensure (gmp, move_task_with_empty_task_id_restores_authenticated_state)
{
  const gchar *attribute_names[] = { "task_id", "slave_id", NULL };
  const gchar *attribute_values[] = { "", "slave", NULL };

  assert_move_task_error_restores_authenticated_state (attribute_names,
                                                        attribute_values);
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context
    (suite, gmp, completed_download_report_export_is_exact_and_reusable);
  add_test_with_context
    (suite, gmp, failed_download_report_export_delivery_is_not_consumed);
  add_test_with_context
    (suite, gmp, disconnected_download_report_export_delivery_is_not_consumed);
  add_test_with_context
    (suite, gmp, cancel_report_export_restores_authenticated_state);
  add_test_with_context
    (suite, gmp, create_report_config_restores_authenticated_state);
  add_test_with_context
    (suite, gmp, download_report_export_restores_authenticated_state);
  add_test_with_context
    (suite, gmp, export_audit_report_restores_authenticated_state);
  add_test_with_context
    (suite, gmp, export_delta_audit_report_restores_authenticated_state);
  add_test_with_context
    (suite, gmp, export_delta_scan_report_restores_authenticated_state);
  add_test_with_context
    (suite, gmp, export_scan_report_restores_authenticated_state);
  add_test_with_context
    (suite, gmp, modify_report_config_restores_authenticated_state);
  add_test_with_context
    (suite, gmp, move_task_without_task_id_restores_authenticated_state);
  add_test_with_context
    (suite, gmp, move_task_without_slave_id_restores_authenticated_state);
  add_test_with_context
    (suite, gmp, move_task_with_empty_task_id_restores_authenticated_state);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
